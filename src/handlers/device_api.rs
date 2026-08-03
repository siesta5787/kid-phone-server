use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::{Extension, Json};

use crate::AppState;
use crate::models::{
    Device, DevicePolicy, EnrollRequest, EnrollResponse, PolicyResponse, StatusReportRequest,
    TrackedApp, TrackedAppUpdate,
};
use crate::security::{self, AuthedDevice};

pub async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> impl IntoResponse {
    let device = sqlx::query_as::<_, Device>(
        "SELECT * FROM devices WHERE enrollment_code = ? \
         AND enrollment_code_expires_at > datetime('now')",
    )
    .bind(&req.enrollment_code)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let Some(device) = device else {
        return (
            StatusCode::UNAUTHORIZED,
            "invalid or expired enrollment code",
        )
            .into_response();
    };

    let token = security::generate_device_token();
    let token_hash = security::hash_token(&token);

    sqlx::query(
        "UPDATE devices SET token_hash = ?, enrollment_code = NULL, \
         enrollment_code_expires_at = NULL, enrolled_at = datetime('now') WHERE id = ?",
    )
    .bind(&token_hash)
    .bind(device.id)
    .execute(&state.db)
    .await
    .ok();

    Json(EnrollResponse {
        device_id: device.id,
        device_token: token,
    })
    .into_response()
}

pub async fn policy(
    State(state): State<AppState>,
    Extension(AuthedDevice(device)): Extension<AuthedDevice>,
) -> impl IntoResponse {
    let policy =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(device.id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(DevicePolicy {
                device_id: device.id,
                wifi_mode: "open".to_string(),
                bluetooth_mode: "open".to_string(),
                ..Default::default()
            });

    let allowlist = policy
        .allowlist_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok());

    Json(PolicyResponse {
        allowlist,
        weekday_start_minutes: policy.weekday_start_minutes,
        weekday_end_minutes: policy.weekday_end_minutes,
        weekend_start_minutes: policy.weekend_start_minutes,
        weekend_end_minutes: policy.weekend_end_minutes,
        bedtime_start_minutes: policy.bedtime_start_minutes,
        bedtime_end_minutes: policy.bedtime_end_minutes,
        kiosk_desired: policy.kiosk_desired,
        lock_task_features: policy.lock_task_features.unwrap_or(0),
        wifi_mode: policy.wifi_mode,
        bluetooth_mode: policy.bluetooth_mode,
        override_pin_hash: policy.override_pin_hash,
        override_pin_salt: policy.override_pin_salt,
        require_tailscale: policy.require_tailscale,
        tailscale_exit_node_id: policy.tailscale_exit_node_id,
        quick_controls_mask: policy.quick_controls_mask,
    })
    .into_response()
}

pub async fn status(
    State(state): State<AppState>,
    Extension(AuthedDevice(device)): Extension<AuthedDevice>,
    Json(report): Json<StatusReportRequest>,
) -> impl IntoResponse {
    let installed_apps_json = report
        .installed_apps
        .as_ref()
        .and_then(|apps| serde_json::to_string(apps).ok());

    sqlx::query(
        "INSERT INTO device_status \
         (device_id, lock_reason, kiosk_engaged, installed_apps_json, app_version, app_version_code, offline_override_used) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.id)
    .bind(&report.lock_reason)
    .bind(report.kiosk_engaged)
    .bind(&installed_apps_json)
    .bind(&report.app_version)
    .bind(report.app_version_code)
    .bind(report.offline_override_used)
    .execute(&state.db)
    .await
    .ok();

    sqlx::query("UPDATE devices SET last_seen_at = datetime('now') WHERE id = ?")
        .bind(device.id)
        .execute(&state.db)
        .await
        .ok();

    StatusCode::NO_CONTENT
}

/// Every enabled tracked app that has a synced release - covers the
/// launcher's own self-update too now, since it's just another row here.
/// `download_url` is computed per-row rather than a fixed string, since
/// there's one download endpoint per app id. `release_tag` is composited
/// with the asset id when one's cached (GitHub-sourced apps) - see
/// `handlers::tracked_apps::sync_one_app`'s doc comment for why a rolling
/// tag alone can't be trusted to signal "this is a new build" client-side.
pub async fn tracked_app_updates(
    State(state): State<AppState>,
    Extension(AuthedDevice(_device)): Extension<AuthedDevice>,
) -> impl IntoResponse {
    let apps = sqlx::query_as::<_, TrackedApp>(
        "SELECT * FROM tracked_apps WHERE enabled = 1 AND latest_release_tag IS NOT NULL",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let updates: Vec<TrackedAppUpdate> = apps
        .into_iter()
        .filter_map(|app| {
            let tag = app.latest_release_tag?;
            let release_tag = match app.latest_release_asset_id {
                Some(asset_id) => format!("{tag}@{asset_id}"),
                None => tag,
            };
            Some(TrackedAppUpdate {
                package_name: app.package_name,
                release_tag,
                download_url: format!("/api/devices/apps/{}/download", app.id),
            })
        })
        .collect();

    Json(updates).into_response()
}

pub async fn tracked_app_download(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(AuthedDevice(_device)): Extension<AuthedDevice>,
) -> impl IntoResponse {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(file_path) = app.and_then(|a| a.latest_release_file_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match tokio::fs::read(&file_path).await {
        Ok(bytes) => (
            [(
                header::CONTENT_TYPE,
                "application/vnd.android.package-archive",
            )],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
