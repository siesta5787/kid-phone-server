use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{Extension, Json};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::AppState;
use crate::models::{
    CommandResultRequest, Device, DeviceCommand, DevicePolicy, EnrollRequest, EnrollResponse,
    PendingCommand, PolicyResponse, StatusReportRequest, TrackedApp, TrackedAppUpdate,
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

    // The oldest undelivered command, if any - marked delivered right here,
    // in the same request that serves it, so a second poll before the device
    // acknowledges never hands out the same command twice. See
    // migrations/0010_find_my_device.sql and handlers::locate.
    let pending = sqlx::query_as::<_, DeviceCommand>(
        "SELECT * FROM device_commands WHERE device_id = ? AND delivered_at IS NULL \
         ORDER BY requested_at ASC LIMIT 1",
    )
    .bind(device.id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let pending_command = if let Some(cmd) = pending {
        sqlx::query("UPDATE device_commands SET delivered_at = datetime('now') WHERE id = ?")
            .bind(cmd.id)
            .execute(&state.db)
            .await
            .ok();
        Some(PendingCommand {
            id: cmd.id,
            command: cmd.command,
        })
    } else {
        None
    };

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
        pending_command,
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

    // Attached on every regular heartbeat when the device has a location
    // reading available, not just after a `locate` command - see
    // LocationReport's doc comment. Pruned on a schedule (30 days) by
    // handlers::locate::run_location_pruning.
    if let Some(loc) = report.location {
        sqlx::query(
            "INSERT INTO device_locations \
             (device_id, latitude, longitude, accuracy_meters, captured_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(device.id)
        .bind(loc.latitude)
        .bind(loc.longitude)
        .bind(loc.accuracy_meters)
        .bind(&loc.captured_at)
        .execute(&state.db)
        .await
        .ok();
    }

    StatusCode::NO_CONTENT
}

/// The device reports back whether a delivered command actually succeeded -
/// never called for `wipe` (the device is gone by the time it would report).
/// Scoped to this device's own commands only, so one device can't ack
/// another's queue entry.
pub async fn command_result(
    State(state): State<AppState>,
    Extension(AuthedDevice(device)): Extension<AuthedDevice>,
    Json(req): Json<CommandResultRequest>,
) -> impl IntoResponse {
    sqlx::query(
        "UPDATE device_commands SET acknowledged_at = datetime('now'), result = ? \
         WHERE id = ? AND device_id = ?",
    )
    .bind(if req.success {
        req.message.unwrap_or_else(|| "ok".to_string())
    } else {
        req.message.unwrap_or_else(|| "failed".to_string())
    })
    .bind(req.command_id)
    .bind(device.id)
    .execute(&state.db)
    .await
    .ok();

    StatusCode::NO_CONTENT
}

/// Held open by the client's foreground service (see kids-launcher-mdm's `CommandListenerService`)
/// for near-instant ring/lock/stop-ring/wipe delivery - a supplement to, not a replacement for,
/// the regular 2-minute policy poll (which is still the actual delivery mechanism; this only tells
/// the device *when* to poll early). Every event is a content-free "something changed, go check"
/// nudge, not the command payload itself - the client always re-fetches `GET /api/devices/policy`
/// to get the real `pending_command`, reusing the exact same dispatch path as a normal scheduled
/// sync. `KeepAlive` pings keep the connection alive through idle proxies/NATs and let the client
/// detect a silently-dead connection and reconnect.
pub async fn commands_stream(
    State(state): State<AppState>,
    Extension(AuthedDevice(device)): Extension<AuthedDevice>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let device_id = device.id;
    let rx = state.command_notify.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(id) if id == device_id => Some(Ok(Event::default().data("command"))),
        _ => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
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
