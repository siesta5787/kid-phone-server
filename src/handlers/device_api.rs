use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};

use crate::AppState;
use crate::models::{
    Device, DevicePolicy, EnrollRequest, EnrollResponse, PolicyResponse, StatusReportRequest,
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
         (device_id, lock_reason, kiosk_engaged, installed_apps_json, app_version) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(device.id)
    .bind(&report.lock_reason)
    .bind(report.kiosk_engaged)
    .bind(&installed_apps_json)
    .bind(&report.app_version)
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
