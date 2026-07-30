use serde::{Deserialize, Serialize};

#[derive(sqlx::FromRow, Clone)]
pub struct AdminUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
}

#[derive(sqlx::FromRow, Clone)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub enrollment_code: Option<String>,
    pub enrollment_code_expires_at: Option<String>,
    pub token_hash: Option<String>,
    pub enrolled_at: Option<String>,
    pub last_seen_at: Option<String>,
}

#[derive(sqlx::FromRow, Clone, Default)]
pub struct DevicePolicy {
    pub device_id: i64,
    pub allowlist_json: Option<String>,
    pub weekday_start_minutes: Option<i64>,
    pub weekday_end_minutes: Option<i64>,
    pub weekend_start_minutes: Option<i64>,
    pub weekend_end_minutes: Option<i64>,
    pub bedtime_start_minutes: Option<i64>,
    pub bedtime_end_minutes: Option<i64>,
    pub kiosk_desired: bool,
    pub lock_task_features: Option<i64>,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DeviceStatus {
    pub id: i64,
    pub device_id: i64,
    pub lock_reason: String,
    pub kiosk_engaged: bool,
    pub installed_apps_json: Option<String>,
    pub app_version: Option<String>,
    pub reported_at: String,
}

/// One entry in a device's self-reported installed-app list, used to build
/// the admin UI's allowlist checkboxes from real data instead of asking a
/// parent to type raw Android package names.
#[derive(Serialize, Deserialize, Clone)]
pub struct InstalledApp {
    pub package_name: String,
    pub label: String,
}

// ---------------------------------------------------------------------
// Device-facing API wire types (plain JSON, no Headwind-style envelope)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub enrollment_code: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub device_id: i64,
    pub device_token: String,
}

#[derive(Serialize)]
pub struct PolicyResponse {
    pub allowlist: Option<Vec<String>>,
    pub weekday_start_minutes: Option<i64>,
    pub weekday_end_minutes: Option<i64>,
    pub weekend_start_minutes: Option<i64>,
    pub weekend_end_minutes: Option<i64>,
    pub bedtime_start_minutes: Option<i64>,
    pub bedtime_end_minutes: Option<i64>,
    pub kiosk_desired: bool,
}

#[derive(Deserialize)]
pub struct StatusReportRequest {
    pub lock_reason: String,
    pub kiosk_engaged: bool,
    pub installed_apps: Option<Vec<InstalledApp>>,
    pub app_version: Option<String>,
}
