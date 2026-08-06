use serde::{Deserialize, Serialize};

#[derive(sqlx::FromRow, Clone)]
pub struct AdminUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub failed_login_attempts: i64,
    pub locked_until: Option<String>,
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
    pub wifi_mode: String,
    pub bluetooth_mode: String,
    pub override_pin_hash: Option<String>,
    pub override_pin_salt: Option<String>,
    pub require_tailscale: bool,
    pub tailscale_exit_node_id: Option<String>,
    pub quick_controls_mask: i64,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DeviceStatus {
    pub id: i64,
    pub device_id: i64,
    pub lock_reason: String,
    pub kiosk_engaged: bool,
    pub installed_apps_json: Option<String>,
    pub app_version: Option<String>,
    pub app_version_code: Option<i64>,
    pub offline_override_used: bool,
    pub reported_at: String,
}

#[derive(sqlx::FromRow, Clone)]
pub struct SecurityEvent {
    pub id: i64,
    pub event_type: String,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

#[derive(sqlx::FromRow, Clone)]
pub struct BannedIp {
    pub ip_address: String,
    pub banned_until: String,
    pub reason: Option<String>,
}

#[derive(sqlx::FromRow, Clone)]
pub struct TrackedApp {
    pub id: i64,
    pub name: String,
    pub package_name: String,
    /// "github" or "manual" - see migrations/0008_tracked_apps_source_type.sql.
    pub source_type: String,
    /// Empty string (not NULL) for manual-source apps - avoids a SQLite
    /// table rebuild to loosen the original NOT NULL constraint; a real
    /// repo string is never empty, so it's an unambiguous sentinel.
    pub github_repo: String,
    pub asset_pattern: Option<String>,
    pub include_prereleases: bool,
    pub enabled: bool,
    pub latest_release_tag: Option<String>,
    pub latest_release_asset_id: Option<i64>,
    pub latest_release_file_path: Option<String>,
    pub last_checked_at: Option<String>,
    pub created_at: String,
}

/// Singleton row (id always 1) - see migrations/0009_dns_filter.sql.
#[derive(sqlx::FromRow, Clone)]
pub struct DnsFilterSettings {
    pub id: i64,
    pub enabled: bool,
    pub upstream: String,
    pub updated_at: String,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DnsBlocklist {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DnsCustomDomain {
    pub id: i64,
    pub domain: String,
    pub list_type: String,
    pub created_at: String,
}

/// One point in a device's location trail - see migrations/0010_find_my_device.sql.
/// `captured_at` is the device's own fix timestamp, not when the server received it.
#[derive(sqlx::FromRow, Clone, Serialize)]
pub struct DeviceLocation {
    pub id: i64,
    pub device_id: i64,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_meters: Option<f64>,
    pub captured_at: String,
    pub received_at: String,
}

/// A queued remote command (ring/lock/wipe/locate) - `delivered_at` is set the
/// instant `policy()` serves it to the device, `acknowledged_at` when the
/// device reports back (never, for `wipe`). See
/// migrations/0010_find_my_device.sql.
#[derive(sqlx::FromRow, Clone)]
pub struct DeviceCommand {
    pub id: i64,
    pub device_id: i64,
    pub command: String,
    pub requested_at: String,
    pub delivered_at: Option<String>,
    pub acknowledged_at: Option<String>,
    pub result: Option<String>,
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
// Device-facing API wire types (plain JSON, no wrapper envelope)
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
    pub lock_task_features: i64,
    pub wifi_mode: String,
    pub bluetooth_mode: String,
    pub override_pin_hash: Option<String>,
    pub override_pin_salt: Option<String>,
    pub require_tailscale: bool,
    pub tailscale_exit_node_id: Option<String>,
    pub quick_controls_mask: i64,
    pub pending_command: Option<PendingCommand>,
    /// Mirrors `dns_filter_settings.enabled` (a global, not per-device,
    /// setting) - when true, the client locks Android's system Private DNS
    /// to this server's own hostname via
    /// `DevicePolicyManager.setGlobalPrivateDnsModeSpecifiedHost`, so DNS
    /// resolution goes straight to the filter engine over DNS-over-TLS
    /// (port 853) regardless of exit-node routing or app-level DNS-over-
    /// HTTPS settings that would otherwise bypass the plain-port-53 path.
    /// See `dns_engine.rs`'s module doc comment for the full picture.
    pub force_private_dns_to_pi: bool,
}

/// The oldest undelivered [DeviceCommand] for this device, if any - `policy()`
/// marks it delivered the instant it's serialized into a response, so a
/// second poll before the device acknowledges never hands out the same
/// command twice. See `handlers::device_api::policy`.
#[derive(Serialize)]
pub struct PendingCommand {
    pub id: i64,
    pub command: String,
}

#[derive(Deserialize)]
pub struct StatusReportRequest {
    pub lock_reason: String,
    pub kiosk_engaged: bool,
    pub installed_apps: Option<Vec<InstalledApp>>,
    pub app_version: Option<String>,
    pub app_version_code: Option<i64>,
    #[serde(default)]
    pub offline_override_used: bool,
    pub location: Option<LocationReport>,
}

/// Attached to a status report whenever the device has a location reading
/// available - on every regular heartbeat, not just after a `locate` command
/// (see kids-launcher-mdm's `MdmSyncWorker`) - so the trail on the admin map
/// stays reasonably fresh without needing repeated explicit requests.
#[derive(Deserialize)]
pub struct LocationReport {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_meters: Option<f64>,
    pub captured_at: String,
}

#[derive(Deserialize)]
pub struct CommandResultRequest {
    pub command_id: i64,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct TrackedAppUpdate {
    pub package_name: String,
    pub release_tag: String,
    pub download_url: String,
}
