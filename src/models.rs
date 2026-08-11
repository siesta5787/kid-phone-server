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
    pub override_pin_hash: Option<String>,
    pub override_pin_salt: Option<String>,
    pub quick_controls_mask: i64,
    pub vpn_filter_enabled: bool,
    /// Whether this device's own weekday/weekend/bedtime *_minutes columns above are actually
    /// used - if false (the default), it follows [GlobalSchedule] instead and its own columns are
    /// just whatever was last configured, ignored until this is turned on. See
    /// `handlers::schedules`.
    pub custom_schedule_enabled: bool,
}

/// Singleton (always `id = 1`) - the schedule every device follows unless it has its own
/// `device_policy.custom_schedule_enabled` override. See `handlers::schedules`.
#[derive(sqlx::FromRow, Clone, Default)]
pub struct GlobalSchedule {
    pub id: i64,
    pub weekday_start_minutes: Option<i64>,
    pub weekday_end_minutes: Option<i64>,
    pub weekend_start_minutes: Option<i64>,
    pub weekend_end_minutes: Option<i64>,
    pub bedtime_start_minutes: Option<i64>,
    pub bedtime_end_minutes: Option<i64>,
    pub updated_at: String,
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
    /// See migrations/0013_device_tracked_apps.sql - marks the one row that
    /// is the launcher itself, which can't be deleted or deselected on any
    /// device.
    pub is_launcher: bool,
}

/// Singleton row (id always 1) - see migrations/0009_dns_filter.sql.
#[derive(sqlx::FromRow, Clone)]
pub struct DnsFilterSettings {
    pub id: i64,
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
    /// NULL = applies to all devices, set = this device only. See
    /// migrations/0011_client_side_dns_filtering.sql.
    pub device_id: Option<i64>,
    pub created_at: String,
}

/// Per-device on/off override for a curated blocklist feed - absence of a
/// row for a given device means "use `DnsBlocklist.enabled`". See
/// migrations/0011_client_side_dns_filtering.sql.
#[derive(sqlx::FromRow, Clone)]
pub struct DeviceBlocklistOverride {
    pub device_id: i64,
    pub blocklist_id: i64,
    pub enabled: bool,
    pub updated_at: String,
}

/// One blocked-domain event, self-reported by the device's on-device filter -
/// `blocked_at` is the device's own timestamp, `received_at` is server
/// ingest time (mirrors `DeviceLocation`'s captured_at/received_at split).
/// See migrations/0011_client_side_dns_filtering.sql.
#[derive(sqlx::FromRow, Clone, Serialize)]
pub struct DeviceDnsEvent {
    pub id: i64,
    pub device_id: i64,
    pub domain: String,
    pub category: String,
    pub blocked_at: String,
    pub received_at: String,
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
    pub override_pin_hash: Option<String>,
    pub override_pin_salt: Option<String>,
    pub quick_controls_mask: i64,
    pub pending_command: Option<PendingCommand>,
    /// Per-device on/off for the on-device DNS filter's VPN piece
    /// (KidVpnService) - see `AppEnforcer.applyVpnRestrictions` on the
    /// client. Defaults true; a parent can turn it off per kid from the
    /// device detail page.
    pub vpn_filter_enabled: bool,
    /// Opaque token summarizing this device's fully-resolved blocklist
    /// (global feeds + this device's overrides + global/device-scoped custom
    /// domains). The client compares this against its last-fetched value and
    /// only calls `GET /api/devices/dns-blocklist` (a potentially 100k+
    /// domain payload) when it actually changes, rather than on every
    /// 2-minute sync. See `handlers::device_api::policy`.
    pub dns_filter_version: String,
    /// Which public DoT resolver the client's on-device filter should send
    /// allowed (non-blocked) queries to - "cloudflare" or "quad9", mirrors
    /// `dns_filter_settings.upstream`.
    pub dns_upstream_provider: String,
    /// Packages the device should silently uninstall - see migrations/0014_device_pending_uninstalls.sql
    /// and `handlers::devices::toggle_tracked_app`. Populated fresh on every fetch (not a one-shot
    /// queue like `pending_command`); the row backing an entry here is only cleared once a status
    /// report confirms the package is actually gone, so the instruction survives being missed by
    /// any single sync cycle.
    pub packages_to_uninstall: Vec<String>,
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

/// One blocked-domain event as reported by the device - see
/// `POST /api/devices/dns-events` and migrations/0011_client_side_dns_filtering.sql.
/// The client already knows which category caused the block (it evaluated
/// the domain against its own locally-cached, categorized list), so this
/// carries that through rather than the server re-deriving it.
#[derive(Deserialize)]
pub struct DnsEventReport {
    pub domain: String,
    pub category: String,
    pub blocked_at: String,
}

/// Response body for `GET /api/devices/dns-blocklist` - this device's fully
/// resolved effective blocklist, grouped by category rather than a flat
/// domain->category map, since at ~100k+ domains a flat JSON object would
/// repeat far more per-key overhead (quoted key + colon per domain) than
/// writing the category name once per group.
#[derive(Serialize)]
pub struct DnsBlocklistCategory {
    pub category: String,
    pub domains: Vec<String>,
}

#[derive(Serialize)]
pub struct TrackedAppUpdate {
    pub id: i64,
    /// The admin-facing name from the Apps catalog (e.g. "Tailscale") - used client-side for the
    /// install-progress notification, since [package_name] can no longer be relied on to be
    /// present or human-meaningful.
    pub name: String,
    /// Kept for the admin's own reference and for backward compat with
    /// already-installed older client builds that still key their local
    /// install-state tracking off it - no longer load-bearing on the server
    /// side, and may be empty (see tracked_apps_add.html - typing a real
    /// Android package name is optional now). A current client keys off
    /// [id]/[is_launcher] instead - see kids-launcher-mdm's
    /// `MdmSyncWorker.checkForTrackedAppUpdates`.
    pub package_name: String,
    pub release_tag: String,
    pub download_url: String,
    pub is_launcher: bool,
}

// ---------------------------------------------------------------------
// Conversation journal (kids-mdm-im integration) - see
// migrations/0015_device_journal.sql and kids-launcher-mdm's JournalSync.kt
// ---------------------------------------------------------------------

/// One row pulled from kids-mdm-im's `content://com.kidsmdm.im.journal/entries`
/// provider and forwarded by the client - see `handlers::device_api::journal_upload`.
/// `occurred_at`/`device_created_at` are the provider's own `timestamp`/`created_at`
/// columns, renamed here to avoid reading as "when the server received this."
#[derive(Deserialize)]
pub struct JournalEntryUpload {
    pub remote_id: i64,
    pub thread_id: i64,
    pub recipient_id: String,
    pub display_name: Option<String>,
    pub direction: String,
    pub entry_type: String,
    pub occurred_at: i64,
    pub body: Option<String>,
    pub media_content_type: Option<String>,
    pub call_type: Option<String>,
    pub call_event: Option<String>,
    pub device_created_at: i64,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DeviceJournalEntry {
    pub id: i64,
    pub device_id: i64,
    pub remote_id: i64,
    pub thread_id: i64,
    pub recipient_id: String,
    pub display_name: Option<String>,
    pub direction: String,
    pub entry_type: String,
    pub occurred_at: i64,
    pub body: Option<String>,
    pub media_content_type: Option<String>,
    pub media_path: Option<String>,
    pub call_type: Option<String>,
    pub call_event: Option<String>,
    pub device_created_at: i64,
    pub received_at: String,
}

/// One entry in the thread-picker sidebar - `preview` is the most recent
/// message body (or a placeholder for MEDIA/CALL rows), so an admin can
/// recognize a conversation without opening it.
pub struct JournalThreadSummary {
    pub thread_id: i64,
    pub display_name: Option<String>,
    pub preview: String,
    pub last_occurred_at: i64,
}

// ---------------------------------------------------------------------
// Browsing history (kids-mdm-browser integration) - see
// migrations/0016_device_browser_history.sql and kids-launcher-mdm's
// BrowserHistorySync.kt. Same journal-provider pattern as the conversation
// journal above, but URL visits have no thread/recipient, hence a separate
// table/struct rather than reusing JournalEntryUpload.
// ---------------------------------------------------------------------

/// One row pulled from the browser fork's `content://<applicationId>.journal/entries`
/// provider and forwarded by the client - see `handlers::device_api::browser_history_upload`.
/// `visited_at`/`device_created_at` are the provider's own `timestamp`/`created_at` columns,
/// renamed here to avoid reading as "when the server received this."
#[derive(Deserialize)]
pub struct BrowserHistoryUpload {
    pub remote_id: i64,
    pub url: String,
    pub title: Option<String>,
    pub visited_at: i64,
    pub device_created_at: i64,
}

#[derive(sqlx::FromRow, Clone)]
pub struct DeviceBrowserHistoryEntry {
    pub id: i64,
    pub device_id: i64,
    pub remote_id: i64,
    pub url: String,
    pub title: Option<String>,
    pub visited_at: i64,
    pub device_created_at: i64,
    pub received_at: String,
}
