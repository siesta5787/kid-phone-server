use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;

use crate::AppState;
use crate::models::{Device, DevicePolicy, DeviceStatus, InstalledApp, TrackedApp};
use crate::security::{self, CurrentAdmin};

/// How long a freshly-generated enrollment code stays valid before it must
/// be regenerated - long enough to walk from the computer to the phone and
/// type it in, short enough that a code shown once on screen isn't a
/// standing credential.
const ENROLLMENT_CODE_MINUTES: i64 = 30;

struct DeviceListRow {
    id: i64,
    name: String,
    status_text: String,
}

#[derive(Template)]
#[template(path = "devices_list.html")]
struct DevicesListTemplate {
    title: String,
    devices: Vec<DeviceListRow>,
}

struct DashboardDeviceRow {
    id: i64,
    name: String,
    status_text: String,
    lock_reason: Option<String>,
    kiosk_engaged: bool,
    offline_override_used: bool,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    title: String,
    device_count: usize,
    devices: Vec<DashboardDeviceRow>,
    any_override_used: bool,
}

/// Landing page - a quick at-a-glance summary, distinct from the full
/// management list at `/devices`. Small enough (a handful of devices,
/// realistically) that a query per device is simpler than one clever join,
/// matching this app's existing style (`view_device` already does the same
/// thing for a single device).
pub async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let device_count = devices.len();
    let mut rows = Vec::with_capacity(device_count);
    let mut any_override_used = false;

    for d in devices {
        let latest_status = sqlx::query_as::<_, DeviceStatus>(
            "SELECT * FROM device_status WHERE device_id = ? ORDER BY reported_at DESC LIMIT 1",
        )
        .bind(d.id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let status_text = if d.enrolled_at.is_none() {
            "Not enrolled yet".to_string()
        } else {
            match &d.last_seen_at {
                Some(t) => format!("Last seen {t}"),
                None => "Enrolled, not seen yet".to_string(),
            }
        };

        let offline_override_used = latest_status
            .as_ref()
            .map(|s| s.offline_override_used)
            .unwrap_or(false);
        if offline_override_used {
            any_override_used = true;
        }

        rows.push(DashboardDeviceRow {
            id: d.id,
            name: d.name,
            status_text,
            lock_reason: latest_status.as_ref().map(|s| s.lock_reason.clone()),
            kiosk_engaged: latest_status
                .as_ref()
                .map(|s| s.kiosk_engaged)
                .unwrap_or(false),
            offline_override_used,
        });
    }

    Html(
        DashboardTemplate {
            title: "Dashboard".to_string(),
            device_count,
            devices: rows,
            any_override_used,
        }
        .render()
        .unwrap(),
    )
}

pub async fn list_devices(State(state): State<AppState>) -> impl IntoResponse {
    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let rows = devices
        .into_iter()
        .map(|d| {
            let status_text = if d.enrolled_at.is_none() {
                "Not enrolled yet".to_string()
            } else {
                match &d.last_seen_at {
                    Some(t) => format!("Last seen {t}"),
                    None => "Enrolled, not seen yet".to_string(),
                }
            };
            DeviceListRow {
                id: d.id,
                name: d.name,
                status_text,
            }
        })
        .collect();

    Html(
        DevicesListTemplate {
            title: "Devices".to_string(),
            devices: rows,
        }
        .render()
        .unwrap(),
    )
}

#[derive(Template)]
#[template(path = "device_add.html")]
struct DeviceAddTemplate {
    title: String,
}

pub async fn new_device_form() -> impl IntoResponse {
    Html(
        DeviceAddTemplate {
            title: "Add a device".to_string(),
        }
        .render()
        .unwrap(),
    )
}

#[derive(Deserialize)]
pub struct CreateDeviceForm {
    name: String,
}

pub async fn create_device(
    State(state): State<AppState>,
    Form(form): Form<CreateDeviceForm>,
) -> impl IntoResponse {
    let code = security::generate_enrollment_code();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (name, enrollment_code, enrollment_code_expires_at) \
         VALUES (?, ?, datetime('now', ?)) RETURNING id",
    )
    .bind(&form.name)
    .bind(&code)
    .bind(format!("+{ENROLLMENT_CODE_MINUTES} minutes"))
    .fetch_one(&state.db)
    .await
    .expect("failed to create device");

    sqlx::query("INSERT INTO device_policy (device_id) VALUES (?)")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to(&format!("/devices/{id}"))
}

pub async fn regenerate_code(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let code = security::generate_enrollment_code();
    sqlx::query(
        "UPDATE devices SET enrollment_code = ?, \
         enrollment_code_expires_at = datetime('now', ?) WHERE id = ?",
    )
    .bind(&code)
    .bind(format!("+{ENROLLMENT_CODE_MINUTES} minutes"))
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to(&format!("/devices/{id}"))
}

struct AppCheckbox {
    package_name: String,
    label: String,
    checked: bool,
}

/// One row per app from the global Apps list (`tracked_apps`), scoped to whether *this* device
/// gets it pushed - see migrations/0013_device_tracked_apps.sql. The launcher's own row is always
/// `checked` and rendered disabled in device_detail.html (also enforced server-side in
/// `update_policy`, which never lets a submitted `selected_apps` list affect it) - there's no
/// real-world case for a kid's phone not running the app that enforces every other restriction on
/// it.
struct TrackedAppCheckbox {
    id: i64,
    name: String,
    checked: bool,
    is_launcher: bool,
}

/// The six parent-facing LockTask features, decoded from/encoded into the
/// raw `lock_task_features` bitmask Android's `setLockTaskFeatures` expects.
/// Not exposing `LOCK_TASK_FEATURE_BLOCK_ACTIVITY_START_IN_TASK` (64) - no
/// clear parent-facing meaning.
const LOCK_FEATURE_SYSTEM_INFO: i64 = 1;
const LOCK_FEATURE_NOTIFICATIONS: i64 = 2;
const LOCK_FEATURE_HOME: i64 = 4;
const LOCK_FEATURE_OVERVIEW: i64 = 8;
const LOCK_FEATURE_GLOBAL_ACTIONS: i64 = 16;
const LOCK_FEATURE_KEYGUARD: i64 = 32;

/// Bits for `quick_controls_mask` - which switches show up on the launcher's
/// swipe-left-from-home "Quick Controls" screen (see kids-launcher-mdm's
/// `ui/quickcontrols/QuickControlsActivity`), the kid-facing replacement for
/// Android's native Quick Settings shade.
const QUICK_CONTROL_WIFI: i64 = 1;
const QUICK_CONTROL_BLUETOOTH: i64 = 2;
const QUICK_CONTROL_BRIGHTNESS: i64 = 4;

const VALID_RADIO_MODES: [&str; 3] = ["open", "restricted", "disabled"];

fn normalize_radio_mode(value: &str) -> String {
    if VALID_RADIO_MODES.contains(&value) {
        value.to_string()
    } else {
        "open".to_string()
    }
}

#[derive(Template)]
#[template(path = "device_detail.html")]
struct DeviceDetailTemplate {
    title: String,
    device: Device,
    apps: Vec<AppCheckbox>,
    tracked_apps: Vec<TrackedAppCheckbox>,
    weekday_start: String,
    weekday_end: String,
    weekend_start: String,
    weekend_end: String,
    bedtime_start: String,
    bedtime_end: String,
    kiosk_desired: bool,
    lock_feature_notifications: bool,
    lock_feature_global_actions: bool,
    wifi_mode: String,
    bluetooth_mode: String,
    pin_configured: bool,
    offline_override_used: bool,
    vpn_filter_enabled: bool,
    quick_control_wifi: bool,
    quick_control_bluetooth: bool,
    quick_control_brightness: bool,
    latest_status: Option<DeviceStatus>,
}

/// HTML `<input type="time">` gives/expects "HH:MM" - these convert to/from
/// the minutes-since-midnight representation the schema and the device's
/// own (already-unit-tested) schedule logic use.
fn minutes_to_time_input(minutes: Option<i64>) -> String {
    match minutes {
        Some(m) => format!("{:02}:{:02}", m / 60, m % 60),
        None => String::new(),
    }
}

fn time_input_to_minutes(value: &str) -> Option<i64> {
    let (h, m) = value.split_once(':')?;
    Some(h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?)
}

pub async fn view_device(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(device) = device else {
        return (axum::http::StatusCode::NOT_FOUND, "Device not found").into_response();
    };

    let policy =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(DevicePolicy {
                device_id: id,
                wifi_mode: "open".to_string(),
                bluetooth_mode: "open".to_string(),
                // See the matching comment in device_api::policy - bool::default() is false,
                // but a never-configured device must still show/default to filtering on.
                vpn_filter_enabled: true,
                ..Default::default()
            });

    let latest_status = sqlx::query_as::<_, DeviceStatus>(
        "SELECT * FROM device_status WHERE device_id = ? ORDER BY reported_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let allowed: std::collections::HashSet<String> = policy
        .allowlist_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .unwrap_or_default()
        .into_iter()
        .collect();

    let installed: Vec<InstalledApp> = latest_status
        .as_ref()
        .and_then(|s| s.installed_apps_json.as_deref())
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();

    let apps = installed
        .into_iter()
        .map(|a| AppCheckbox {
            checked: allowed.contains(&a.package_name),
            package_name: a.package_name,
            label: a.label,
        })
        .collect();

    let all_tracked = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    let selected_app_ids: std::collections::HashSet<i64> =
        sqlx::query_scalar("SELECT tracked_app_id FROM device_tracked_apps WHERE device_id = ?")
            .bind(id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    let tracked_apps = all_tracked
        .into_iter()
        .map(|a| TrackedAppCheckbox {
            checked: a.is_launcher || selected_app_ids.contains(&a.id),
            id: a.id,
            name: a.name,
            is_launcher: a.is_launcher,
        })
        .collect();

    let lock_task_features = policy.lock_task_features.unwrap_or(0);
    let offline_override_used = latest_status
        .as_ref()
        .map(|s| s.offline_override_used)
        .unwrap_or(false);

    Html(
        DeviceDetailTemplate {
            title: device.name.clone(),
            weekday_start: minutes_to_time_input(policy.weekday_start_minutes),
            weekday_end: minutes_to_time_input(policy.weekday_end_minutes),
            weekend_start: minutes_to_time_input(policy.weekend_start_minutes),
            weekend_end: minutes_to_time_input(policy.weekend_end_minutes),
            bedtime_start: minutes_to_time_input(policy.bedtime_start_minutes),
            bedtime_end: minutes_to_time_input(policy.bedtime_end_minutes),
            kiosk_desired: policy.kiosk_desired,
            lock_feature_notifications: lock_task_features & LOCK_FEATURE_NOTIFICATIONS != 0,
            lock_feature_global_actions: lock_task_features & LOCK_FEATURE_GLOBAL_ACTIONS != 0,
            wifi_mode: policy.wifi_mode,
            bluetooth_mode: policy.bluetooth_mode,
            pin_configured: policy.override_pin_hash.is_some(),
            offline_override_used,
            vpn_filter_enabled: policy.vpn_filter_enabled,
            quick_control_wifi: policy.quick_controls_mask & QUICK_CONTROL_WIFI != 0,
            quick_control_bluetooth: policy.quick_controls_mask & QUICK_CONTROL_BLUETOOTH != 0,
            quick_control_brightness: policy.quick_controls_mask & QUICK_CONTROL_BRIGHTNESS != 0,
            device,
            apps,
            tracked_apps,
            latest_status,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Repeated `allowed_packages` checkbox values can't be collected into a
/// `Vec<String>` via axum's built-in `Form` extractor (it deserializes each
/// key as a single scalar, so a form with one or more identically-named
/// fields fails with "expected a sequence") - parsed manually instead.
pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let mut allowed_packages = Vec::new();
    let mut selected_apps = Vec::new();
    let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (key, value) in form_urlencoded::parse(&body) {
        if key == "allowed_packages" {
            allowed_packages.push(value.into_owned());
        } else if key == "selected_apps" {
            selected_apps.push(value.into_owned());
        } else {
            fields.insert(key.into_owned(), value.into_owned());
        }
    }
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();

    let allowlist_json = serde_json::to_string(&allowed_packages).ok();

    // Home, status bar info, and recents don't let a kid reach anything outside the pinned/
    // allowed app set - Home just re-navigates within it, recents only lists apps already in it,
    // and status bar info is read-only. They're not real restrictions, just navigation
    // convenience, so they're always on rather than admin-configurable (see device_detail.html).
    //
    // Keyguard is also forced on unconditionally, for a very different reason: a real device got
    // stuck at boot after GrapheneOS's own auto-reboot-after-inactivity feature re-locked storage
    // (Before First Unlock/FBE) while this bit was off. LOCK_TASK_FEATURE_KEYGUARD is disabled by
    // default in lock-task mode, and that suppression is a DevicePolicyManager-level setting
    // enforced by system_server itself - it keeps applying even before the device is decrypted,
    // when this app's own process can't run at all (its components aren't resolvable pre-unlock).
    // With keyguard off and this app the exclusive enforced Home app, there was no lock screen to
    // enter a PIN into *and* no launcher available either - a total deadlock recoverable only via
    // hardware-level recovery mode. Forcing this bit on guarantees Android's own (already
    // direct-boot-aware) keyguard can always come up after any reboot, regardless of kiosk
    // config. The real tradeoff: every kiosk-mode device now also requires a PIN to resume from
    // sleep, not just after a reboot - Android doesn't expose those as separate bits.
    let mut lock_task_features: i64 = LOCK_FEATURE_SYSTEM_INFO
        | LOCK_FEATURE_HOME
        | LOCK_FEATURE_OVERVIEW
        | LOCK_FEATURE_KEYGUARD;
    if fields.contains_key("lock_feature_notifications") {
        lock_task_features |= LOCK_FEATURE_NOTIFICATIONS;
    }
    if fields.contains_key("lock_feature_global_actions") {
        lock_task_features |= LOCK_FEATURE_GLOBAL_ACTIONS;
    }

    let wifi_mode = normalize_radio_mode(&field("wifi_mode"));
    let bluetooth_mode = normalize_radio_mode(&field("bluetooth_mode"));

    let mut quick_controls_mask: i64 = 0;
    if fields.contains_key("quick_control_wifi") {
        quick_controls_mask |= QUICK_CONTROL_WIFI;
    }
    if fields.contains_key("quick_control_bluetooth") {
        quick_controls_mask |= QUICK_CONTROL_BLUETOOTH;
    }
    if fields.contains_key("quick_control_brightness") {
        quick_controls_mask |= QUICK_CONTROL_BRIGHTNESS;
    }

    let vpn_filter_enabled = fields.contains_key("vpn_filter_enabled");

    // The PIN fields are optional on every save (this form saves everything
    // together) - leave the stored hash/salt untouched unless the admin
    // actually typed a new PIN or explicitly asked to clear it, so blank
    // fields on an unrelated save can't silently wipe an already-configured
    // PIN.
    let current =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let current_pin = current.as_ref().and_then(|p| p.override_pin_hash.clone());
    let current_salt = current.as_ref().and_then(|p| p.override_pin_salt.clone());

    let new_pin = field("new_pin");
    let new_pin = new_pin.trim();
    let (override_pin_hash, override_pin_salt, pin_event) = if fields.contains_key("clear_pin") {
        (None, None, Some("override_pin_cleared"))
    } else if !new_pin.is_empty() {
        if new_pin.len() >= 6 && new_pin.chars().all(|c| c.is_ascii_digit()) {
            let (hash, salt) = security::hash_pin(new_pin);
            (Some(hash), Some(salt), Some("override_pin_changed"))
        } else {
            // Invalid PIN typed - ignore it rather than fail the whole save,
            // keeping whatever was already configured.
            (current_pin, current_salt, None)
        }
    } else {
        (current_pin, current_salt, None)
    };

    if let Some(event_type) = pin_event {
        security::record_security_event(
            &state.db,
            event_type,
            Some(&admin.username),
            None,
            Some(&format!("device {id}")),
        )
        .await;
    }

    sqlx::query(
        "UPDATE device_policy SET allowlist_json = ?, weekday_start_minutes = ?, \
         weekday_end_minutes = ?, weekend_start_minutes = ?, weekend_end_minutes = ?, \
         bedtime_start_minutes = ?, bedtime_end_minutes = ?, kiosk_desired = ?, \
         lock_task_features = ?, wifi_mode = ?, bluetooth_mode = ?, \
         override_pin_hash = ?, override_pin_salt = ?, \
         quick_controls_mask = ?, vpn_filter_enabled = ?, \
         updated_at = datetime('now') WHERE device_id = ?",
    )
    .bind(&allowlist_json)
    .bind(time_input_to_minutes(&field("weekday_start")))
    .bind(time_input_to_minutes(&field("weekday_end")))
    .bind(time_input_to_minutes(&field("weekend_start")))
    .bind(time_input_to_minutes(&field("weekend_end")))
    .bind(time_input_to_minutes(&field("bedtime_start")))
    .bind(time_input_to_minutes(&field("bedtime_end")))
    .bind(fields.contains_key("kiosk_desired"))
    .bind(lock_task_features)
    .bind(&wifi_mode)
    .bind(&bluetooth_mode)
    .bind(&override_pin_hash)
    .bind(&override_pin_salt)
    .bind(quick_controls_mask)
    .bind(vpn_filter_enabled)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    // Replace-all semantics, same as allowlist_json above - simpler than diffing, and this list is
    // small (a handful of tracked apps at most). The launcher's own row is never submitted (its
    // checkbox is rendered disabled in device_detail.html - a disabled control never appears in
    // form data), so it never ends up here; it doesn't need to, since it's unconditionally
    // included for every device regardless of this table - see device_api::tracked_app_updates.
    let selected_app_ids: Vec<i64> = selected_apps
        .iter()
        .filter_map(|s| s.parse::<i64>().ok())
        .collect();
    sqlx::query("DELETE FROM device_tracked_apps WHERE device_id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();
    for app_id in &selected_app_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO device_tracked_apps (device_id, tracked_app_id) VALUES (?, ?)",
        )
        .bind(id)
        .bind(app_id)
        .execute(&state.db)
        .await
        .ok();
    }

    // Nudges the device to re-sync immediately over the same SSE connection Find My Device uses
    // for ring/lock, rather than waiting out the rest of the background poll interval - the nudge
    // itself carries no data, the device just re-fetches /api/devices/policy on it, so this reuses
    // the exact same dispatch path as a normal scheduled sync.
    let _ = state.command_notify.send(id);

    Redirect::to(&format!("/devices/{id}"))
}

pub async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(_admin): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/")
}
