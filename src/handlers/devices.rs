use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;

use crate::AppState;
use crate::models::{Device, DevicePolicy, DeviceStatus, InstalledApp};
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
    weekday_start: String,
    weekday_end: String,
    weekend_start: String,
    weekend_end: String,
    bedtime_start: String,
    bedtime_end: String,
    kiosk_desired: bool,
    lock_feature_system_info: bool,
    lock_feature_notifications: bool,
    lock_feature_home: bool,
    lock_feature_overview: bool,
    lock_feature_global_actions: bool,
    lock_feature_keyguard: bool,
    wifi_mode: String,
    bluetooth_mode: String,
    pin_configured: bool,
    offline_override_used: bool,
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
            lock_feature_system_info: lock_task_features & LOCK_FEATURE_SYSTEM_INFO != 0,
            lock_feature_notifications: lock_task_features & LOCK_FEATURE_NOTIFICATIONS != 0,
            lock_feature_home: lock_task_features & LOCK_FEATURE_HOME != 0,
            lock_feature_overview: lock_task_features & LOCK_FEATURE_OVERVIEW != 0,
            lock_feature_global_actions: lock_task_features & LOCK_FEATURE_GLOBAL_ACTIONS != 0,
            lock_feature_keyguard: lock_task_features & LOCK_FEATURE_KEYGUARD != 0,
            wifi_mode: policy.wifi_mode,
            bluetooth_mode: policy.bluetooth_mode,
            pin_configured: policy.override_pin_hash.is_some(),
            offline_override_used,
            device,
            apps,
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
    let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (key, value) in form_urlencoded::parse(&body) {
        if key == "allowed_packages" {
            allowed_packages.push(value.into_owned());
        } else {
            fields.insert(key.into_owned(), value.into_owned());
        }
    }
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();

    let allowlist_json = serde_json::to_string(&allowed_packages).ok();

    let mut lock_task_features: i64 = 0;
    if fields.contains_key("lock_feature_system_info") {
        lock_task_features |= LOCK_FEATURE_SYSTEM_INFO;
    }
    if fields.contains_key("lock_feature_notifications") {
        lock_task_features |= LOCK_FEATURE_NOTIFICATIONS;
    }
    if fields.contains_key("lock_feature_home") {
        lock_task_features |= LOCK_FEATURE_HOME;
    }
    if fields.contains_key("lock_feature_overview") {
        lock_task_features |= LOCK_FEATURE_OVERVIEW;
    }
    if fields.contains_key("lock_feature_global_actions") {
        lock_task_features |= LOCK_FEATURE_GLOBAL_ACTIONS;
    }
    if fields.contains_key("lock_feature_keyguard") {
        lock_task_features |= LOCK_FEATURE_KEYGUARD;
    }

    let wifi_mode = normalize_radio_mode(&field("wifi_mode"));
    let bluetooth_mode = normalize_radio_mode(&field("bluetooth_mode"));

    // The PIN fields are optional on every save (this form saves everything
    // together) - leave the stored hash/salt untouched unless the admin
    // actually typed a new PIN or explicitly asked to clear it, so blank
    // fields on an unrelated save can't silently wipe an already-configured
    // PIN.
    let current = sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
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
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

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
