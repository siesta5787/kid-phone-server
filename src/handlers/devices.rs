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

    sqlx::query(
        "UPDATE device_policy SET allowlist_json = ?, weekday_start_minutes = ?, \
         weekday_end_minutes = ?, weekend_start_minutes = ?, weekend_end_minutes = ?, \
         bedtime_start_minutes = ?, bedtime_end_minutes = ?, kiosk_desired = ?, \
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
