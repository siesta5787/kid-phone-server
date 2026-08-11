//! Screen-time schedules - a global default every device follows, plus an explicit opt-in
//! per-device override. Previously each device configured its own schedule independently on its
//! own detail page; in practice nearly every device wants the same hours, so this collapses that
//! down to "set it once, override the rare device that needs something different" - see
//! migrations/0017_schedules_page.sql.

use std::collections::HashMap;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};

use crate::AppState;
use crate::models::{Device, DevicePolicy, GlobalSchedule};
use crate::security::CurrentAdmin;

struct DeviceOption {
    id: i64,
    name: String,
    selected: bool,
}

struct SelectedDevice {
    id: i64,
    name: String,
    custom_enabled: bool,
    weekday_start: String,
    weekday_end: String,
    weekend_start: String,
    weekend_end: String,
    bedtime_start: String,
    bedtime_end: String,
}

#[derive(Template)]
#[template(path = "schedules.html")]
struct SchedulesTemplate {
    title: String,
    global_weekday_start: String,
    global_weekday_end: String,
    global_weekend_start: String,
    global_weekend_end: String,
    global_bedtime_start: String,
    global_bedtime_end: String,
    devices: Vec<DeviceOption>,
    selected: Option<SelectedDevice>,
}

/// HTML `<input type="time">` gives/expects "HH:MM" - these convert to/from the minutes-since-
/// midnight representation the schema and the device's own schedule logic use.
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

pub async fn show_schedules(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let global = sqlx::query_as::<_, GlobalSchedule>("SELECT * FROM global_schedule WHERE id = 1")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let all_devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let selected_id: Option<i64> = params.get("device").and_then(|v| v.parse().ok());

    let devices = all_devices
        .iter()
        .map(|d| DeviceOption {
            id: d.id,
            name: d.name.clone(),
            selected: Some(d.id) == selected_id,
        })
        .collect();

    let selected = if let Some(id) = selected_id {
        let device = all_devices.into_iter().find(|d| d.id == id);
        let policy =
            sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
                .bind(id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
        device.map(|d| SelectedDevice {
            id: d.id,
            name: d.name,
            custom_enabled: policy.custom_schedule_enabled,
            weekday_start: minutes_to_time_input(policy.weekday_start_minutes),
            weekday_end: minutes_to_time_input(policy.weekday_end_minutes),
            weekend_start: minutes_to_time_input(policy.weekend_start_minutes),
            weekend_end: minutes_to_time_input(policy.weekend_end_minutes),
            bedtime_start: minutes_to_time_input(policy.bedtime_start_minutes),
            bedtime_end: minutes_to_time_input(policy.bedtime_end_minutes),
        })
    } else {
        None
    };

    Html(
        SchedulesTemplate {
            title: "Schedules".to_string(),
            global_weekday_start: minutes_to_time_input(global.weekday_start_minutes),
            global_weekday_end: minutes_to_time_input(global.weekday_end_minutes),
            global_weekend_start: minutes_to_time_input(global.weekend_start_minutes),
            global_weekend_end: minutes_to_time_input(global.weekend_end_minutes),
            global_bedtime_start: minutes_to_time_input(global.bedtime_start_minutes),
            global_bedtime_end: minutes_to_time_input(global.bedtime_end_minutes),
            devices,
            selected,
        }
        .render()
        .unwrap(),
    )
}

/// Saves the global default. Doesn't individually notify every device over SSE (unlike a single
/// device's own policy save) - the change only actually affects a device on its next sync, and
/// nudging every enrolled device at once for what's usually an infrequent settings tweak isn't
/// worth the churn; the existing periodic sync picks it up within its normal interval regardless.
pub async fn save_global_schedule(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(fields): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();

    sqlx::query(
        "UPDATE global_schedule SET weekday_start_minutes = ?, weekday_end_minutes = ?, \
         weekend_start_minutes = ?, weekend_end_minutes = ?, bedtime_start_minutes = ?, \
         bedtime_end_minutes = ?, updated_at = datetime('now') WHERE id = 1",
    )
    .bind(time_input_to_minutes(&field("weekday_start")))
    .bind(time_input_to_minutes(&field("weekday_end")))
    .bind(time_input_to_minutes(&field("weekend_start")))
    .bind(time_input_to_minutes(&field("weekend_end")))
    .bind(time_input_to_minutes(&field("bedtime_start")))
    .bind(time_input_to_minutes(&field("bedtime_end")))
    .execute(&state.db)
    .await
    .ok();

    Redirect::to("/schedules")
}

pub async fn save_device_schedule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(fields): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();
    let custom_enabled = fields.contains_key("custom_schedule_enabled");

    sqlx::query(
        "UPDATE device_policy SET custom_schedule_enabled = ?, weekday_start_minutes = ?, \
         weekday_end_minutes = ?, weekend_start_minutes = ?, weekend_end_minutes = ?, \
         bedtime_start_minutes = ?, bedtime_end_minutes = ?, updated_at = datetime('now') \
         WHERE device_id = ?",
    )
    .bind(custom_enabled)
    .bind(time_input_to_minutes(&field("weekday_start")))
    .bind(time_input_to_minutes(&field("weekday_end")))
    .bind(time_input_to_minutes(&field("weekend_start")))
    .bind(time_input_to_minutes(&field("weekend_end")))
    .bind(time_input_to_minutes(&field("bedtime_start")))
    .bind(time_input_to_minutes(&field("bedtime_end")))
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    // Same instant-nudge pattern as devices::update_policy - a schedule change is exactly the
    // kind of thing worth reflecting immediately rather than waiting out the periodic sync.
    let _ = state.command_notify.send(id);

    Redirect::to(&format!("/schedules?device={id}"))
}
