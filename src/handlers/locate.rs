//! Find My Device admin UI: a device picker + map (see `templates/device_locate.html`,
//! Leaflet against public OSM tiles) plus Ring/Lock/Wipe. Commands are queued
//! into `device_commands` and picked up by the device on its next regular
//! policy fetch (see `handlers::device_api::policy`) - no push mechanism,
//! same 2-minute-polling tradeoff as the rest of this project.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Json, Redirect};
use axum::{Extension, Form};
use std::collections::HashMap;
use std::time::Duration;

use crate::AppState;
use crate::models::{Device, DeviceCommand, DeviceLocation};
use crate::security::{self, CurrentAdmin};

#[derive(Template)]
#[template(path = "device_locate.html")]
struct LocateTemplate {
    title: String,
    devices: Vec<Device>,
    selected: Option<Device>,
    /// Same id as `selected.id`, but as a plain `i64` (0 = none selected) so
    /// the dropdown's `<option>` loop can compare without nested `if let`.
    selected_id: i64,
    commands: Vec<DeviceCommand>,
    wipe_error: Option<String>,
}

async fn render_locate_page(
    state: &AppState,
    selected_id: Option<i64>,
    wipe_error: Option<String>,
) -> Html<String> {
    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let selected = selected_id.and_then(|id| devices.iter().find(|d| d.id == id).cloned());

    let commands = if let Some(ref dev) = selected {
        sqlx::query_as::<_, DeviceCommand>(
            "SELECT * FROM device_commands WHERE device_id = ? \
             ORDER BY requested_at DESC LIMIT 20",
        )
        .bind(dev.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    let selected_id = selected.as_ref().map(|d| d.id).unwrap_or(0);

    Html(
        LocateTemplate {
            title: "Find My Device".to_string(),
            devices,
            selected,
            selected_id,
            commands,
            wipe_error,
        }
        .render()
        .unwrap(),
    )
}

pub async fn show_locate(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let selected_id = params.get("device").and_then(|s| s.parse::<i64>().ok());
    render_locate_page(&state, selected_id, None).await
}

pub async fn locations_json(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let locations = sqlx::query_as::<_, DeviceLocation>(
        "SELECT * FROM device_locations WHERE device_id = ? ORDER BY captured_at ASC",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Json(locations)
}

/// Deletes any not-yet-delivered command for this device before inserting the
/// new one - "your last action wins", and doubles as a way to cancel a
/// queued-but-not-yet-delivered wipe by queuing something else before it
/// lands. Once a command is delivered it's no longer touched by this.
async fn queue_command(state: &AppState, device_id: i64, command: &str) {
    sqlx::query("DELETE FROM device_commands WHERE device_id = ? AND delivered_at IS NULL")
        .bind(device_id)
        .execute(&state.db)
        .await
        .ok();
    sqlx::query("INSERT INTO device_commands (device_id, command) VALUES (?, ?)")
        .bind(device_id)
        .bind(command)
        .execute(&state.db)
        .await
        .ok();
}

pub async fn ring(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    queue_command(&state, id, "ring").await;
    security::record_security_event(
        &state.db,
        "device_command_queued",
        Some(&admin.username),
        None,
        Some("ring"),
    )
    .await;
    Redirect::to(&format!("/devices/locate?device={id}"))
}

pub async fn lock(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    queue_command(&state, id, "lock").await;
    security::record_security_event(
        &state.db,
        "device_command_queued",
        Some(&admin.username),
        None,
        Some("lock"),
    )
    .await;
    Redirect::to(&format!("/devices/locate?device={id}"))
}

/// Gated the same way backup restore/delete already are in this project
/// (`templates/backups.html`) - the admin must type the device's exact name
/// before this actually queues anything. Wipe is irreversible and the device
/// can never acknowledge it (it's gone), so this confirmation is the only
/// safety net there is.
pub async fn wipe(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(device) = device else {
        return Redirect::to("/devices/locate").into_response();
    };

    let confirm = form.get("confirm_name").map(|s| s.trim()).unwrap_or("");
    if confirm != device.name {
        return render_locate_page(
            &state,
            Some(id),
            Some("That didn't match the device name - nothing was wiped.".to_string()),
        )
        .await
        .into_response();
    }

    queue_command(&state, id, "wipe").await;
    security::record_security_event(
        &state.db,
        "device_wipe_queued",
        Some(&admin.username),
        None,
        Some(&device.name),
    )
    .await;
    Redirect::to(&format!("/devices/locate?device={id}")).into_response()
}

/// Keeps the location trail bounded - same shape as the other scheduled
/// background loops in this project (`handlers::backups::run_scheduled_backups`,
/// `handlers::tracked_apps::run_scheduled_tracked_app_sync`).
pub async fn run_location_pruning(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60 * 24));
    loop {
        interval.tick().await;
        sqlx::query("DELETE FROM device_locations WHERE received_at < datetime('now', '-30 days')")
            .execute(&state.db)
            .await
            .ok();
    }
}
