//! Admin viewer for browsing history pulled from the kids-mdm-browser fork - see
//! migrations/0016_device_browser_history.sql and `handlers::device_api::browser_history_upload`.
//! A device-detail sub-page (linked from `device_detail.html`), same category as the journal
//! viewer - not every device runs the browser fork, and this is "what's on this specific phone."

use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};

use crate::AppState;
use crate::models::{Device, DeviceBrowserHistoryEntry};

#[derive(Template)]
#[template(path = "device_browser_history.html")]
struct DeviceBrowserHistoryTemplate {
    title: String,
    device: Device,
    entries: Vec<DeviceBrowserHistoryEntry>,
}

pub async fn show_history(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(device) = device else {
        return (StatusCode::NOT_FOUND, "Device not found").into_response();
    };

    let entries = sqlx::query_as::<_, DeviceBrowserHistoryEntry>(
        "SELECT * FROM device_browser_history_entries WHERE device_id = ? \
         ORDER BY visited_at DESC LIMIT 500",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Html(
        DeviceBrowserHistoryTemplate {
            title: format!("{} - Browsing history", device.name),
            device,
            entries,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
