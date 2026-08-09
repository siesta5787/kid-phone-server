//! Admin viewer for the conversation journal pulled from kids-mdm-im - see
//! migrations/0015_device_journal.sql and `handlers::device_api::journal_upload`. A
//! device-detail sub-page (linked from `device_detail.html`) rather than its own bottom-nav
//! tab - not every device runs kids-mdm-im, and this is "what's on this specific phone," the
//! same category as the Apps-to-install card, not a fleet-wide view like DNS/Filters.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse};
use std::collections::HashMap;

use crate::AppState;
use crate::models::{Device, DeviceJournalEntry, JournalThreadSummary};

#[derive(Template)]
#[template(path = "device_journal.html")]
struct DeviceJournalTemplate {
    title: String,
    device: Device,
    threads: Vec<JournalThreadSummary>,
    selected_thread_id: Option<i64>,
    entries: Vec<DeviceJournalEntry>,
}

pub async fn show_journal(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<HashMap<String, String>>,
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

    // One row per thread, its own most-recent entry, most-recently-active thread first -
    // SQLite's "bare column in an aggregate query picks the row from the MAX() group" behavior
    // (documented, not accidental - see https://sqlite.org/lang_select.html#bareagg) is exactly
    // what makes `display_name`/`entry_type`/`body` here line up with the same row `MAX(occurred_at)`
    // picked, without a second query per thread.
    let thread_rows: Vec<(i64, Option<String>, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT thread_id, display_name, entry_type, body, MAX(occurred_at) as last_occurred_at \
         FROM device_journal_entries WHERE device_id = ? \
         GROUP BY thread_id ORDER BY last_occurred_at DESC",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let threads: Vec<JournalThreadSummary> = thread_rows
        .into_iter()
        .map(
            |(thread_id, display_name, entry_type, body, last_occurred_at)| {
                let preview = match entry_type.as_str() {
                    "MESSAGE" => body.unwrap_or_default(),
                    "MEDIA" => "\u{1F4CE} Photo/video".to_string(),
                    "CALL" => "\u{1F4DE} Call".to_string(),
                    _ => String::new(),
                };
                JournalThreadSummary {
                    thread_id,
                    display_name,
                    preview,
                    last_occurred_at,
                }
            },
        )
        .collect();

    let selected_thread_id = params
        .get("thread_id")
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| threads.first().map(|t| t.thread_id));

    let entries = if let Some(thread_id) = selected_thread_id {
        sqlx::query_as::<_, DeviceJournalEntry>(
            "SELECT * FROM device_journal_entries WHERE device_id = ? AND thread_id = ? \
             ORDER BY occurred_at ASC LIMIT 500",
        )
        .bind(id)
        .bind(thread_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    Html(
        DeviceJournalTemplate {
            title: format!("{} - Conversations", device.name),
            device,
            threads,
            selected_thread_id,
            entries,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Serves one media file - gated behind the same admin-session auth as every other route in
/// `admin_routes` (see main.rs), unlike the device-facing bearer-token API. `entry.id` isn't part
/// of the URL (just `remote_id`, scoped to `device_id`) since that's what the admin page's links
/// already have on hand from the same `device_journal_entries` row.
pub async fn download_media(
    State(state): State<AppState>,
    Path((id, remote_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    let entry = sqlx::query_as::<_, DeviceJournalEntry>(
        "SELECT * FROM device_journal_entries WHERE device_id = ? AND remote_id = ?",
    )
    .bind(id)
    .bind(remote_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let Some(entry) = entry else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(media_path) = entry.media_path else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match tokio::fs::read(&media_path).await {
        Ok(bytes) => {
            let content_type = entry
                .media_content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
