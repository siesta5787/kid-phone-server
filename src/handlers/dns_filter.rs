//! Admin UI for the in-process DNS content filter (see `crate::dns_engine`).
//! Every mutating handler here: updates the DB, calls `dns_engine::rebuild`
//! to recompute and hot-swap the running filter state (no restart needed),
//! then redirects back to `/dns` - same shape as `handlers::devices::update_policy`.
//! Toggling the feature on/off additionally requests the `iptables` redirect
//! via the same root-owned-watcher flag-file mechanism `system_maintenance.rs`
//! already uses for reboot/Tailscale-update/etc - the only part of this
//! feature that's actually privileged.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use std::collections::HashMap;
use std::time::Duration;

use crate::AppState;
use crate::dns_engine;
use crate::models::{Device, DeviceDnsEvent, DnsBlocklist, DnsCustomDomain, DnsFilterSettings};
use crate::security::{self, CurrentAdmin};

/// One blocklist feed as shown on a specific device's row - `effective_enabled`
/// already resolves the global default against any `device_blocklist_overrides`
/// row for this device, so the template doesn't need to do that lookup itself.
struct BlocklistRow {
    blocklist: DnsBlocklist,
    effective_enabled: bool,
    is_override: bool,
}

const FLAG_FILE: &str = "data/update_requested";

async fn request_privileged_action(
    state: &AppState,
    admin: &crate::models::AdminUser,
    action: &str,
) {
    if tokio::fs::write(FLAG_FILE, action).await.is_ok() {
        security::record_security_event(
            &state.db,
            "dns_filter_toggled",
            Some(&admin.username),
            None,
            None,
        )
        .await;
    } else {
        tracing::warn!(
            "couldn't write {FLAG_FILE} to request '{action}' - the update watcher may not be set up on this install"
        );
    }
}

#[derive(Template)]
#[template(path = "dns_filter.html")]
struct DnsFilterTemplate {
    title: String,
    settings: DnsFilterSettings,
    blocklists: Vec<DnsBlocklist>,
    blocked_domains: Vec<DnsCustomDomain>,
    allowed_domains: Vec<DnsCustomDomain>,
    total_queries: u64,
    blocked_queries: u64,
    running_since: String,
    tailscale_ip: Option<String>,
    devices: Vec<Device>,
    selected: Option<Device>,
    selected_id: i64,
    device_blocklist_rows: Vec<BlocklistRow>,
    device_blocked_domains: Vec<DnsCustomDomain>,
    device_allowed_domains: Vec<DnsCustomDomain>,
}

pub async fn show_dns_filter(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let settings =
        sqlx::query_as::<_, DnsFilterSettings>("SELECT * FROM dns_filter_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .expect("dns_filter_settings singleton row always exists");

    let blocklists =
        sqlx::query_as::<_, DnsBlocklist>("SELECT * FROM dns_blocklists ORDER BY name")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    // Global (device_id IS NULL) custom domains only - the site-wide
    // defaults section. Per-device custom domains are loaded separately
    // below, only once a device is selected.
    let custom = sqlx::query_as::<_, DnsCustomDomain>(
        "SELECT * FROM dns_custom_domains WHERE device_id IS NULL ORDER BY domain",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let (blocked_domains, allowed_domains): (Vec<_>, Vec<_>) =
        custom.into_iter().partition(|d| d.list_type == "block");

    let (total_queries, blocked_queries, started_at) = dns_engine::stats_snapshot(&state.dns_stats);
    let running_since = started_at.format("%Y-%m-%d %H:%M UTC").to_string();

    let tailscale_ip = tailscale_self_ip().await;

    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    let selected_id = params.get("device").and_then(|s| s.parse::<i64>().ok());
    let selected = selected_id.and_then(|id| devices.iter().find(|d| d.id == id).cloned());

    let (device_blocklist_rows, device_blocked_domains, device_allowed_domains) =
        if let Some(ref dev) = selected {
            let overrides: HashMap<i64, bool> = sqlx::query_as::<_, (i64, bool)>(
                "SELECT blocklist_id, enabled FROM device_blocklist_overrides WHERE device_id = ?",
            )
            .bind(dev.id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

            let rows = blocklists
                .iter()
                .map(|b| {
                    let is_override = overrides.contains_key(&b.id);
                    let effective_enabled = overrides.get(&b.id).copied().unwrap_or(b.enabled);
                    BlocklistRow {
                        blocklist: b.clone(),
                        effective_enabled,
                        is_override,
                    }
                })
                .collect();

            let device_custom = sqlx::query_as::<_, DnsCustomDomain>(
                "SELECT * FROM dns_custom_domains WHERE device_id = ? ORDER BY domain",
            )
            .bind(dev.id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            let (dev_blocked, dev_allowed): (Vec<_>, Vec<_>) = device_custom
                .into_iter()
                .partition(|d| d.list_type == "block");

            (rows, dev_blocked, dev_allowed)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    let selected_id = selected.as_ref().map(|d| d.id).unwrap_or(0);

    Html(
        DnsFilterTemplate {
            title: "DNS/Filters".to_string(),
            settings,
            blocklists,
            blocked_domains,
            allowed_domains,
            total_queries,
            blocked_queries,
            running_since,
            tailscale_ip,
            devices,
            selected,
            selected_id,
            device_blocklist_rows,
            device_blocked_domains,
            device_allowed_domains,
        }
        .render()
        .unwrap(),
    )
}

/// Best-effort, read-only local `tailscale status` query - no privilege
/// needed (mirrors the existing `tailscale version` read-only check in
/// `system_maintenance.rs`) - lets the "connect your kid's device" card show
/// this Pi's own tailnet IP directly instead of making the admin go find it.
async fn tailscale_self_ip() -> Option<String> {
    let output = tokio::process::Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ip = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!ip.is_empty()).then_some(ip)
}

pub async fn toggle_enabled(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let enabled = form.contains_key("enabled");
    sqlx::query(
        "UPDATE dns_filter_settings SET enabled = ?, updated_at = datetime('now') WHERE id = 1",
    )
    .bind(enabled)
    .execute(&state.db)
    .await
    .ok();

    dns_engine::rebuild(&state, &state.dns_state).await;
    dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    request_privileged_action(
        &state,
        &admin,
        if enabled {
            "dns_filter_enable"
        } else {
            "dns_filter_disable"
        },
    )
    .await;

    Redirect::to("/dns")
}

pub async fn set_upstream(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let upstream = match form.get("upstream").map(String::as_str) {
        Some("quad9") => "quad9",
        _ => "cloudflare",
    };
    sqlx::query(
        "UPDATE dns_filter_settings SET upstream = ?, updated_at = datetime('now') WHERE id = 1",
    )
    .bind(upstream)
    .execute(&state.db)
    .await
    .ok();

    dns_engine::rebuild(&state, &state.dns_state).await;
    Redirect::to("/dns")
}

pub async fn create_blocklist(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let name = form.get("name").cloned().unwrap_or_default();
    let url = form.get("url").cloned().unwrap_or_default();
    let (name, url) = (name.trim(), url.trim());

    if !name.is_empty() && !url.is_empty() {
        sqlx::query("INSERT INTO dns_blocklists (name, url, enabled) VALUES (?, ?, 1)")
            .bind(name)
            .bind(url)
            .execute(&state.db)
            .await
            .ok();
        dns_engine::rebuild(&state, &state.dns_state).await;
        dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    }

    Redirect::to("/dns")
}

pub async fn toggle_blocklist(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let enabled = form.contains_key("enabled");
    sqlx::query("UPDATE dns_blocklists SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    dns_engine::rebuild(&state, &state.dns_state).await;
    dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    Redirect::to("/dns")
}

pub async fn delete_blocklist(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    sqlx::query("DELETE FROM dns_blocklists WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    dns_engine::rebuild(&state, &state.dns_state).await;
    dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    Redirect::to("/dns")
}

pub async fn create_custom_domain(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let domain = form.get("domain").cloned().unwrap_or_default();
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let list_type = match form.get("list_type").map(String::as_str) {
        Some("allow") => "allow",
        _ => "block",
    };
    // Absent/empty/unparseable = global (device_id NULL), same convention as
    // migrations/0011_client_side_dns_filtering.sql.
    let device_id = form.get("device_id").and_then(|s| s.parse::<i64>().ok());
    let redirect_to = match device_id {
        Some(id) => format!("/dns?device={id}"),
        None => "/dns".to_string(),
    };

    if !domain.is_empty() {
        sqlx::query(
            "INSERT INTO dns_custom_domains (domain, list_type, device_id) VALUES (?, ?, ?)",
        )
        .bind(&domain)
        .bind(list_type)
        .bind(device_id)
        .execute(&state.db)
        .await
        .ok();
        dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
        if device_id.is_none() {
            dns_engine::rebuild(&state, &state.dns_state).await;
        }
    }

    Redirect::to(&redirect_to)
}

/// Sets or clears this device's override for one blocklist feed. An empty
/// `enabled` form value (the checkbox is absent when unchecked, same as
/// every other checkbox handler in this file) still needs to distinguish
/// "override to off" from "no override, use the global default" - the form
/// carries an explicit `clear` action for the latter (see the template's
/// "Use default" control) rather than trying to infer it from a bare
/// checkbox POST.
pub async fn set_device_blocklist_override(
    State(state): State<AppState>,
    Path((device_id, blocklist_id)): Path<(i64, i64)>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if form.contains_key("clear") {
        sqlx::query(
            "DELETE FROM device_blocklist_overrides WHERE device_id = ? AND blocklist_id = ?",
        )
        .bind(device_id)
        .bind(blocklist_id)
        .execute(&state.db)
        .await
        .ok();
    } else {
        let enabled = form.contains_key("enabled");
        sqlx::query(
            "INSERT INTO device_blocklist_overrides (device_id, blocklist_id, enabled, updated_at) \
             VALUES (?, ?, ?, datetime('now')) \
             ON CONFLICT (device_id, blocklist_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
        )
        .bind(device_id)
        .bind(blocklist_id)
        .bind(enabled)
        .execute(&state.db)
        .await
        .ok();
    }

    Redirect::to(&format!("/dns?device={device_id}"))
}

#[derive(Template)]
#[template(path = "dns_log.html")]
struct DnsLogTemplate {
    title: String,
    devices: Vec<Device>,
    selected: Option<Device>,
    selected_id: i64,
    events: Vec<DeviceDnsEvent>,
}

/// Blocked-domain log admin page - near-identical shape to
/// `handlers::locate::show_locate`/`render_locate_page` (device picker + this
/// device's recent event rows).
pub async fn show_dns_log(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let selected_id = params.get("device").and_then(|s| s.parse::<i64>().ok());
    let selected = selected_id.and_then(|id| devices.iter().find(|d| d.id == id).cloned());

    let events = if let Some(ref dev) = selected {
        sqlx::query_as::<_, DeviceDnsEvent>(
            "SELECT * FROM device_dns_events WHERE device_id = ? \
             ORDER BY blocked_at DESC LIMIT 200",
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
        DnsLogTemplate {
            title: "Blocked activity".to_string(),
            devices,
            selected,
            selected_id,
            events,
        }
        .render()
        .unwrap(),
    )
}

pub async fn delete_custom_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    // Fetch the device scope first (if any) so the redirect can send the
    // admin back to the same device-filtered view they deleted it from,
    // rather than always bouncing to the global page.
    let device_id: Option<i64> =
        sqlx::query_scalar("SELECT device_id FROM dns_custom_domains WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    sqlx::query("DELETE FROM dns_custom_domains WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    if device_id.is_none() {
        dns_engine::rebuild(&state, &state.dns_state).await;
    }

    match device_id {
        Some(id) => Redirect::to(&format!("/dns?device={id}")),
        None => Redirect::to("/dns"),
    }
}

/// Hourly refresh of every enabled blocklist's remote content - same shape
/// as `tracked_apps::run_scheduled_tracked_app_sync`. Settings/domain-list
/// *changes* already trigger an immediate rebuild themselves; this loop is
/// only for picking up upstream blocklist content changes over time.
pub async fn run_blocklist_refresh(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        interval.tick().await;
        dns_engine::rebuild(&state, &state.dns_state).await;
        dns_engine::compile_blocklist(&state, &state.dns_compiled).await;
    }
}

/// Keeps the blocked-domain log bounded - same shape as
/// `handlers::locate::run_location_pruning`, just a longer retention window
/// (60 vs 30 days) since this log is lower-volume and higher conversational
/// value ("did my kid try to visit X") than a location trail.
pub async fn run_dns_event_pruning(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60 * 24));
    loop {
        interval.tick().await;
        sqlx::query(
            "DELETE FROM device_dns_events WHERE received_at < datetime('now', '-60 days')",
        )
        .execute(&state.db)
        .await
        .ok();
    }
}
