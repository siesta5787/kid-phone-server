//! Admin UI for the in-process DNS content filter (see `crate::dns_engine`).
//! Every mutating handler here: updates the DB, calls `dns_engine::rebuild`
//! to recompute and hot-swap the running filter state (no restart needed),
//! then redirects back to `/dns` - same shape as `handlers::devices::update_policy`.
//! Toggling the feature on/off additionally requests the `iptables` redirect
//! via the same root-owned-watcher flag-file mechanism `system_maintenance.rs`
//! already uses for reboot/Tailscale-update/etc - the only part of this
//! feature that's actually privileged.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use std::collections::HashMap;
use std::time::Duration;

use crate::AppState;
use crate::dns_engine;
use crate::models::{DnsBlocklist, DnsCustomDomain, DnsFilterSettings};
use crate::security::{self, CurrentAdmin};

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
}

pub async fn show_dns_filter(State(state): State<AppState>) -> impl IntoResponse {
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

    let custom =
        sqlx::query_as::<_, DnsCustomDomain>("SELECT * FROM dns_custom_domains ORDER BY domain")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    let (blocked_domains, allowed_domains): (Vec<_>, Vec<_>) =
        custom.into_iter().partition(|d| d.list_type == "block");

    let (total_queries, blocked_queries, started_at) = dns_engine::stats_snapshot(&state.dns_stats);
    let running_since = started_at.format("%Y-%m-%d %H:%M UTC").to_string();

    let tailscale_ip = tailscale_self_ip().await;

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

    if !domain.is_empty() {
        sqlx::query("INSERT INTO dns_custom_domains (domain, list_type) VALUES (?, ?)")
            .bind(&domain)
            .bind(list_type)
            .execute(&state.db)
            .await
            .ok();
        dns_engine::rebuild(&state, &state.dns_state).await;
    }

    Redirect::to("/dns")
}

pub async fn delete_custom_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    sqlx::query("DELETE FROM dns_custom_domains WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    dns_engine::rebuild(&state, &state.dns_state).await;
    Redirect::to("/dns")
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
    }
}
