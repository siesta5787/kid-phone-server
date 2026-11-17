//! App groups - a parent-named set of apps on one device ("Streaming", "Games") sharing one daily
//! time limit, one allowed-hours window and one pause/allow override, so a parent manages a few
//! groups instead of a setting per app. See migrations/0024_app_groups.sql.
//!
//! Everyday controls (time used, Pause/Allow) live on the device page - see [summaries]. Setting
//! groups up lives on its own page (`/devices/{id}/app-groups`) so the device page stays short.
//! The phone does all the enforcing and time counting against its own clock (kids-launcher-mdm's
//! `AppGroups.kt`), so it keeps working offline - this module only stores the rules and shows the
//! phone's last report.

use std::collections::{HashMap, HashSet};

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;

use crate::AppState;
use crate::handlers::devices::remaining_label;
use crate::handlers::schedules::{minutes_to_time_input, time_input_to_minutes};
use crate::models::{AppGroup, Device, DevicePolicy, DeviceStatus, InstalledApp, now_epoch_ms};
use crate::security::CurrentAdmin;

/// Longest group name accepted - it has to fit on one line on the device page.
const MAX_NAME_CHARS: usize = 40;

/// Daily-limit choices offered in the edit form, in minutes.
const LIMIT_CHOICES: [i64; 9] = [15, 30, 45, 60, 90, 120, 180, 240, 360];

/// Longest Pause/Allow accepted from the form - anything longer should use "until I change it".
const MAX_OVERRIDE_MINUTES: i64 = 7 * 24 * 60;

pub async fn groups_for_device(state: &AppState, device_id: i64) -> Vec<AppGroup> {
    sqlx::query_as::<_, AppGroup>(
        "SELECT * FROM app_groups WHERE device_id = ? ORDER BY name COLLATE NOCASE, id",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
}

/// "45 min", "1 h", "1 h 30 min".
fn duration_label(minutes: i64) -> String {
    let (h, m) = (minutes / 60, minutes % 60);
    match (h, m) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// "3:00 PM" for a minutes-since-midnight value.
fn clock_label(minutes: i64) -> String {
    let (h, m) = (minutes / 60 % 24, minutes % 60);
    let suffix = if h < 12 { "AM" } else { "PM" };
    let h12 = match h % 12 {
        0 => 12,
        h => h,
    };
    format!("{h12}:{m:02} {suffix}")
}

/// The allowed-hours window as text, or None when there isn't one (any time). Same "null or
/// start == end means no restriction" rule as the phone.
fn hours_label(start: Option<i64>, end: Option<i64>) -> Option<String> {
    match (start, end) {
        (Some(s), Some(e)) if s != e => Some(format!("{} to {}", clock_label(s), clock_label(e))),
        _ => None,
    }
}

/// One group's line on the device page - see `device_detail.html`.
pub struct AppGroupSummary {
    pub id: i64,
    pub name: String,
    /// e.g. "3 apps · 1 h a day · 3:00 PM to 8:00 PM".
    pub rules_label: String,
    /// e.g. "35 min of 1 h used today" - empty when there's nothing to show yet.
    pub usage_label: String,
    /// e.g. "Available", "Paused by you for another 45 min", "Blocked - time's up for today".
    pub status_label: String,
    /// The group's apps can't be opened right now.
    pub blocked: bool,
    /// A parent's Pause/Allow is in effect - the page offers "Back to rules".
    pub has_override: bool,
}

/// Builds the device page's group lines. `today` is the server's local date (YYYY-MM-DD) - the
/// phone reports usage against its own date, so a report from an earlier day is labelled with
/// that day instead of passing for today's.
pub fn summaries(groups: &[AppGroup], now_ms: i64, today: &str) -> Vec<AppGroupSummary> {
    groups
        .iter()
        .map(|g| {
            let app_count = g.packages().len();
            let plural = if app_count == 1 { "" } else { "s" };
            let mut rules = vec![format!("{app_count} app{plural}")];
            if let Some(limit) = g.daily_limit_minutes {
                rules.push(format!("{} a day", duration_label(limit)));
            }
            if let Some(hours) = hours_label(g.allowed_start_minutes, g.allowed_end_minutes) {
                rules.push(hours);
            }
            if rules.len() == 1 {
                rules.push("no limit or hours set".to_string());
            }

            let usage_label = match (g.used_minutes, g.usage_day.as_deref()) {
                (Some(used), Some(day)) if day == today => {
                    let used = duration_label(used);
                    match g.daily_limit_minutes {
                        Some(limit) => format!("{used} of {} used today", duration_label(limit)),
                        None => format!("{used} used today"),
                    }
                }
                (Some(used), Some(day)) => {
                    format!("{} used on {day} (last report)", duration_label(used))
                }
                _ => String::new(),
            };

            let until_text = |until: Option<i64>| match until {
                Some(u) => remaining_label(u, now_ms),
                None => "until you change it".to_string(),
            };
            let active_override = g.active_override(now_ms);
            let (status_label, blocked) = match active_override {
                Some(("pause", until)) => (format!("Paused by you {}", until_text(until)), true),
                Some((_, until)) => (format!("Allowed by you {}", until_text(until)), false),
                // No parent override - go by what the phone last reported. A "PAUSED" report with
                // no override left means one just ended and the phone hasn't re-reported yet.
                None => match g.blocked_reason.as_deref() {
                    Some("OUTSIDE_HOURS") => ("Blocked - outside allowed hours".to_string(), true),
                    Some("TIME_UP") => ("Blocked - time's up for today".to_string(), true),
                    _ if g.usage_reported_at.is_none() => {
                        ("Waiting for the phone to pick this up".to_string(), false)
                    }
                    _ => ("Available".to_string(), false),
                },
            };

            AppGroupSummary {
                id: g.id,
                name: g.name.clone(),
                rules_label: rules.join(" · "),
                usage_label,
                status_label,
                blocked,
                has_override: active_override.is_some(),
            }
        })
        .collect()
}

const NOTE_OLD_LAUNCHER: &str = "This phone's launcher is too old for app groups - they'll \
    start working after its next update.";

const NOTE_NO_USAGE_ACCESS: &str = "This phone can't count app time yet, so daily limits don't \
    apply. On the phone, open the launcher's Settings and tap \"App time tracking\". Allowed hours \
    and Pause work without it.";

/// A warning for the device page/manage page when app groups can't fully work on this phone, or
/// an empty string when they can.
pub fn usage_note(groups: &[AppGroup], latest_status: Option<&DeviceStatus>) -> String {
    if groups.is_empty() {
        return String::new();
    }
    match latest_status.map(|s| s.usage_access_granted) {
        Some(None) => NOTE_OLD_LAUNCHER.to_string(),
        Some(Some(false)) if groups.iter().any(|g| g.daily_limit_minutes.is_some()) => {
            NOTE_NO_USAGE_ACCESS.to_string()
        }
        _ => String::new(),
    }
}

/// One app checkbox on the manage page.
struct AppChoice {
    package_name: String,
    label: String,
    checked: bool,
    /// Name of the other group this app is in, if any - ticking it here moves it.
    other_group: Option<String>,
}

struct LimitChoice {
    minutes: i64,
    label: String,
    selected: bool,
}

struct GroupForm {
    id: i64,
    name: String,
    no_limit: bool,
    limit_choices: Vec<LimitChoice>,
    allowed_start: String,
    allowed_end: String,
    apps: Vec<AppChoice>,
}

#[derive(Template)]
#[template(path = "app_groups.html")]
struct AppGroupsTemplate {
    title: String,
    device: Device,
    groups: Vec<GroupForm>,
    note: String,
}

pub async fn show_app_groups(
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
        return (axum::http::StatusCode::NOT_FOUND, "Device not found").into_response();
    };

    let allowlist: Option<HashSet<String>> =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .and_then(|p| p.allowlist_json)
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            .filter(|list| !list.is_empty())
            .map(|list| list.into_iter().collect());

    let latest_status = sqlx::query_as::<_, DeviceStatus>(
        "SELECT * FROM device_status WHERE device_id = ? ORDER BY reported_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    // Only apps the kid is actually allowed - a disallowed app is hidden on the phone anyway, so
    // offering it here would only confuse.
    let mut candidates: Vec<InstalledApp> = latest_status
        .as_ref()
        .and_then(|s| s.installed_apps_json.as_deref())
        .and_then(|j| serde_json::from_str::<Vec<InstalledApp>>(j).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|a| {
            allowlist
                .as_ref()
                .is_none_or(|al| al.contains(&a.package_name))
        })
        .collect();
    candidates.sort_by_key(|a| a.label.to_lowercase());

    let groups = groups_for_device(&state, id).await;
    let mut owner: HashMap<String, (i64, String)> = HashMap::new();
    for g in &groups {
        for package in g.packages() {
            owner.insert(package, (g.id, g.name.clone()));
        }
    }

    let forms = groups
        .iter()
        .map(|g| {
            let in_group: HashSet<String> = g.packages().into_iter().collect();
            let mut apps: Vec<AppChoice> = candidates
                .iter()
                .map(|a| AppChoice {
                    package_name: a.package_name.clone(),
                    label: a.label.clone(),
                    checked: in_group.contains(&a.package_name),
                    other_group: owner
                        .get(&a.package_name)
                        .filter(|(gid, _)| *gid != g.id)
                        .map(|(_, name)| name.clone()),
                })
                .collect();
            // Keep packages that are in the group but no longer offered (uninstalled, or taken off
            // the allowlist) visible, so they can still be unticked.
            for package in &in_group {
                if !candidates.iter().any(|a| &a.package_name == package) {
                    apps.push(AppChoice {
                        package_name: package.clone(),
                        label: format!("{package} (not currently on the phone or allowed)"),
                        checked: true,
                        other_group: None,
                    });
                }
            }

            let mut limits: Vec<i64> = LIMIT_CHOICES.to_vec();
            if let Some(current) = g.daily_limit_minutes {
                if !limits.contains(&current) {
                    limits.push(current);
                    limits.sort_unstable();
                }
            }
            GroupForm {
                id: g.id,
                name: g.name.clone(),
                no_limit: g.daily_limit_minutes.is_none(),
                limit_choices: limits
                    .into_iter()
                    .map(|m| LimitChoice {
                        minutes: m,
                        label: duration_label(m),
                        selected: g.daily_limit_minutes == Some(m),
                    })
                    .collect(),
                allowed_start: minutes_to_time_input(g.allowed_start_minutes),
                allowed_end: minutes_to_time_input(g.allowed_end_minutes),
                apps,
            }
        })
        .collect();

    Html(
        AppGroupsTemplate {
            title: format!("App groups · {}", device.name),
            note: usage_note(&groups, latest_status.as_ref()),
            device,
            groups: forms,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct CreateGroupForm {
    name: String,
}

fn clean_name(raw: &str) -> Option<String> {
    let name: String = raw.trim().chars().take(MAX_NAME_CHARS).collect();
    (!name.is_empty()).then_some(name)
}

pub async fn create_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(form): Form<CreateGroupForm>,
) -> impl IntoResponse {
    let Some(name) = clean_name(&form.name) else {
        return Redirect::to(&format!("/devices/{id}/app-groups"));
    };
    let new_id: Option<i64> =
        sqlx::query_scalar("INSERT INTO app_groups (device_id, name) VALUES (?, ?) RETURNING id")
            .bind(id)
            .bind(&name)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    match new_id {
        Some(gid) => Redirect::to(&format!("/devices/{id}/app-groups#group-{gid}")),
        None => Redirect::to(&format!("/devices/{id}/app-groups")),
    }
}

/// Saves one group's edit form. Takes the raw body rather than `Form<T>` because `packages` is a
/// repeated checkbox field, which axum's `Form` can't deserialize - see the matching gotcha in
/// CLAUDE.md. Ticking an app that's in another of this device's groups moves it here, so an app is
/// never in two groups (which would make "which limit applies?" ambiguous).
pub async fn update_group(
    State(state): State<AppState>,
    Path((id, gid)): Path<(i64, i64)>,
    Extension(_admin): Extension<CurrentAdmin>,
    body: Bytes,
) -> impl IntoResponse {
    let back = Redirect::to(&format!("/devices/{id}/app-groups#group-{gid}"));

    let mut name = String::new();
    let mut limit_raw = String::new();
    let mut start_raw = String::new();
    let mut end_raw = String::new();
    let mut packages: Vec<String> = Vec::new();
    for (key, value) in form_urlencoded::parse(&body) {
        match &*key {
            "name" => name = value.into_owned(),
            "daily_limit_minutes" => limit_raw = value.into_owned(),
            "allowed_start" => start_raw = value.into_owned(),
            "allowed_end" => end_raw = value.into_owned(),
            "packages" => {
                let package = value.trim().to_string();
                if !package.is_empty() && !packages.contains(&package) {
                    packages.push(package);
                }
            }
            _ => {}
        }
    }

    let Some(name) = clean_name(&name) else {
        return back;
    };
    let daily_limit_minutes = limit_raw
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|m| (1..=24 * 60).contains(m));
    let parse_time = |raw: &str| time_input_to_minutes(raw).filter(|m| (0..24 * 60).contains(m));
    let start = parse_time(start_raw.as_str());
    let end = parse_time(end_raw.as_str());
    let (allowed_start, allowed_end) = match (start, end) {
        (Some(s), Some(e)) if s != e => (Some(s), Some(e)),
        _ => (None, None),
    };
    let Ok(packages_json) = serde_json::to_string(&packages) else {
        return back;
    };

    let updated = sqlx::query(
        "UPDATE app_groups SET name = ?, packages_json = ?, daily_limit_minutes = ?, \
         allowed_start_minutes = ?, allowed_end_minutes = ? WHERE id = ? AND device_id = ?",
    )
    .bind(&name)
    .bind(&packages_json)
    .bind(daily_limit_minutes)
    .bind(allowed_start)
    .bind(allowed_end)
    .bind(gid)
    .bind(id)
    .execute(&state.db)
    .await
    .map(|r| r.rows_affected() > 0)
    .unwrap_or(false);
    if !updated {
        return back;
    }

    let moved: HashSet<&String> = packages.iter().collect();
    for other in groups_for_device(&state, id).await {
        if other.id == gid {
            continue;
        }
        let before = other.packages();
        let after: Vec<&String> = before.iter().filter(|p| !moved.contains(p)).collect();
        if after.len() == before.len() {
            continue;
        }
        let Ok(json) = serde_json::to_string(&after) else {
            continue;
        };
        sqlx::query("UPDATE app_groups SET packages_json = ? WHERE id = ?")
            .bind(&json)
            .bind(other.id)
            .execute(&state.db)
            .await
            .ok();
    }

    let _ = state.command_notify.send(id);
    back
}

pub async fn delete_group(
    State(state): State<AppState>,
    Path((id, gid)): Path<(i64, i64)>,
    Extension(_admin): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    sqlx::query("DELETE FROM app_groups WHERE id = ? AND device_id = ?")
        .bind(gid)
        .bind(id)
        .execute(&state.db)
        .await
        .ok();
    let _ = state.command_notify.send(id);
    Redirect::to(&format!("/devices/{id}/app-groups"))
}

#[derive(Deserialize)]
pub struct GroupOverrideForm {
    /// `pause`, `allow`, or `rules` (clear the override and follow the group's rules again).
    action: String,
    /// Blank = until the parent changes it.
    #[serde(default)]
    duration_minutes: String,
}

/// The device page's per-group "Pause" / "Allow" / "Back to rules" buttons. Pause blocks the
/// group's apps regardless of its limit and hours; Allow lets them be used regardless (e.g. extra
/// time once today's limit is used up). Same delivery as the screen-time "Lock now": an SSE nudge,
/// then the phone checks the end time against its own clock.
pub async fn set_group_override(
    State(state): State<AppState>,
    Path((id, gid)): Path<(i64, i64)>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(form): Form<GroupOverrideForm>,
) -> impl IntoResponse {
    let (mode, until_ms) = match form.action.as_str() {
        "pause" | "allow" => {
            let until_ms = form
                .duration_minutes
                .trim()
                .parse::<i64>()
                .ok()
                .filter(|m| (1..=MAX_OVERRIDE_MINUTES).contains(m))
                .map(|m| now_epoch_ms() + m * 60_000);
            (Some(form.action.as_str()), until_ms)
        }
        "rules" => (None, None),
        _ => return Redirect::to(&format!("/devices/{id}")),
    };

    sqlx::query(
        "UPDATE app_groups SET override_mode = ?, override_until_ms = ? \
         WHERE id = ? AND device_id = ?",
    )
    .bind(mode)
    .bind(until_ms)
    .bind(gid)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    let _ = state.command_notify.send(id);
    Redirect::to(&format!("/devices/{id}#app-groups"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(limit: Option<i64>, start: Option<i64>, end: Option<i64>) -> AppGroup {
        AppGroup {
            id: 1,
            name: "Streaming".to_string(),
            packages_json: r#"["a","b"]"#.to_string(),
            daily_limit_minutes: limit,
            allowed_start_minutes: start,
            allowed_end_minutes: end,
            ..Default::default()
        }
    }

    #[test]
    fn labels() {
        assert_eq!(duration_label(45), "45 min");
        assert_eq!(duration_label(60), "1 h");
        assert_eq!(duration_label(90), "1 h 30 min");
        assert_eq!(clock_label(0), "12:00 AM");
        assert_eq!(clock_label(15 * 60 + 5), "3:05 PM");
        assert_eq!(hours_label(Some(60), Some(60)), None);
        assert_eq!(hours_label(None, Some(60)), None);
    }

    #[test]
    fn summary_shows_rules_usage_and_status() {
        let mut g = group(Some(60), Some(15 * 60), Some(20 * 60));
        g.used_minutes = Some(35);
        g.usage_day = Some("2026-11-16".to_string());
        g.usage_reported_at = Some("2026-11-16 15:40:00".to_string());
        let s = &summaries(&[g], 0, "2026-11-16")[0];
        assert_eq!(s.rules_label, "2 apps · 1 h a day · 3:00 PM to 8:00 PM");
        assert_eq!(s.usage_label, "35 min of 1 h used today");
        assert_eq!(s.status_label, "Available");
        assert!(!s.blocked && !s.has_override);
    }

    #[test]
    fn summary_labels_an_old_report_with_its_day() {
        let mut g = group(None, None, None);
        g.used_minutes = Some(10);
        g.usage_day = Some("2026-11-15".to_string());
        let s = &summaries(&[g], 0, "2026-11-16")[0];
        assert_eq!(s.rules_label, "2 apps · no limit or hours set");
        assert_eq!(s.usage_label, "10 min used on 2026-11-15 (last report)");
    }

    #[test]
    fn parent_override_beats_the_phones_report() {
        let mut g = group(Some(60), None, None);
        g.blocked_reason = Some("TIME_UP".to_string());
        g.usage_reported_at = Some("x".to_string());
        assert!(summaries(std::slice::from_ref(&g), 0, "d")[0].blocked);

        g.override_mode = Some("allow".to_string());
        g.override_until_ms = Some(30 * 60_000);
        let s = &summaries(std::slice::from_ref(&g), 0, "d")[0];
        assert!(!s.blocked && s.has_override);
        assert_eq!(s.status_label, "Allowed by you for another 30 min");

        g.override_mode = Some("pause".to_string());
        g.override_until_ms = None;
        let s = &summaries(std::slice::from_ref(&g), 0, "d")[0];
        assert!(s.blocked);
        assert_eq!(s.status_label, "Paused by you until you change it");
    }
}
