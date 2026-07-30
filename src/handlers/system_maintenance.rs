//! OS-level and Tailscale update management, plus scheduling - parallel to
//! (but separate from) the app's own self-update logic in
//! handlers::system_update. Both are rendered together on one combined page
//! by handlers::updates.
//!
//! Read-only status checks (apt list --upgradable, tailscale version) run
//! directly in this unprivileged process - they don't touch anything and
//! don't need root. Anything that actually changes the system (installing
//! packages, updating Tailscale, rebooting) goes through the same
//! flag-file + root-owned watcher pattern as the app's own update button;
//! see deploy/install.sh's watcher.sh for the privileged side.
//!
//! Scheduling is handled entirely by a separate root-owned timer
//! (kid-phone-server-scheduler.timer) that polls a plain config file this
//! handler writes - the schedule itself never needs to go through the
//! flag-file mechanism, since that indirection exists only to let this
//! unprivileged, internet-facing process request privileged actions.

use axum::Extension;
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::{Form, http};
use serde::Deserialize;
use std::time::Duration;

use crate::AppState;
use crate::handlers::updates;
use crate::security::{self, CurrentAdmin};

const FLAG_FILE: &str = "data/update_requested";
const SCHEDULE_FILE: &str = "data/schedule.conf";
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a command with a timeout - a stuck subprocess (e.g. `apt` blocked
/// waiting on the dpkg lock while an upgrade is still running) must never be
/// able to hang this page indefinitely. `watcher_busy` below is the primary
/// defense (skips calling apt at all when an update is known to be running);
/// this timeout is the backstop for cases that check doesn't catch.
async fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(cmd).args(args).output();
    let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, child)
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// True while the root-owned watcher is actively running a requested action
/// (an OS upgrade in particular can take a long time on a Pi's first run).
/// Querying another unit's status is a read-only systemd operation any local
/// user can do - no privilege needed, unlike actually controlling the unit.
async fn watcher_busy() -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "kid-phone-server-updater.service"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn apt_upgradable_count() -> Option<usize> {
    let output = run("apt", &["list", "--upgradable"]).await?;
    Some(
        output
            .lines()
            .filter(|l| !l.starts_with("Listing...") && !l.trim().is_empty())
            .count(),
    )
}

async fn tailscale_versions() -> Option<(String, String)> {
    let current = run("tailscale", &["version"]).await?;
    let current = current.lines().next().unwrap_or("").trim().to_string();

    // `--upstream` prints the same version block as plain `tailscale
    // version` (commit hash, long version, go version, ...) with an extra
    // "upstream: X" field appended somewhere in it - comparing the whole
    // blob against just current's first line always looked like an update
    // was available, even when up to date. Pull out just that field's
    // value via substring search rather than assuming it's on its own line,
    // since it's unclear whether tailscale's output actually has a newline
    // there or just a space.
    let upstream = run("tailscale", &["version", "--upstream"])
        .await
        .unwrap_or_default()
        .split("upstream:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("")
        .to_string();

    if current.is_empty() {
        return None;
    }
    Some((current, upstream))
}

fn reboot_required() -> bool {
    std::path::Path::new("/var/run/reboot-required").exists()
}

#[derive(Default, Clone)]
pub(crate) struct ScheduleConfig {
    pub(crate) frequency: String,
    pub(crate) day_of_week: String,
    pub(crate) day_of_month: String,
    pub(crate) check_time: String,
    pub(crate) auto_apply_os: bool,
    pub(crate) auto_apply_tailscale: bool,
    pub(crate) auto_reboot: bool,
}

impl ScheduleConfig {
    fn defaults() -> Self {
        ScheduleConfig {
            frequency: "daily".to_string(),
            day_of_week: "0".to_string(),
            day_of_month: "1".to_string(),
            check_time: "03:00".to_string(),
            auto_apply_os: false,
            auto_apply_tailscale: false,
            auto_reboot: false,
        }
    }

    async fn load() -> Self {
        let Ok(contents) = tokio::fs::read_to_string(SCHEDULE_FILE).await else {
            return Self::defaults();
        };
        let mut config = Self::defaults();
        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_string();
            match key.trim() {
                "FREQUENCY" => config.frequency = value,
                "DAY_OF_WEEK" => config.day_of_week = value,
                "DAY_OF_MONTH" => config.day_of_month = value,
                "CHECK_TIME" => config.check_time = value,
                "AUTO_APPLY_OS" => config.auto_apply_os = value == "true",
                "AUTO_APPLY_TAILSCALE" => config.auto_apply_tailscale = value == "true",
                "AUTO_REBOOT" => config.auto_reboot = value == "true",
                _ => {}
            }
        }
        config
    }

    fn to_file_contents(&self) -> String {
        format!(
            "FREQUENCY={}\nDAY_OF_WEEK={}\nDAY_OF_MONTH={}\nCHECK_TIME={}\nAUTO_APPLY_OS={}\nAUTO_APPLY_TAILSCALE={}\nAUTO_REBOOT={}\n",
            self.frequency,
            self.day_of_week,
            self.day_of_month,
            self.check_time,
            self.auto_apply_os,
            self.auto_apply_tailscale,
            self.auto_reboot,
        )
    }

    /// Plain-language readout of what's actually configured right now, same
    /// idea as BackupScheduleConfig::summary in handlers/backups.rs.
    fn summary(&self) -> String {
        let when = match self.frequency.as_str() {
            "weekly" => format!(
                "every {} at {}",
                crate::handlers::backups::day_of_week_name(&self.day_of_week),
                self.check_time
            ),
            "monthly" => format!(
                "on day {} of the month at {}",
                self.day_of_month, self.check_time
            ),
            _ => format!("daily at {}", self.check_time),
        };
        let os = if self.auto_apply_os { "on" } else { "off" };
        let tailscale = if self.auto_apply_tailscale {
            "on"
        } else {
            "off"
        };
        let reboot = if self.auto_reboot { "on" } else { "off" };
        format!(
            "Checking for updates {when}. Auto-install OS updates: {os}. Auto-update Tailscale: {tailscale}. Auto-reboot if needed: {reboot}."
        )
    }
}

/// Everything the combined updates page needs to know about the OS/Tailscale
/// side - gathered here, rendered by `handlers::updates`.
pub(crate) struct OsUpdateData {
    pub(crate) watcher_busy: bool,
    pub(crate) os_update_count: Option<usize>,
    pub(crate) reboot_required: bool,
    pub(crate) tailscale_current: Option<String>,
    pub(crate) tailscale_upstream: Option<String>,
    pub(crate) tailscale_update_available: bool,
    pub(crate) schedule: ScheduleConfig,
    pub(crate) schedule_summary: String,
}

pub(crate) async fn gather() -> OsUpdateData {
    let busy = watcher_busy().await;

    // Skip calling apt/tailscale entirely while the watcher is busy - apt
    // would just block on the dpkg lock the in-progress action is holding,
    // and there's nothing new to report while it's still running anyway.
    let (os_update_count, tailscale_current, tailscale_upstream, tailscale_update_available) =
        if busy {
            (None, None, None, false)
        } else {
            let os_update_count = apt_upgradable_count().await;
            let tailscale = tailscale_versions().await;
            let (tailscale_current, tailscale_upstream, tailscale_update_available) =
                match tailscale {
                    Some((current, upstream)) => {
                        let available = !upstream.is_empty() && current != upstream;
                        (Some(current), Some(upstream), available)
                    }
                    None => (None, None, false),
                };
            (
                os_update_count,
                tailscale_current,
                tailscale_upstream,
                tailscale_update_available,
            )
        };

    let schedule = ScheduleConfig::load().await;
    let schedule_summary = schedule.summary();

    OsUpdateData {
        watcher_busy: busy,
        os_update_count,
        reboot_required: reboot_required(),
        tailscale_current,
        tailscale_upstream,
        tailscale_update_available,
        schedule,
        schedule_summary,
    }
}

async fn request_action(
    state: &AppState,
    admin: &crate::models::AdminUser,
    action: &str,
    event_type: &str,
    started_message: &str,
) -> Html<String> {
    let message = if tokio::fs::write(FLAG_FILE, action).await.is_ok() {
        security::record_security_event(&state.db, event_type, Some(&admin.username), None, None)
            .await;
        started_message.to_string()
    } else {
        "Couldn't write the request file - the update watcher may not be set up on this install."
            .to_string()
    };
    updates::render_page(state, Some(message)).await
}

pub async fn trigger_os_check(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    request_action(
        &state,
        &admin,
        "os_check",
        "os_check_triggered",
        "Refreshing the package list now. Refresh this page in a few seconds.",
    )
    .await
}

pub async fn trigger_os_upgrade(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    request_action(
        &state,
        &admin,
        "os_upgrade",
        "os_upgrade_triggered",
        "Installing OS updates now - this can take a long time on a Pi's first upgrade. \
         This page will show \"still working\" until it's done - feel free to check back later.",
    )
    .await
}

pub async fn trigger_tailscale_update(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    request_action(
        &state,
        &admin,
        "tailscale_update",
        "tailscale_update_triggered",
        "Updating Tailscale now. Refresh this page in a few seconds.",
    )
    .await
}

pub async fn trigger_reboot(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    request_action(
        &state,
        &admin,
        "reboot",
        "reboot_triggered",
        "Rebooting now - the app will be unreachable for about a minute.",
    )
    .await
}

#[derive(Deserialize)]
pub struct ScheduleForm {
    frequency: String,
    day_of_week: String,
    day_of_month: String,
    check_time: String,
    auto_apply_os: Option<String>,
    auto_apply_tailscale: Option<String>,
    auto_reboot: Option<String>,
}

const VALID_FREQUENCIES: [&str; 3] = ["daily", "weekly", "monthly"];

pub async fn save_schedule(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(form): Form<ScheduleForm>,
) -> impl IntoResponse {
    if !VALID_FREQUENCIES.contains(&form.frequency.as_str()) {
        return (
            http::StatusCode::BAD_REQUEST,
            updates::render_page(&state, Some("Invalid frequency.".to_string())).await,
        )
            .into_response();
    }
    let day_of_week: i32 = form.day_of_week.trim().parse().unwrap_or(0).clamp(0, 6);
    let day_of_month: i32 = form.day_of_month.trim().parse().unwrap_or(1).clamp(1, 28);
    let check_time = if form.check_time.trim().is_empty() {
        "03:00".to_string()
    } else {
        form.check_time.trim().to_string()
    };

    let config = ScheduleConfig {
        frequency: form.frequency,
        day_of_week: day_of_week.to_string(),
        day_of_month: day_of_month.to_string(),
        check_time,
        auto_apply_os: form.auto_apply_os.is_some(),
        auto_apply_tailscale: form.auto_apply_tailscale.is_some(),
        auto_reboot: form.auto_reboot.is_some(),
    };

    let message = if tokio::fs::write(SCHEDULE_FILE, config.to_file_contents())
        .await
        .is_ok()
    {
        security::record_security_event(
            &state.db,
            "update_schedule_changed",
            Some(&admin.username),
            None,
            None,
        )
        .await;
        "Schedule saved.".to_string()
    } else {
        "Couldn't save the schedule.".to_string()
    };

    updates::render_page(&state, Some(message))
        .await
        .into_response()
}
