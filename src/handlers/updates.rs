//! Software updates page. On a Box, the Box keeps the system, Tailscale and
//! this app up to date (signed updates with automatic rollback); this page
//! shows what the Box reports and asks it to check, install or restart,
//! through the Box API (crate::box_api). Off a Box there's nothing for this
//! app to update itself with, and the page says so.

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse};

use crate::AppState;
use crate::box_api::{self, Action, Status};

#[derive(Template)]
#[template(path = "updates.html")]
struct UpdatesTemplate {
    title: String,
    message: Option<String>,
    /// This app's own version
    app_version: String,
    on_box: bool,
    /// The Box's report, if it answered
    status: Option<Status>,
    /// Why the Box didn't answer
    box_error: Option<String>,
    /// When the Box last checked for updates, readable
    checked_at: Option<String>,
    /// Reload the page after this many seconds (something's in progress)
    refresh: Option<u32>,
}

/// "2026-10-24 14:03 UTC" from a Unix time
fn readable_time(unix: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(unix, 0).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
}

async fn render_page(message: Option<String>, refresh_after: Option<u32>) -> Html<String> {
    let on_box = box_api::socket().is_some();
    let (status, box_error) = if on_box {
        match box_api::status().await {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    let busy = status.as_ref().is_some_and(Status::busy);
    Html(
        UpdatesTemplate {
            title: "Software updates".to_string(),
            message,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            on_box,
            checked_at: status
                .as_ref()
                .and_then(|s| s.checked_at)
                .and_then(readable_time),
            refresh: refresh_after.or(busy.then_some(5)),
            status,
            box_error,
        }
        .render()
        .unwrap(),
    )
}

pub async fn show_updates_page(State(_state): State<AppState>) -> impl IntoResponse {
    render_page(None, None).await
}

async fn act(action: Action, refresh_after: Option<u32>) -> Html<String> {
    let message = box_api::start(action).await;
    render_page(Some(message), refresh_after).await
}

pub async fn check(State(_state): State<AppState>) -> impl IntoResponse {
    act(Action::Check, Some(3)).await
}

pub async fn install_system(State(_state): State<AppState>) -> impl IntoResponse {
    act(Action::InstallSystem, Some(3)).await
}

/// The Box stops this app to swap it, so the page waits a minute before reloading
pub async fn update_app(State(_state): State<AppState>) -> impl IntoResponse {
    act(Action::UpdateApp, Some(60)).await
}

pub async fn update_tailscale(State(_state): State<AppState>) -> impl IntoResponse {
    act(Action::UpdateTailscale, Some(3)).await
}

pub async fn restart_box(State(_state): State<AppState>) -> impl IntoResponse {
    act(Action::Restart, Some(90)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_well() {
        assert_eq!(
            readable_time(1792468800).as_deref(),
            Some("2026-10-20 04:00 UTC")
        );
    }

    #[test]
    fn renders_a_box_status() {
        let s: Status = serde_json::from_str(
            r#"{"os": {"version": "0.50", "latest": "0.51", "update_available": true,
                       "install": {"state": "idle"}},
                "app": {"version": "0.19.0", "latest": "0.20.0", "update_available": true,
                        "progress": {"state": "idle"}},
                "tailscale": {"version": "1.104.1", "dns_name": "box.tail1.ts.net", "progress": {"state": "idle"}},
                "checked_at": 1792468800,
                "auto_updates": {"enabled": true, "timezone": "Europe/Paris", "testing": true}}"#,
        )
        .unwrap();
        let page = UpdatesTemplate {
            title: "Software updates".into(),
            message: None,
            app_version: "0.19.0".into(),
            on_box: true,
            checked_at: readable_time(1792468800),
            refresh: None,
            status: Some(s),
            box_error: None,
        }
        .render()
        .unwrap();
        for expected in [
            "A new version is available: <strong>0.20.0</strong>",
            "action=\"/updates/app\"",
            "A system update is available: <strong>0.51</strong>",
            "action=\"/updates/system\"",
            "connected as <strong>box.tail1.ts.net</strong>",
            "Last checked 2026-10-20 04:00 UTC",
            "Europe/Paris time",
            "<strong>test versions</strong>",
        ] {
            assert!(page.contains(expected), "missing {expected:?}");
        }
    }

    #[tokio::test]
    async fn off_a_box_the_page_says_so() {
        if box_api::socket().is_some() {
            return; // running the tests on a Box
        }
        let Html(page) = render_page(None, None).await;
        assert!(page.contains("isn't running on a Box"), "{page}");
        assert!(page.contains(env!("CARGO_PKG_VERSION")));
        assert!(!page.contains("/updates/system"));
    }
}
