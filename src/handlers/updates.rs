//! Combined admin view for update-related actions: the app's own version
//! and self-update controls alongside the Pi's OS package updates and
//! Tailscale. "Is everything up to date" is one job regardless of which
//! layer it's checking, so this is one page even though the two underlying
//! schedules (app auto-update vs. OS/Tailscale auto-update) stay
//! independently configurable - each POST route from handlers::system_update
//! / handlers::system_maintenance hands off to `render_page` below.

use askama::Template;
use axum::response::{Html, IntoResponse};

use crate::AppState;
use crate::handlers::{system_maintenance, system_update};

#[derive(Template)]
#[template(path = "updates.html")]
struct UpdatesTemplate {
    title: String,
    message: Option<String>,
    app: system_update::AppUpdateData,
    os: system_maintenance::OsUpdateData,
}

pub(crate) async fn render_page(_state: &AppState, message: Option<String>) -> Html<String> {
    Html(
        UpdatesTemplate {
            title: "Software updates".to_string(),
            message,
            app: system_update::gather().await,
            os: system_maintenance::gather().await,
        }
        .render()
        .unwrap(),
    )
}

pub async fn show_updates_page(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    render_page(&state, None).await
}
