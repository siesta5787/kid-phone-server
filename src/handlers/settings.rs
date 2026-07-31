//! The Settings tab - a static card list linking out to the existing
//! Backups/Software updates/Security log/Account pages, mirroring the
//! admin-console pattern from the user's Board Game Tracker app. No DB
//! queries of its own, just navigation.

use askama::Template;
use axum::response::{Html, IntoResponse};

#[derive(Template)]
#[template(path = "settings_hub.html")]
struct SettingsHubTemplate {
    title: String,
}

pub async fn settings_hub() -> impl IntoResponse {
    Html(
        SettingsHubTemplate {
            title: "Settings".to_string(),
        }
        .render()
        .unwrap(),
    )
}
