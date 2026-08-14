//! The Settings tab - a static card list linking out to the existing
//! Backups/Software updates/Security log/Account pages, mirroring the
//! admin-console pattern from the user's Board Game Tracker app. No DB
//! queries of its own, just navigation.

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use std::collections::HashMap;

use crate::AppState;
use crate::models::ProvisioningSettings;

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

#[derive(Template)]
#[template(path = "provisioning_settings.html")]
struct ProvisioningSettingsTemplate {
    title: String,
    settings: ProvisioningSettings,
}

/// Single server_url/tailscale_auth_key pair, embedded verbatim into every device's QR
/// provisioning payload (`handlers::provisioning`) and read by the launcher's own in-app QR
/// scanner for devices where Android's native zero-touch flow doesn't run (e.g. GrapheneOS) -
/// see that handler's own doc comment for why these are global rather than per-device.
pub async fn provisioning_settings_form(State(state): State<AppState>) -> impl IntoResponse {
    let settings = sqlx::query_as::<_, ProvisioningSettings>(
        "SELECT * FROM provisioning_settings WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

    Html(
        ProvisioningSettingsTemplate {
            title: "Provisioning".to_string(),
            settings,
        }
        .render()
        .unwrap(),
    )
}

pub async fn update_provisioning_settings(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let server_url = form.get("server_url").map(|s| s.trim()).unwrap_or("");
    let tailscale_auth_key = form
        .get("tailscale_auth_key")
        .map(|s| s.trim())
        .unwrap_or("");

    sqlx::query(
        "UPDATE provisioning_settings SET server_url = ?, tailscale_auth_key = ?, \
         updated_at = datetime('now') WHERE id = 1",
    )
    .bind(server_url)
    .bind(tailscale_auth_key)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to("/settings/provisioning")
}
