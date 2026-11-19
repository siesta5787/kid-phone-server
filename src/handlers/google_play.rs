//! Admin pages for Google Play as an app source: Settings → Google Play (sign the server in with a
//! spare Google account - from a phone, or by pasting a sign-in code), and Apps → "Add from Google
//! Play" (look an app up by link or package name, then add it to the catalog). See src/play.rs.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;

use crate::AppState;
use crate::models::now_epoch_ms;
use crate::play::{self, PlayApp, SIGNIN_WINDOW_MINUTES};
use crate::security::{self, CurrentAdmin};

#[derive(Template)]
#[template(path = "google_play_settings.html")]
struct GooglePlaySettingsTemplate {
    title: String,
    signed_in: bool,
    email: String,
    signed_in_at: String,
    last_ok_at: String,
    last_error: String,
    window_open: bool,
    window_email: String,
    window_minutes_left: i64,
    window_length: i64,
    message: String,
    error: String,
}

async fn render_settings(state: &AppState, message: String, error: String) -> Html<String> {
    let settings = play::settings(state).await;
    let now_ms = now_epoch_ms();
    let window_open = settings.signin_window_open(now_ms);
    let window_minutes_left = settings
        .signin_window_until_ms
        .map(|until| ((until - now_ms).max(0) + 59_999) / 60_000)
        .unwrap_or(0);
    Html(
        GooglePlaySettingsTemplate {
            title: "Google Play".to_string(),
            signed_in: settings.signed_in(),
            email: settings.email.clone().unwrap_or_default(),
            signed_in_at: settings.signed_in_at.clone().unwrap_or_default(),
            last_ok_at: settings.last_ok_at.clone().unwrap_or_default(),
            last_error: settings.last_error.clone().unwrap_or_default(),
            window_open,
            window_email: settings.signin_email.clone().unwrap_or_default(),
            window_minutes_left,
            window_length: SIGNIN_WINDOW_MINUTES,
            message,
            error,
        }
        .render()
        .unwrap(),
    )
}

pub async fn show_settings(State(state): State<AppState>) -> impl IntoResponse {
    render_settings(&state, String::new(), String::new()).await
}

#[derive(Deserialize)]
pub struct EmailForm {
    email: String,
}

/// Opens the "Sign in using a phone" window: for the next few minutes, a device may send the
/// server a sign-in code from the launcher's "Sign in to Google Play" screen
/// (`device_api::play_signin`). Nothing else ever lets a device change the server's account.
pub async fn start_phone_signin(
    State(state): State<AppState>,
    Form(form): Form<EmailForm>,
) -> impl IntoResponse {
    let email = form.email.trim();
    if email.is_empty() || !email.contains('@') {
        return render_settings(
            &state,
            String::new(),
            "Type the spare Google account's email address first.".to_string(),
        )
        .await
        .into_response();
    }
    sqlx::query(
        "UPDATE play_settings SET signin_window_until_ms = ?, signin_email = ? WHERE id = 1",
    )
    .bind(now_epoch_ms() + SIGNIN_WINDOW_MINUTES * 60_000)
    .bind(email)
    .execute(&state.db)
    .await
    .ok();
    Redirect::to("/settings/google-play").into_response()
}

pub async fn cancel_phone_signin(State(state): State<AppState>) -> impl IntoResponse {
    sqlx::query(
        "UPDATE play_settings SET signin_window_until_ms = NULL, signin_email = NULL WHERE id = 1",
    )
    .execute(&state.db)
    .await
    .ok();
    Redirect::to("/settings/google-play")
}

#[derive(Deserialize)]
pub struct ManualSigninForm {
    email: String,
    oauth_token: String,
}

/// The fallback when signing in from a phone isn't possible: the parent copies the `oauth_token`
/// cookie from Google's sign-in page in their own browser (instructions on the page).
pub async fn manual_signin(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(form): Form<ManualSigninForm>,
) -> impl IntoResponse {
    match play::sign_in(&state, &form.email, &form.oauth_token).await {
        Ok(()) => {
            security::record_security_event(
                &state.db,
                "google_play_signed_in",
                Some(&admin.username),
                None,
                Some(&format!("{} (manual code)", form.email.trim())),
            )
            .await;
            render_settings(&state, "Signed in.".to_string(), String::new()).await
        }
        Err(e) => render_settings(&state, String::new(), e).await,
    }
}

pub async fn test_connection(State(state): State<AppState>) -> impl IntoResponse {
    match play::test(&state).await {
        Ok(()) => {
            render_settings(&state, "Google Play is working.".to_string(), String::new()).await
        }
        Err(e) => render_settings(&state, String::new(), e).await,
    }
}

pub async fn sign_out(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    play::sign_out(&state).await;
    security::record_security_event(
        &state.db,
        "google_play_signed_out",
        Some(&admin.username),
        None,
        None,
    )
    .await;
    Redirect::to("/settings/google-play")
}

#[derive(Template)]
#[template(path = "play_app_add.html")]
struct PlayAppAddTemplate {
    title: String,
    signed_in: bool,
    query: String,
    found: Option<PlayApp>,
    /// Human-readable download size, e.g. "48 MB" - empty if Play didn't say.
    size_label: String,
    /// Catalog id if this package is already in the catalog.
    existing_id: Option<i64>,
    error: String,
}

#[derive(Deserialize)]
pub struct LookupQuery {
    #[serde(default)]
    q: String,
}

/// Apps → "Add from Google Play": paste a Play Store link or a package name, see a preview, add.
pub async fn add_form(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> impl IntoResponse {
    let signed_in = play::settings(&state).await.signed_in();
    let mut template = PlayAppAddTemplate {
        title: "Add from Google Play".to_string(),
        signed_in,
        query: query.q.trim().to_string(),
        found: None,
        size_label: String::new(),
        existing_id: None,
        error: String::new(),
    };
    if signed_in && !template.query.is_empty() {
        match play::parse_package(&template.query) {
            None => {
                template.error = "That doesn't look like a Google Play link or package name. \
                                  Open the app on play.google.com and copy the address."
                    .to_string()
            }
            Some(package) => {
                template.existing_id = sqlx::query_scalar(
                    "SELECT id FROM tracked_apps WHERE package_name = ? LIMIT 1",
                )
                .bind(&package)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
                match play::lookup(&state, &package).await {
                    Ok(app) => {
                        template.size_label = app
                            .download_size
                            .map(|b| format!("{} MB", (b + 999_999) / 1_000_000))
                            .unwrap_or_default();
                        template.found = Some(app);
                    }
                    Err(e) => template.error = e,
                }
            }
        }
    }
    Html(template.render().unwrap())
}

#[derive(Deserialize)]
pub struct AddPlayAppForm {
    package_name: String,
    name: String,
}

/// Adds a Play app to the catalog and starts its first download in the background - the page it
/// redirects to shows progress via "Last checked" / any error. Pushing it to a device is the
/// usual per-device "Apps" checkbox, which also allows it.
pub async fn add_app(
    State(state): State<AppState>,
    Form(form): Form<AddPlayAppForm>,
) -> impl IntoResponse {
    let Some(package) = play::parse_package(&form.package_name) else {
        return Redirect::to("/apps/play/new");
    };
    if let Some(id) =
        sqlx::query_scalar::<_, i64>("SELECT id FROM tracked_apps WHERE package_name = ? LIMIT 1")
            .bind(&package)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
    {
        return Redirect::to(&format!("/apps/tracked/{id}"));
    }
    let name = match form.name.trim() {
        "" => package.clone(),
        n => n.to_string(),
    };
    // hold_days 0: Play updates have already been through Google's own review, and a parent who
    // wants a buffer can still set one on the app's page.
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO tracked_apps (name, package_name, source_type, github_repo, hold_days) \
         VALUES (?, ?, 'play', '', 0) RETURNING id",
    )
    .bind(&name)
    .bind(&package)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(id) = id else {
        return Redirect::to("/apps/play/new");
    };

    crate::handlers::tracked_apps::start_check(&state, id);
    Redirect::to(&format!("/apps/tracked/{id}"))
}
