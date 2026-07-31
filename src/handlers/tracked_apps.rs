//! Watches arbitrary GitHub repos' Releases for a new APK and pushes it to
//! devices the same way the launcher already self-updates - a generalized,
//! Obtainium-style version of `handlers::releases`. Mirrors
//! `handlers::system_update`'s existing self-update-check pattern (same
//! `reqwest` client construction, same `api.github.com/repos/.../releases/
//! latest` call), just parameterized by repo and reading `assets[]` instead
//! of only `tag_name`.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;
use std::time::Duration;

use crate::AppState;
use crate::models::TrackedApp;
use crate::security::CurrentAdmin;

const TRACKED_APPS_DIR: &str = "data/tracked_apps";

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

async fn fetch_latest_release(github_repo: &str) -> Result<GithubRelease, String> {
    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, github.com)")
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("https://api.github.com/repos/{github_repo}/releases/latest");
    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub API returned {}", response.status()));
    }
    response
        .json::<GithubRelease>()
        .await
        .map_err(|e| e.to_string())
}

fn pick_asset<'a>(
    release: &'a GithubRelease,
    asset_pattern: Option<&str>,
) -> Option<&'a GithubAsset> {
    release.assets.iter().find(|a| match asset_pattern {
        Some(pattern) if !pattern.is_empty() => a.name.contains(pattern),
        _ => a.name.ends_with(".apk"),
    })
}

/// Checks one app's GitHub repo for a new release and, if the tag differs
/// from what's cached, downloads the matching asset and replaces the
/// previously-cached file. Used by both the scheduled loop and the admin's
/// manual "Check now" button, so they can never drift apart.
async fn sync_one_app(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    let release = fetch_latest_release(&app.github_repo).await?;

    sqlx::query("UPDATE tracked_apps SET last_checked_at = datetime('now') WHERE id = ?")
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();

    if Some(&release.tag_name) == app.latest_release_tag.as_ref() {
        return Ok(());
    }

    let asset = pick_asset(&release, app.asset_pattern.as_deref())
        .ok_or_else(|| "no matching .apk asset in the latest release".to_string())?;

    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, github.com)")
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;

    let app_dir = format!("{TRACKED_APPS_DIR}/{}", app.id);
    tokio::fs::create_dir_all(&app_dir)
        .await
        .map_err(|e| e.to_string())?;
    let file_path = format!("{app_dir}/{}.apk", release.tag_name);
    tokio::fs::write(&file_path, &bytes)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(old_path) = &app.latest_release_file_path {
        if old_path != &file_path {
            tokio::fs::remove_file(old_path).await.ok();
        }
    }

    sqlx::query(
        "UPDATE tracked_apps SET latest_release_tag = ?, latest_release_file_path = ? WHERE id = ?",
    )
    .bind(&release.tag_name)
    .bind(&file_path)
    .bind(app.id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Background task: checks every enabled tracked app on a fixed interval.
/// One app's failure (bad repo, rate-limited, network blip) never blocks the
/// others or crashes the loop - logged and retried next cycle.
pub async fn run_scheduled_tracked_app_sync(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        interval.tick().await;

        let apps = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE enabled = 1")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

        for app in apps {
            if let Err(e) = sync_one_app(&state, &app).await {
                tracing::warn!("tracked app '{}' sync failed: {e}", app.name);
            }
        }
    }
}

#[derive(Template)]
#[template(path = "tracked_app_add.html")]
struct TrackedAppAddTemplate {
    title: String,
}

pub async fn new_tracked_app_form() -> impl IntoResponse {
    Html(
        TrackedAppAddTemplate {
            title: "Add an app".to_string(),
        }
        .render()
        .unwrap(),
    )
}

#[derive(Deserialize)]
pub struct CreateTrackedAppForm {
    name: String,
    package_name: String,
    github_repo: String,
    asset_pattern: String,
}

pub async fn create_tracked_app(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(form): Form<CreateTrackedAppForm>,
) -> impl IntoResponse {
    let asset_pattern =
        (!form.asset_pattern.trim().is_empty()).then(|| form.asset_pattern.trim().to_string());

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO tracked_apps (name, package_name, github_repo, asset_pattern) \
         VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(form.name.trim())
    .bind(form.package_name.trim())
    .bind(form.github_repo.trim())
    .bind(&asset_pattern)
    .fetch_one(&state.db)
    .await
    .expect("failed to create tracked app");

    Redirect::to(&format!("/apps/tracked/{id}"))
}

#[derive(Template)]
#[template(path = "tracked_app_detail.html")]
struct TrackedAppDetailTemplate {
    title: String,
    app: TrackedApp,
    error: Option<String>,
}

pub async fn view_tracked_app(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    render_detail(&state, id, None).await
}

async fn render_detail(
    state: &AppState,
    id: i64,
    error: Option<String>,
) -> axum::response::Response {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(app) = app else {
        return (axum::http::StatusCode::NOT_FOUND, "App not found").into_response();
    };

    Html(
        TrackedAppDetailTemplate {
            title: app.name.clone(),
            app,
            error,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

pub async fn check_now(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(app) = app else {
        return (axum::http::StatusCode::NOT_FOUND, "App not found").into_response();
    };

    let error = sync_one_app(&state, &app).await.err();
    render_detail(&state, id, error).await
}

pub async fn set_enabled(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let enabled = form.contains_key("enabled");
    sqlx::query("UPDATE tracked_apps SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to(&format!("/apps/tracked/{id}"))
}

pub async fn delete_tracked_app(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Ok(Some(app)) =
        sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
    {
        if let Some(path) = &app.latest_release_file_path {
            tokio::fs::remove_file(path).await.ok();
        }
    }

    sqlx::query("DELETE FROM tracked_apps WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/apps")
}
