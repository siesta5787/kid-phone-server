//! Watches arbitrary GitHub repos' Releases for a new APK and pushes it to
//! devices - or, for apps with no public release feed (or where an admin
//! wants full manual control, including the launcher's own updates), lets
//! the admin upload an APK directly. Both source types feed the same
//! `latest_release_tag`/`latest_release_file_path` fields and the same
//! device-facing API (`handlers::device_api::tracked_app_updates`), so nothing
//! downstream of "there's a cached release ready to serve" needs to know or
//! care which source produced it.

use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use crate::AppState;
use crate::models::TrackedApp;
use crate::security::{CurrentAdmin, generate_device_token};

const TRACKED_APPS_DIR: &str = "data/tracked_apps";

#[derive(Deserialize)]
struct GithubAsset {
    id: i64,
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    assets: Vec<GithubAsset>,
}

/// Hits the Releases *list* endpoint rather than `/releases/latest` - the
/// latter only ever returns the newest non-prerelease, non-draft release,
/// which would never find anything for a repo (like this project's own
/// kids-launcher-mdm) that only ever publishes to a rolling prerelease tag.
/// The list is already newest-first, so after filtering the first match is
/// the one we want - same approach Obtainium uses for this exact problem.
async fn fetch_latest_release(
    github_repo: &str,
    include_prereleases: bool,
) -> Result<GithubRelease, String> {
    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, github.com)")
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("https://api.github.com/repos/{github_repo}/releases");
    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub API returned {}", response.status()));
    }
    let releases: Vec<GithubRelease> = response.json().await.map_err(|e| e.to_string())?;

    releases
        .into_iter()
        .find(|r| !r.draft && (include_prereleases || !r.prerelease))
        .ok_or_else(|| "no matching release found".to_string())
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

/// Checks one GitHub-sourced app's repo for a new release and, if the
/// release+asset identity differs from what's cached, downloads the
/// matching asset and replaces the previously-cached file. A no-op for
/// manual-source apps - those only ever change via `upload_tracked_app_release`.
/// Used by both the scheduled loop and the admin's manual "Check now"
/// button, so they can never drift apart.
async fn sync_one_app(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    if app.source_type != "github" {
        return Ok(());
    }

    let release = fetch_latest_release(&app.github_repo, app.include_prereleases).await?;

    sqlx::query("UPDATE tracked_apps SET last_checked_at = datetime('now') WHERE id = ?")
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();

    let asset = pick_asset(&release, app.asset_pattern.as_deref())
        .ok_or_else(|| "no matching .apk asset in the latest release".to_string())?;

    // Compared as a (tag, asset id) pair, not just the tag - a rolling tag
    // (e.g. this project's own "pre-release") never changes name between
    // pushes, but GitHub gives the replaced asset a new id every time, so
    // this still correctly detects a new build even when the tag doesn't.
    if Some(&release.tag_name) == app.latest_release_tag.as_ref()
        && Some(asset.id) == app.latest_release_asset_id
    {
        return Ok(());
    }

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
    let file_path = format!("{app_dir}/{}-{}.apk", release.tag_name, asset.id);
    tokio::fs::write(&file_path, &bytes)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(old_path) = &app.latest_release_file_path {
        if old_path != &file_path {
            tokio::fs::remove_file(old_path).await.ok();
        }
    }

    sqlx::query(
        "UPDATE tracked_apps SET latest_release_tag = ?, latest_release_asset_id = ?, \
         latest_release_file_path = ? WHERE id = ?",
    )
    .bind(&release.tag_name)
    .bind(asset.id)
    .bind(&file_path)
    .bind(app.id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Background task: checks every enabled tracked app on a fixed interval.
/// One app's failure (bad repo, rate-limited, network blip) never blocks the
/// others or crashes the loop - logged and retried next cycle. A no-op per
/// iteration for manual-source apps (`sync_one_app` returns early for them).
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

/// A random on-disk filename component, not anything browser-supplied -
/// avoids trusting client input for a filesystem path. Reuses the device-
/// token generator purely for its randomness, not as a credential here.
fn random_label() -> String {
    generate_device_token()
}

#[derive(Template)]
#[template(path = "apps_list.html")]
struct AppsListTemplate {
    title: String,
    tracked: Vec<TrackedApp>,
}

/// The Apps tab - one card per tracked app, whatever its source (including
/// the launcher itself, which is just another GitHub-sourced row here).
pub async fn list_apps(State(state): State<AppState>) -> impl IntoResponse {
    let tracked = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    Html(
        AppsListTemplate {
            title: "Apps".to_string(),
            tracked,
        }
        .render()
        .unwrap(),
    )
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

pub async fn create_tracked_app(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentAdmin>,
    Form(fields): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();
    let source_type = if field("source_type") == "manual" {
        "manual"
    } else {
        "github"
    };

    let github_repo = if source_type == "github" {
        field("github_repo").trim().to_string()
    } else {
        String::new()
    };
    let asset_pattern = if source_type == "github" {
        let trimmed = field("asset_pattern").trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    } else {
        None
    };
    let include_prereleases = source_type == "github" && fields.contains_key("include_prereleases");

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO tracked_apps (name, package_name, source_type, github_repo, asset_pattern, include_prereleases) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(field("name").trim())
    .bind(field("package_name").trim())
    .bind(source_type)
    .bind(&github_repo)
    .bind(&asset_pattern)
    .bind(include_prereleases)
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

/// Manual-source apps' only path to a new release: the admin types a label
/// (there's no GitHub tag to borrow one from) and uploads an APK directly,
/// same shape as the old launcher_releases upload flow this replaces.
pub async fn upload_tracked_app_release(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(app) = app else {
        return (axum::http::StatusCode::NOT_FOUND, "App not found").into_response();
    };

    let mut release_label: Option<String> = None;
    let mut apk_bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "release_label" => {
                release_label = field.text().await.ok().map(|s| s.trim().to_string());
            }
            "apk" => {
                apk_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
        }
    }

    let (Some(release_label), Some(apk_bytes)) = (release_label, apk_bytes) else {
        return render_detail(
            &state,
            id,
            Some("Fill in a release label and choose a file.".to_string()),
        )
        .await;
    };

    if release_label.is_empty() || apk_bytes.is_empty() {
        return render_detail(
            &state,
            id,
            Some("Fill in a release label and choose a file.".to_string()),
        )
        .await;
    }

    let app_dir = format!("{TRACKED_APPS_DIR}/{id}");
    if tokio::fs::create_dir_all(&app_dir).await.is_err() {
        return render_detail(
            &state,
            id,
            Some("Failed to save the uploaded file.".to_string()),
        )
        .await;
    }
    let file_path = format!("{app_dir}/{}.apk", random_label());
    if tokio::fs::write(&file_path, &apk_bytes).await.is_err() {
        return render_detail(
            &state,
            id,
            Some("Failed to save the uploaded file.".to_string()),
        )
        .await;
    }

    if let Some(old_path) = &app.latest_release_file_path {
        if old_path != &file_path {
            tokio::fs::remove_file(old_path).await.ok();
        }
    }

    sqlx::query(
        "UPDATE tracked_apps SET latest_release_tag = ?, latest_release_asset_id = NULL, \
         latest_release_file_path = ?, last_checked_at = datetime('now') WHERE id = ?",
    )
    .bind(&release_label)
    .bind(&file_path)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    render_detail(&state, id, None).await
}

pub async fn set_enabled(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
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

pub async fn set_include_prereleases(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let include_prereleases = form.contains_key("include_prereleases");
    sqlx::query("UPDATE tracked_apps SET include_prereleases = ? WHERE id = ?")
        .bind(include_prereleases)
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
