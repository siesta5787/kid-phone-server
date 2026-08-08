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

/// Accepts a plain "owner/repo" string, or a pasted GitHub URL in any of its common forms - full
/// URL, with or without protocol/www, pointing at the repo root or its Releases page, with or
/// without a trailing slash or ".git" - and normalizes all of them down to "owner/repo" (what
/// `fetch_latest_release` actually needs to build the API URL). Confirmed live this needed to be
/// forgiving: an admin copying a URL out of the browser address bar naturally includes
/// "https://github.com/" and is often sitting on the repo's "/releases" page specifically, and a
/// strict "owner/repo"-only parser rejected all of that with no useful error.
fn normalize_github_repo(input: &str) -> String {
    let mut s = input.trim();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
        }
    }
    for host in ["www.github.com/", "github.com/"] {
        if let Some(rest) = s.strip_prefix(host) {
            s = rest;
        }
    }
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    match (parts.first(), parts.get(1)) {
        (Some(owner), Some(repo)) => {
            format!("{owner}/{}", repo.strip_suffix(".git").unwrap_or(repo))
        }
        _ => s.trim_end_matches('/').to_string(),
    }
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
        normalize_github_repo(field("github_repo").trim())
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

/// Lets an admin fix any of a tracked app's identifying details after creation - there was
/// previously no way to do this short of deleting and re-adding the row (losing its cached
/// release/check history). `source_type` itself isn't editable here - switching between
/// GitHub-tracked and manually-uploaded changes the whole update-fetching model, not just a field.
pub async fn update_tracked_app(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(fields): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(app) = app else {
        return Redirect::to("/apps");
    };

    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();
    let name = field("name").trim().to_string();
    let package_name = field("package_name").trim().to_string();

    let (github_repo, asset_pattern) = if app.source_type == "github" {
        let repo = normalize_github_repo(field("github_repo").trim());
        let pattern = field("asset_pattern").trim().to_string();
        (repo, (!pattern.is_empty()).then_some(pattern))
    } else {
        (app.github_repo.clone(), app.asset_pattern.clone())
    };

    sqlx::query(
        "UPDATE tracked_apps SET name = ?, package_name = ?, github_repo = ?, asset_pattern = ? \
         WHERE id = ?",
    )
    .bind(&name)
    .bind(&package_name)
    .bind(&github_repo)
    .bind(&asset_pattern)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to(&format!("/apps/tracked/{id}"))
}

/// Explicit admin-facing way to mark/unmark the one row that is the launcher itself - see
/// migrations/0013_device_tracked_apps.sql's doc comment for what this flag does. Exists because
/// the migration's one-time best-effort `UPDATE ... WHERE package_name = 'com.kidslauncher.mdm'`
/// missed the real row on a live install whose actual package name was the debug-suffixed
/// `com.kidslauncher.mdm.debug` (every build shipped so far has been the debug variant - see
/// kids-launcher-mdm's `app/build.gradle.kts`) - a plain heuristic match on package name is too
/// fragile to be the only way to set this, so there needed to be a direct way to fix it without a
/// new migration or shell access to the Pi.
pub async fn set_is_launcher(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let is_launcher = form.contains_key("is_launcher");
    sqlx::query("UPDATE tracked_apps SET is_launcher = ? WHERE id = ?")
        .bind(is_launcher)
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to(&format!("/apps/tracked/{id}"))
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
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    // Enforced here, not just hidden in tracked_app_detail.html - the launcher is the app that
    // enforces every other restriction on the phone, so there's no safe way to let an admin
    // remove it from the push list. The template already doesn't render a delete control for it;
    // this is defense-in-depth against a direct POST.
    let Some(app) = app else {
        return Redirect::to("/apps");
    };
    if app.is_launcher {
        return Redirect::to(&format!("/apps/tracked/{id}"));
    }

    if let Some(path) = &app.latest_release_file_path {
        tokio::fs::remove_file(path).await.ok();
    }

    sqlx::query("DELETE FROM tracked_apps WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/apps")
}
