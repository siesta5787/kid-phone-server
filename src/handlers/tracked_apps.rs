//! Watches arbitrary GitHub repos' Releases for a new APK and pushes it to
//! devices - or, for apps with no public release feed (or where an admin
//! wants full manual control, including the launcher's own updates), lets
//! the admin upload an APK directly. Both source types feed the same
//! `latest_release_tag`/`latest_release_file_path` fields and the same
//! device-facing API (`handlers::device_api::tracked_app_updates`), so nothing
//! downstream of "there's a cached release ready to serve" needs to know or
//! care which source produced it.
//!
//! Every new release from either source goes through one review step first (`stage_release`):
//! the APK is read (`crate::apk`) and either published straight away or held as the app's one
//! pending release - for the parent's approval when something looks off (`review_reasons`), or
//! just until the app's hold period runs out. Devices only ever see the published release.

use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use crate::AppState;
use crate::apk::ApkInfo;
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

/// How a release is identified for "have we seen this one before" checks - the same
/// `"{tag}@{asset_id}"` composite `device_api::tracked_app_updates` sends to devices (see that
/// handler for why the asset id matters for rolling tags). Plain tag for manual uploads.
fn release_key(tag: &str, asset_id: Option<i64>) -> String {
    match asset_id {
        Some(id) => format!("{tag}@{id}"),
        None => tag.to_string(),
    }
}

/// A release already saved to disk, not yet published or held.
struct StagedRelease {
    tag: String,
    asset_id: Option<i64>,
    file_path: String,
    apk: Result<ApkInfo, String>,
}

async fn analyze_file(file_path: &str) -> Result<ApkInfo, String> {
    let path = std::path::PathBuf::from(file_path);
    tokio::task::spawn_blocking(move || crate::apk::analyze(&path))
        .await
        .map_err(|e| e.to_string())?
}

/// Why a new release needs the parent to look at it before it goes to any phone - empty when
/// it can go out on its own (after the app's hold period, if any). Compares against the live
/// release (`live`, when its APK could be read) and the pinned signing key (`pin`).
///
/// Never a dead end: every reason here is a hold, not a refusal, so a bug in reading some
/// unusual APK can't block an app's updates - the parent can always publish it anyway.
fn review_reasons(
    live: Option<&ApkInfo>,
    pin: Option<&str>,
    has_live_release: bool,
    candidate: &Result<ApkInfo, String>,
    from_admin_upload: bool,
) -> Vec<String> {
    let apk = match candidate {
        Ok(apk) => apk,
        Err(e) => {
            return vec![format!(
                "Couldn't read this APK ({e}), so its version, permissions and signing key are \
                 unknown. Only publish it if you're sure it's the right file."
            )];
        }
    };

    let mut reasons = Vec::new();
    // An admin upload is already a deliberate choice of this exact file.
    if !has_live_release && !from_admin_upload {
        reasons.push("New app. Check what it can access before it goes to any phone.".to_string());
    }
    if let Some(live) = live {
        if live.package_name != apk.package_name {
            reasons.push(format!(
                "This is a different app ({}) from the one phones have now ({}).",
                apk.package_name, live.package_name
            ));
        }
        if apk.version_code < live.version_code {
            reasons.push(format!(
                "Older version ({}) than the one phones have now ({}). Android won't install an \
                 older version over a newer one.",
                apk.version_label(),
                live.version_label()
            ));
        }
        // Compared per Android permission, not per label - an app going from approximate to
        // precise location is still worth a look even though both read "Location".
        let mut added: Vec<&str> = apk
            .permissions
            .iter()
            .filter(|p| !live.permissions.contains(p))
            .filter_map(|p| crate::apk::sensitive_permission_label(p))
            .collect();
        added.sort_unstable();
        added.dedup();
        if !added.is_empty() {
            reasons.push(format!("Asks for new access: {}.", added.join(", ")));
        }
    }
    match (&apk.cert_sha256, pin) {
        (None, _) => reasons.push("Isn't signed, so Android won't install it.".to_string()),
        (Some(cert), Some(pin)) if cert != pin => reasons.push(
            "Signed with a different key than earlier versions. That can mean it didn't come \
             from the app's real developer. Android will refuse to install it over the current \
             version unless the developer properly moved to a new key."
                .to_string(),
        ),
        _ => {}
    }
    // Recent Pixels (7 and later) can't run 32-bit-only apps at all.
    if !apk.native_abis.is_empty() && !apk.native_abis.iter().any(|a| a == "arm64-v8a") {
        reasons.push(format!(
            "Has no 64-bit ARM build (only {}), so it probably won't install on the phones.",
            apk.native_abis.join(", ")
        ));
    }
    reasons
}

const CLEAR_PENDING: &str = "pending_release_tag = NULL, pending_release_asset_id = NULL, \
     pending_release_file_path = NULL, pending_apk_json = NULL, pending_review_reasons = NULL, \
     pending_publish_after = NULL, pending_found_at = NULL";

/// Decides what happens to a release that was just downloaded or uploaded: published straight
/// away, or held as this app's one pending release (replacing any older pending one) - for the
/// parent's review if `review_reasons` found anything, otherwise just until the hold period ends.
async fn stage_release(
    state: &AppState,
    app: &TrackedApp,
    release: StagedRelease,
    from_admin_upload: bool,
) -> Result<(), String> {
    let reasons = review_reasons(
        app.latest_apk().as_ref(),
        app.signing_cert_sha256.as_deref(),
        app.latest_release_file_path.is_some(),
        &release.apk,
        from_admin_upload,
    );
    // The launcher enforces everything else on the phone, so its own fixes are never delayed.
    let hold_days = if app.is_launcher || from_admin_upload {
        0
    } else {
        app.hold_days.max(0)
    };

    if let Some(old) = &app.pending_release_file_path {
        if old != &release.file_path {
            tokio::fs::remove_file(old).await.ok();
        }
    }

    if reasons.is_empty() && hold_days == 0 {
        return publish(state, app, release).await;
    }

    let publish_after_modifier = reasons.is_empty().then(|| format!("+{hold_days} days"));
    sqlx::query(
        "UPDATE tracked_apps SET pending_release_tag = ?, pending_release_asset_id = ?, \
         pending_release_file_path = ?, pending_apk_json = ?, pending_review_reasons = ?, \
         pending_publish_after = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', ?) END, \
         pending_found_at = datetime('now') WHERE id = ?",
    )
    .bind(&release.tag)
    .bind(release.asset_id)
    .bind(&release.file_path)
    .bind(
        release
            .apk
            .as_ref()
            .ok()
            .and_then(|a| serde_json::to_string(a).ok()),
    )
    .bind(serde_json::to_string(&reasons).unwrap_or_else(|_| "[]".to_string()))
    .bind(&publish_after_modifier)
    .bind(&publish_after_modifier)
    .bind(app.id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Makes `release` the live one devices download, replacing (and deleting) the previous live
/// file and clearing any pending release. A release signed with a new key moves the pin to that
/// key - reaching here with one means the parent approved it.
async fn publish(state: &AppState, app: &TrackedApp, release: StagedRelease) -> Result<(), String> {
    let apk = release.apk.ok();
    sqlx::query(&format!(
        "UPDATE tracked_apps SET latest_release_tag = ?, latest_release_asset_id = ?, \
         latest_release_file_path = ?, latest_apk_json = ?, \
         signing_cert_sha256 = COALESCE(?, signing_cert_sha256), {CLEAR_PENDING} WHERE id = ?"
    ))
    .bind(&release.tag)
    .bind(release.asset_id)
    .bind(&release.file_path)
    .bind(apk.as_ref().and_then(|a| serde_json::to_string(a).ok()))
    .bind(apk.as_ref().and_then(|a| a.cert_sha256.clone()))
    .bind(app.id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(old) = &app.latest_release_file_path {
        if old != &release.file_path {
            tokio::fs::remove_file(old).await.ok();
        }
    }
    if let Some(apk) = &apk {
        fill_package_name(state, app, &apk.package_name).await;
    }

    // Nudge the phones that get this app to sync now rather than at their next poll - the same
    // data-free SSE nudge a policy save sends (see AppState::command_notify).
    let device_ids: Vec<i64> = if app.is_launcher {
        sqlx::query_scalar("SELECT id FROM devices")
            .fetch_all(&state.db)
            .await
    } else {
        sqlx::query_scalar("SELECT device_id FROM device_tracked_apps WHERE tracked_app_id = ?")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
    }
    .unwrap_or_default();
    for device_id in device_ids {
        let _ = state.command_notify.send(device_id);
    }

    Ok(())
}

/// The APK is the authority on its own package name, so a catalog app that doesn't have one on
/// file yet gets it from here - before any phone installs it, instead of waiting for
/// device_api::status's after-install guess - and is allowlisted on every device it's already
/// selected for, which toggle_tracked_app couldn't do at selection time without a package name.
async fn fill_package_name(state: &AppState, app: &TrackedApp, package_name: &str) {
    if !app.package_name.is_empty() || package_name.is_empty() {
        return;
    }
    sqlx::query("UPDATE tracked_apps SET package_name = ? WHERE id = ? AND package_name = ''")
        .bind(package_name)
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();
    let device_ids: Vec<i64> =
        sqlx::query_scalar("SELECT device_id FROM device_tracked_apps WHERE tracked_app_id = ?")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    for device_id in device_ids {
        crate::handlers::devices::add_to_allowlist(state, device_id, package_name).await;
    }
}

async fn publish_pending(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    let Some(file_path) = app.pending_release_file_path.clone() else {
        return Ok(());
    };
    let release = StagedRelease {
        tag: app.pending_release_tag.clone().unwrap_or_default(),
        asset_id: app.pending_release_asset_id,
        file_path,
        apk: app
            .pending_apk()
            .ok_or_else(|| "APK couldn't be read".to_string()),
    };
    publish(state, app, release).await
}

/// Publishes every pending release whose hold period has run out.
async fn publish_due_releases(state: &AppState) {
    let due = sqlx::query_as::<_, TrackedApp>(
        "SELECT * FROM tracked_apps WHERE pending_publish_after IS NOT NULL \
         AND pending_publish_after <= datetime('now')",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for app in due {
        if let Err(e) = publish_pending(state, &app).await {
            tracing::warn!("publishing held release of '{}' failed: {e}", app.name);
        }
    }
}

/// Reads the live release of any app that has one but hasn't been read yet - every app cached
/// before the review step existed. Pins the signing key from it, so those apps' next update is
/// checked against the key their phones already have rather than treated as brand new.
async fn backfill_release_info(state: &AppState) {
    let apps = sqlx::query_as::<_, TrackedApp>(
        "SELECT * FROM tracked_apps WHERE latest_release_file_path IS NOT NULL \
         AND latest_apk_json IS NULL",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for app in apps {
        let Some(path) = &app.latest_release_file_path else {
            continue;
        };
        let apk = match analyze_file(path).await {
            Ok(apk) => apk,
            Err(e) => {
                tracing::warn!("couldn't read cached APK of '{}': {e}", app.name);
                continue;
            }
        };
        sqlx::query(
            "UPDATE tracked_apps SET latest_apk_json = ?, \
             signing_cert_sha256 = COALESCE(signing_cert_sha256, ?) WHERE id = ?",
        )
        .bind(serde_json::to_string(&apk).ok())
        .bind(&apk.cert_sha256)
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();
        fill_package_name(state, &app, &apk.package_name).await;
    }
}

/// Checks one GitHub-sourced app's repo for a new release and, if it's one not seen before
/// (not the live one, the pending one, or one the parent rejected), downloads it and hands it to
/// `stage_release`. A no-op for manual-source apps - those only ever change via
/// `upload_tracked_app_release`. Used by both the scheduled loop and the admin's manual "Check
/// now" button, so they can never drift apart.
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

    // Compared as a (tag, asset id) pair, not just the tag - a rolling tag (e.g. this project's
    // own "pre-release") never changes name between pushes, but GitHub gives the replaced asset a
    // new id every time, so this still correctly detects a new build even when the tag doesn't.
    let key = release_key(&release.tag_name, Some(asset.id));
    let seen = [
        app.latest_release_tag
            .as_deref()
            .map(|t| release_key(t, app.latest_release_asset_id)),
        app.pending_release_tag
            .as_deref()
            .map(|t| release_key(t, app.pending_release_asset_id)),
        app.rejected_release_key.clone(),
    ];
    if seen.iter().flatten().any(|k| k == &key) {
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

    let apk = analyze_file(&file_path).await;
    let staged = StagedRelease {
        tag: release.tag_name.clone(),
        asset_id: Some(asset.id),
        file_path,
        apk,
    };
    stage_release(state, app, staged, false).await
}

/// Background task: checks every enabled tracked app on a fixed interval, after publishing any
/// held release whose wait is over. One app's failure (bad repo, rate-limited, network blip)
/// never blocks the others or crashes the loop - logged and retried next cycle. A no-op per
/// iteration for manual-source apps (`sync_one_app` returns early for them).
pub async fn run_scheduled_tracked_app_sync(state: AppState) {
    backfill_release_info(&state).await;

    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        interval.tick().await;

        publish_due_releases(&state).await;

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
    review_count: usize,
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
            review_count: tracked.iter().filter(|a| a.needs_review()).count(),
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
    let hold_days = if source_type == "github" {
        parse_hold_days(&field("hold_days"))
    } else {
        0
    };

    // package_name is never taken from admin input (see update_tracked_app's own doc comment) -
    // a brand-new app can't have one known yet anyway, since nothing's been installed to detect
    // it from. Always starts empty; device_api::status backfills it automatically.
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO tracked_apps (name, package_name, source_type, github_repo, asset_pattern, include_prereleases, hold_days) \
         VALUES (?, '', ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(field("name").trim())
    .bind(source_type)
    .bind(&github_repo)
    .bind(&asset_pattern)
    .bind(include_prereleases)
    .bind(hold_days)
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

    sqlx::query("UPDATE tracked_apps SET last_checked_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    let apk = analyze_file(&file_path).await;
    let staged = StagedRelease {
        tag: release_label,
        asset_id: None,
        file_path,
        apk,
    };
    let error = stage_release(&state, &app, staged, true).await.err();
    render_detail(&state, id, error).await
}

/// Publishes the pending release now - the parent's approval of a held release, or skipping
/// the rest of its hold period.
pub async fn publish_pending_release(
    State(state): State<AppState>,
    Path(id): Path<i64>,
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
    let error = publish_pending(&state, &app).await.err();
    render_detail(&state, id, error).await
}

/// Throws the pending release away and remembers it, so the hourly check doesn't download and
/// offer the same one again. The next new release upstream is offered as normal.
pub async fn reject_pending_release(
    State(state): State<AppState>,
    Path(id): Path<i64>,
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
    if let Some(path) = &app.pending_release_file_path {
        tokio::fs::remove_file(path).await.ok();
    }
    let rejected = app
        .pending_release_tag
        .as_deref()
        .map(|t| release_key(t, app.pending_release_asset_id));
    sqlx::query(&format!(
        "UPDATE tracked_apps SET rejected_release_key = COALESCE(?, rejected_release_key), \
         {CLEAR_PENDING} WHERE id = ?"
    ))
    .bind(rejected)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to(&format!("/apps/tracked/{id}"))
}

/// The longest hold period the form accepts - long enough for any real "wait and see", short
/// enough that a typo can't silently freeze an app's updates for a year.
const MAX_HOLD_DAYS: i64 = 30;

fn parse_hold_days(input: &str) -> i64 {
    input
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
        .clamp(0, MAX_HOLD_DAYS)
}

pub async fn set_hold_days(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let hold_days = parse_hold_days(form.get("hold_days").map(String::as_str).unwrap_or(""));
    sqlx::query("UPDATE tracked_apps SET hold_days = ? WHERE id = ?")
        .bind(hold_days)
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to(&format!("/apps/tracked/{id}"))
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

    let (github_repo, asset_pattern) = if app.source_type == "github" {
        let repo = normalize_github_repo(field("github_repo").trim());
        let pattern = field("asset_pattern").trim().to_string();
        (repo, (!pattern.is_empty()).then_some(pattern))
    } else {
        (app.github_repo.clone(), app.asset_pattern.clone())
    };

    // package_name is deliberately not editable here - it used to be free text ("Android package
    // name (optional)"), and a typo or a missed applicationIdSuffix (confirmed live: the browser
    // fork's real installed package is com.kidsmdm.browser.debug, not the com.kidsmdm.browser an
    // admin reasonably typed) silently broke the unified Apps list's matching with no obvious
    // cause. device_api::status now backfills it automatically the moment a device reports the
    // real package - see that handler's own doc comment - so there's no longer a reason for a
    // human to type it at all. forget_package_name below is the escape hatch if it's ever
    // detected wrong.
    sqlx::query(
        "UPDATE tracked_apps SET name = ?, github_repo = ?, asset_pattern = ? WHERE id = ?",
    )
    .bind(&name)
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

/// Resets a wrongly-detected package name back to empty, letting device_api::status's
/// auto-backfill try again from the next device that reports this app newly installed - the
/// escape hatch for update_tracked_app no longer accepting manual package name entry at all (see
/// that handler's own doc comment for why).
pub async fn forget_package_name(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    sqlx::query("UPDATE tracked_apps SET package_name = '' WHERE id = ?")
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

    for path in [
        &app.latest_release_file_path,
        &app.pending_release_file_path,
    ]
    .into_iter()
    .flatten()
    {
        tokio::fs::remove_file(path).await.ok();
    }

    sqlx::query("DELETE FROM tracked_apps WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/apps")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apk(version_code: i64, permissions: &[&str], cert: &str) -> ApkInfo {
        ApkInfo {
            package_name: "org.example.app".to_string(),
            version_code,
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
            cert_sha256: Some(cert.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn ordinary_update_needs_no_review() {
        let live = apk(1, &["android.permission.INTERNET"], "aa");
        let new = Ok(apk(2, &["android.permission.INTERNET"], "aa"));
        assert!(review_reasons(Some(&live), Some("aa"), true, &new, false).is_empty());
    }

    #[test]
    fn new_app_needs_review_unless_uploaded() {
        let new = Ok(apk(1, &[], "aa"));
        assert_eq!(review_reasons(None, None, false, &new, false).len(), 1);
        assert!(review_reasons(None, None, false, &new, true).is_empty());
    }

    #[test]
    fn flags_key_change_downgrade_and_new_permissions() {
        let live = apk(5, &["android.permission.ACCESS_COARSE_LOCATION"], "aa");
        let new = Ok(apk(
            4,
            &[
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.VIBRATE",
            ],
            "bb",
        ));
        let reasons = review_reasons(Some(&live), Some("aa"), true, &new, true);
        assert_eq!(reasons.len(), 3, "{reasons:?}");
        assert!(
            reasons
                .iter()
                .any(|r| r == "Asks for new access: Location.")
        );
    }

    #[test]
    fn flags_missing_arm64_and_unreadable_apk() {
        let mut new = apk(1, &[], "aa");
        new.native_abis = vec!["armeabi-v7a".to_string(), "x86".to_string()];
        let reasons = review_reasons(None, Some("aa"), true, &Ok(new), false);
        assert_eq!(reasons.len(), 1);

        let unreadable = Err("not a valid APK/zip file".to_string());
        assert_eq!(
            review_reasons(None, Some("aa"), true, &unreadable, false).len(),
            1
        );
    }

    #[test]
    fn hold_days_are_clamped() {
        assert_eq!(parse_hold_days("2"), 2);
        assert_eq!(parse_hold_days("-3"), 0);
        assert_eq!(parse_hold_days("400"), MAX_HOLD_DAYS);
        assert_eq!(parse_hold_days("soon"), 0);
    }
}
