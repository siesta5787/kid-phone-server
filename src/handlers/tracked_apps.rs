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
use crate::models::{ReleaseSplit, TrackedApp};
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
    /// The base APK - the only file for GitHub/manual releases.
    file_path: String,
    /// Split APKs installed together with the base one (Google Play) - see
    /// migrations/0026_split_apks.sql. `apk` describes the base APK only.
    splits: Vec<ReleaseSplit>,
    apk: Result<ApkInfo, String>,
}

fn splits_json(splits: &[ReleaseSplit]) -> Option<String> {
    (!splits.is_empty())
        .then(|| serde_json::to_string(splits).ok())
        .flatten()
}

/// Deletes a release's files: the base APK, its splits, and - for a Google Play release kept in
/// its own `play-*` folder - that folder once it's empty.
async fn remove_release_files(base: &str, splits: &[ReleaseSplit]) {
    tokio::fs::remove_file(base).await.ok();
    for split in splits {
        tokio::fs::remove_file(&split.path).await.ok();
    }
    let parent = std::path::Path::new(base).parent();
    if let Some(dir) = parent.filter(|d| {
        d.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("play-"))
    }) {
        tokio::fs::remove_dir(dir).await.ok();
    }
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
     pending_publish_after = NULL, pending_found_at = NULL, pending_release_splits_json = NULL";

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
            remove_release_files(old, &app.pending_splits()).await;
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
         pending_found_at = datetime('now'), pending_release_splits_json = ? WHERE id = ?",
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
    .bind(splits_json(&release.splits))
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
         latest_release_file_path = ?, latest_apk_json = ?, latest_release_splits_json = ?, \
         signing_cert_sha256 = COALESCE(?, signing_cert_sha256), {CLEAR_PENDING} WHERE id = ?"
    ))
    .bind(&release.tag)
    .bind(release.asset_id)
    .bind(&release.file_path)
    .bind(apk.as_ref().and_then(|a| serde_json::to_string(a).ok()))
    .bind(splits_json(&release.splits))
    .bind(apk.as_ref().and_then(|a| a.cert_sha256.clone()))
    .bind(app.id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(old) = &app.latest_release_file_path {
        if old != &release.file_path {
            remove_release_files(old, &app.latest_splits()).await;
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
        splits: app.pending_splits(),
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
    // Never two checks of the same app at once (hourly loop + "Check now", or a double click):
    // they'd download into the same folder. The later one just skips.
    let Some(_guard) = begin_check(app.id) else {
        return Ok(());
    };
    run_check(state, app).await
}

/// The check itself, for a caller already holding the app's [CheckGuard].
async fn run_check(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    let result = match app.source_type.as_str() {
        "github" => sync_github_app(state, app).await,
        "play" => sync_play_app(state, app).await,
        _ => Ok(()),
    };
    sqlx::query("UPDATE tracked_apps SET last_check_error = ? WHERE id = ?")
        .bind(result.as_ref().err())
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();
    result
}

async fn sync_github_app(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    set_progress(app.id, "Checking GitHub for a new release…", None);
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

    let app_dir = format!("{TRACKED_APPS_DIR}/{}", app.id);
    tokio::fs::create_dir_all(&app_dir)
        .await
        .map_err(|e| e.to_string())?;
    let file_path = format!("{app_dir}/{}-{}.apk", release.tag_name, asset.id);
    // Streamed to disk (not held in memory whole), with progress for the app page.
    download_to_file(
        &asset.browser_download_url,
        &file_path,
        app.id,
        "Downloading…",
    )
    .await?;

    set_progress(app.id, "Checking the download…", None);
    let apk = analyze_file(&file_path).await;
    let staged = StagedRelease {
        tag: release.tag_name.clone(),
        asset_id: Some(asset.id),
        file_path,
        splits: Vec::new(),
        apk,
    };
    stage_release(state, app, staged, false).await
}

/// What a running update check is doing right now, for the app page's live status line. Kept in
/// memory only - it means nothing once the check ends (or the server restarts).
#[derive(Clone)]
pub struct CheckProgress {
    pub stage: String,
    /// Download progress, when the current stage is a download of known size.
    pub percent: Option<u8>,
}

static CHECKS: std::sync::Mutex<Option<HashMap<i64, CheckProgress>>> = std::sync::Mutex::new(None);

/// Marks app `id` as being checked until dropped - see [begin_check].
pub struct CheckGuard(i64);

impl Drop for CheckGuard {
    fn drop(&mut self) {
        if let Ok(mut checks) = CHECKS.lock() {
            if let Some(map) = checks.as_mut() {
                map.remove(&self.0);
            }
        }
    }
}

/// Claims app `id` for a check, or None if one is already running for it.
fn begin_check(id: i64) -> Option<CheckGuard> {
    let mut checks = CHECKS.lock().ok()?;
    let map = checks.get_or_insert_with(HashMap::new);
    if map.contains_key(&id) {
        return None;
    }
    map.insert(
        id,
        CheckProgress {
            stage: "Starting…".to_string(),
            percent: None,
        },
    );
    Some(CheckGuard(id))
}

fn set_progress(id: i64, stage: &str, percent: Option<u8>) {
    if let Ok(mut checks) = CHECKS.lock() {
        if let Some(entry) = checks.as_mut().and_then(|m| m.get_mut(&id)) {
            entry.stage = stage.to_string();
            entry.percent = percent;
        }
    }
}

/// The running check of app `id`, if any.
pub fn check_progress(id: i64) -> Option<CheckProgress> {
    CHECKS.lock().ok()?.as_ref()?.get(&id).cloned()
}

/// Starts app `id`'s update check in the background and returns at once - "Check now" and a newly
/// added Google Play app's first download, which can take minutes for a big app. The app page
/// shows [check_progress] meanwhile and any error afterwards (`last_check_error`). Returns false
/// if a check of that app is already running.
pub fn start_check(state: &AppState, id: i64) -> bool {
    let Some(guard) = begin_check(id) else {
        return false;
    };
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
        if let Some(app) = app {
            if let Err(e) = run_check(&state, &app).await {
                tracing::warn!("tracked app '{}' check failed: {e}", app.name);
            }
        }
    });
    true
}

/// A Google Play app's update check (see src/play.rs): asks Play for the current version, and
/// when it's one phones don't have yet (and newer than the live one - Play can briefly serve an
/// older build, and Android refuses downgrades anyway), downloads it and hands it to
/// `stage_release` like any other source. Play's version name + code is the release tag.
///
/// Apps Play only delivers as several "split" APKs, or with extra OBB data files, are refused
/// with a readable reason for now - launchers can only install a single APK so far.
async fn sync_play_app(state: &AppState, app: &TrackedApp) -> Result<(), String> {
    set_progress(app.id, "Asking Google Play for the latest version…", None);
    let listing = crate::play::lookup(state, &app.package_name).await?;

    sqlx::query("UPDATE tracked_apps SET last_checked_at = datetime('now') WHERE id = ?")
        .bind(app.id)
        .execute(&state.db)
        .await
        .ok();

    let tag = format!("{} ({})", listing.version_name, listing.version_code);
    let key = release_key(&tag, None);
    if app.rejected_release_key.as_deref() == Some(key.as_str()) {
        return Ok(());
    }
    // A release already downloaded is only "done" if its files are intact - one damaged before
    // v0.24.2 (two checks of the same app could download into the same folder at once) gets
    // downloaded again: a live one is repaired in place, a pending one re-staged.
    let is_live = app.latest_release_tag.as_deref() == Some(tag.as_str());
    let is_pending = app.pending_release_tag.as_deref() == Some(tag.as_str());
    let mut repair_live = false;
    if is_live {
        let base = app.latest_release_file_path.clone().unwrap_or_default();
        match verify_release_files(&base, &app.latest_splits()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    "'{}' live release is damaged, downloading again: {e}",
                    app.name
                );
                repair_live = true;
            }
        }
    } else if is_pending {
        let base = app.pending_release_file_path.clone().unwrap_or_default();
        if verify_release_files(&base, &app.pending_splits())
            .await
            .is_ok()
        {
            return Ok(());
        }
    } else if app
        .latest_apk()
        .is_some_and(|live| listing.version_code <= live.version_code)
    {
        return Ok(());
    }

    set_progress(app.id, "Getting download links from Google Play…", None);
    let files = crate::play::files(state, &app.package_name, listing.version_code).await?;
    if files.has_additional_files {
        return Err(
            "This app needs extra data files (OBB) from Google Play, which aren't supported."
                .to_string(),
        );
    }

    // Each Play release gets its own folder (base + splits), so removing it later is one folder.
    let release_dir = format!(
        "{TRACKED_APPS_DIR}/{}/play-{}",
        app.id, listing.version_code
    );
    tokio::fs::remove_dir_all(&release_dir).await.ok();
    tokio::fs::create_dir_all(&release_dir)
        .await
        .map_err(|e| e.to_string())?;
    let file_path = format!("{release_dir}/base.apk");
    let mut splits = Vec::new();
    let pieces = files.splits.len() + 1;
    let piece_label = |n: usize| {
        if pieces == 1 {
            "Downloading…".to_string()
        } else {
            format!("Downloading piece {n} of {pieces}…")
        }
    };
    let downloaded = async {
        download_to_file(&files.main_url, &file_path, app.id, &piece_label(1)).await?;
        for (index, (name, url)) in files.splits.iter().enumerate() {
            // Never a Play-supplied name in the path - it only goes in the JSON.
            let path = format!("{release_dir}/split-{index}.apk");
            download_to_file(url, &path, app.id, &piece_label(index + 2)).await?;
            splits.push(ReleaseSplit {
                name: name.clone(),
                path,
            });
        }
        Ok::<(), String>(())
    }
    .await;
    let verified = match downloaded {
        Ok(()) => {
            set_progress(app.id, "Checking the download…", None);
            verify_release_files(&file_path, &splits).await
        }
        Err(e) => Err(e),
    };
    if let Err(e) = verified {
        tokio::fs::remove_dir_all(&release_dir).await.ok();
        return Err(e);
    }

    if repair_live {
        // Same version, fresh intact files at the same place - point the live release at them.
        // Phones that failed to install it retry on their own (after their hour's back-off).
        sqlx::query(
            "UPDATE tracked_apps SET latest_release_file_path = ?, latest_release_splits_json = ? \
             WHERE id = ?",
        )
        .bind(&file_path)
        .bind(splits_json(&splits))
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|e| e.to_string())?;
        tracing::info!("'{}' live release repaired", app.name);
        return Ok(());
    }

    let apk = analyze_file(&file_path).await;
    let staged = StagedRelease {
        tag,
        asset_id: None,
        file_path,
        splits,
        apk,
    };
    // The first release was picked deliberately from a preview on the "Add from Google Play" page,
    // so it doesn't also wait for review or the hold period - same as an admin upload. Later
    // updates get the normal checks.
    let first_release = app.latest_release_file_path.is_none();
    stage_release(state, app, staged, first_release).await
}

/// Checks a release's files are complete APKs (a readable zip with an AndroidManifest.xml) - the
/// base and every split. A damaged one fails phone installs with INSTALL_PARSE_FAILED_NOT_APK,
/// which is what two overlapping downloads into the same folder produced before v0.24.2.
async fn verify_release_files(base: &str, splits: &[ReleaseSplit]) -> Result<(), String> {
    let mut paths = vec![base.to_string()];
    paths.extend(splits.iter().map(|s| s.path.clone()));
    let count = paths.len();
    for (index, path) in paths.into_iter().enumerate() {
        let checked = tokio::task::spawn_blocking(move || verify_apk_file(&path))
            .await
            .map_err(|e| e.to_string())?;
        checked.map_err(|why| {
            format!(
                "Downloaded piece {} of {count} isn't a complete APK ({why}). It's downloaded again \
                 on the next check.",
                index + 1
            )
        })?;
    }
    Ok(())
}

fn verify_apk_file(path: &str) -> Result<(), String> {
    use std::io::Read;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut head = [0u8; 4];
    let read = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    let detail = |why: &str| {
        let start: String = head[..read].iter().map(|b| format!("{b:02x}")).collect();
        format!("{why}; {size} bytes, starts with {start}")
    };
    let file = std::fs::File::open(path).map_err(|e| detail(&e.to_string()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| detail(&e.to_string()))?;
    archive
        .by_name("AndroidManifest.xml")
        .map_err(|_| detail("no AndroidManifest.xml"))?;
    Ok(())
}

/// Streams a download to `path` via a `.part` file, so a cut-off download never looks like a
/// finished APK. Play APKs can be hundreds of MB - never held in memory whole. Reports progress
/// for app `app_id` under `stage` (e.g. "Downloading piece 2 of 3…") - see [check_progress].
async fn download_to_file(url: &str, path: &str, app_id: i64, stage: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted)")
        .timeout(Duration::from_secs(30 * 60))
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("download failed: {e}"))?;
    let total = response.content_length().filter(|&n| n > 0);
    set_progress(app_id, stage, total.map(|_| 0));
    let part = format!("{path}.part");
    let mut file = tokio::fs::File::create(&part)
        .await
        .map_err(|e| e.to_string())?;
    let mut written: u64 = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("download failed: {e}"))?
    {
        file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        written += chunk.len() as u64;
        if let Some(total) = total {
            set_progress(app_id, stage, Some((written * 100 / total).min(100) as u8));
        }
    }
    file.flush().await.map_err(|e| e.to_string())?;
    drop(file);
    tokio::fs::rename(&part, path)
        .await
        .map_err(|e| e.to_string())
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
    /// A running update check - the page shows it and refreshes itself until it ends.
    progress: Option<CheckProgress>,
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
            progress: check_progress(app.id),
            app,
            error,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// "Check now": starts the check in the background and returns straight to the app page, which
/// shows live progress (see [check_progress]) and refreshes itself until it's done - a Google Play
/// download can take minutes, and the page used to hang that long.
pub async fn check_now(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    start_check(&state, id);
    Redirect::to(&format!("/apps/tracked/{id}"))
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
        splits: Vec::new(),
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
        remove_release_files(path, &app.pending_splits()).await;
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

    if let Some(path) = &app.latest_release_file_path {
        remove_release_files(path, &app.latest_splits()).await;
    }
    if let Some(path) = &app.pending_release_file_path {
        remove_release_files(path, &app.pending_splits()).await;
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

#[cfg(test)]
mod check_progress_tests {
    use super::{begin_check, check_progress, set_progress};

    #[test]
    fn one_check_per_app_until_the_guard_drops() {
        let guard = begin_check(-42).expect("first check starts");
        assert!(
            begin_check(-42).is_none(),
            "second check of the same app is refused"
        );
        set_progress(-42, "Downloading…", Some(40));
        let progress = check_progress(-42).expect("running check is visible");
        assert_eq!(progress.stage, "Downloading…");
        assert_eq!(progress.percent, Some(40));
        drop(guard);
        assert!(check_progress(-42).is_none(), "finished check disappears");
        assert!(begin_check(-42).is_some(), "app can be checked again");
    }
}

#[cfg(test)]
mod verify_tests {
    use super::verify_apk_file;
    use std::io::Write;

    #[test]
    fn rejects_truncated_and_accepts_complete_apks() {
        let dir = std::env::temp_dir().join(format!("kps-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.apk");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&good).unwrap());
        zip.start_file(
            "AndroidManifest.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(b"manifest").unwrap();
        zip.finish().unwrap();
        assert!(verify_apk_file(good.to_str().unwrap()).is_ok());

        let bytes = std::fs::read(&good).unwrap();
        let cut = dir.join("cut.apk");
        std::fs::write(&cut, &bytes[..bytes.len() / 2]).unwrap();
        let err = verify_apk_file(cut.to_str().unwrap()).unwrap_err();
        assert!(err.contains("starts with 504b"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
