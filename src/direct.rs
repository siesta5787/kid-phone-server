//! Lets phones download Google Play and GitHub apps straight from Google / GitHub instead of from
//! this server (launcher v0.56.0+). Every byte otherwise crosses the Pi Zero's slow 2.4 GHz Wi-Fi
//! twice (source → Pi → phone); a 1.2 GB game took about 15 minutes that way.
//!
//! The server still downloads and checks every release itself - that copy is what the parent
//! approved, what the phone falls back to, and what makes the direct download safe: right before
//! downloading, the phone asks `GET /api/devices/apps/{id}/direct` for fresh links (Google's
//! expire) plus the SHA-256 and size of each of this server's files, and only installs a direct
//! download that matches them exactly. Anything else - no links, a mismatch, a network error - and
//! it downloads that file from this server as before.
//!
//! The SHA-256 of each release file is kept next to it as `<file>.sha256` ("<hex> <size>"),
//! written as the file is downloaded ([crate::handlers::tracked_apps]) or worked out later for
//! releases downloaded before this existed ([backfill]).

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::AppState;
use crate::models::{DirectDownloadFile, DirectDownloads, TrackedApp};

/// How long the phone's request may spend asking Google / GitHub for links - under the phone's
/// own 10-second read timeout, so a slow answer becomes a quick fallback, not a failed request.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

fn fingerprint_path(path: &str) -> String {
    format!("{path}.sha256")
}

/// Records `path`'s SHA-256 (lowercase hex) and size. Best-effort: without it, phones just
/// download that file from this server.
pub async fn save_fingerprint(path: &str, sha256: &str, size: u64) {
    if let Err(e) = tokio::fs::write(fingerprint_path(path), format!("{sha256} {size}")).await {
        tracing::warn!("couldn't save the fingerprint of {path}: {e}");
    }
}

/// Removes `path`'s fingerprint, alongside removing the file itself.
pub async fn remove_fingerprint(path: &str) {
    tokio::fs::remove_file(fingerprint_path(path)).await.ok();
}

/// `path`'s recorded SHA-256 and size - None if there's none, or the file's size no longer matches
/// it (replaced since).
async fn read_fingerprint(path: &str) -> Option<(String, u64)> {
    let text = tokio::fs::read_to_string(fingerprint_path(path))
        .await
        .ok()?;
    let (sha256, size) = parse_fingerprint(&text)?;
    let actual = tokio::fs::metadata(path).await.ok()?.len();
    (actual == size).then_some((sha256, size))
}

fn parse_fingerprint(text: &str) -> Option<(String, u64)> {
    let (sha256, size) = text.trim().split_once(' ')?;
    let valid = sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit());
    Some((sha256.to_ascii_lowercase(), size.parse().ok()?)).filter(|_| valid)
}

/// Reads `path` through and records its fingerprint, dropping it from the page cache as it goes
/// (see src/disk.rs - a game is bigger than the Pi's memory).
async fn compute_fingerprint(path: &str) -> Result<(), String> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| e.to_string())?;
    let mut reader = crate::disk::CacheDroppingReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut size: u64 = 0;
    loop {
        let read = reader.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    save_fingerprint(path, &hex::encode(hasher.finalize()), size).await;
    Ok(())
}

/// Every file of `app`'s live release, base APK first, then its splits in the order phones get
/// them from `tracked_app_updates`.
fn live_files(app: &TrackedApp) -> Vec<String> {
    let mut files: Vec<String> = app.latest_release_file_path.iter().cloned().collect();
    files.extend(app.latest_splits().into_iter().map(|s| s.path));
    files
}

fn has_direct_source(app: &TrackedApp) -> bool {
    matches!(app.source_type.as_str(), "play" | "github")
}

/// Works out the fingerprints missing from Google Play / GitHub apps' live releases - those
/// downloaded before v0.25.0. Run from the hourly update loop; one big file read at a time, sharing
/// [crate::disk::DOWNLOADS] with downloads so the SD card isn't asked for both at once.
pub async fn backfill(apps: &[TrackedApp]) {
    for app in apps.iter().filter(|a| has_direct_source(a)) {
        for path in live_files(app) {
            if read_fingerprint(&path).await.is_some() {
                continue;
            }
            let Ok(_slot) = crate::disk::DOWNLOADS.acquire().await else {
                return;
            };
            match compute_fingerprint(&path).await {
                Ok(()) => tracing::info!("fingerprinted {path} for direct downloads"),
                Err(e) => tracing::warn!("couldn't fingerprint {path}: {e}"),
            }
        }
    }
}

/// Fresh links to `app`'s live release straight from Google Play / GitHub, with what each file
/// must match. Err (with why, for the log) when there's no direct option - the phone then uses
/// this server's copy.
pub async fn direct_links(state: &AppState, app: &TrackedApp) -> Result<DirectDownloads, String> {
    let tag = app.latest_release_tag.clone().ok_or("no live release")?;
    let release_tag = match app.latest_release_asset_id {
        Some(asset_id) => format!("{tag}@{asset_id}"),
        None => tag,
    };

    let mut fingerprints = Vec::new();
    for path in live_files(app) {
        fingerprints.push(
            read_fingerprint(&path)
                .await
                .ok_or_else(|| format!("{path} has no fingerprint yet"))?,
        );
    }

    let (source, urls) = match app.source_type.as_str() {
        "play" => ("google_play", play_urls(state, app).await?),
        "github" => ("github", vec![github_url(app).await?]),
        other => return Err(format!("{other} apps have no direct source")),
    };
    if urls.len() != fingerprints.len() {
        return Err(format!(
            "the source has {} files, this server {}",
            urls.len(),
            fingerprints.len()
        ));
    }
    if let Some(bad) = urls.iter().find(|u| !u.starts_with("https://")) {
        return Err(format!("not an https link: {bad}"));
    }

    Ok(DirectDownloads {
        source: source.to_string(),
        release_tag,
        files: urls
            .into_iter()
            .zip(fingerprints)
            .map(|(url, (sha256, size))| DirectDownloadFile { url, sha256, size })
            .collect(),
    })
}

/// Google's links for the exact version that's live here - base APK, then the splits in this
/// server's order (matched by Play's split name).
async fn play_urls(state: &AppState, app: &TrackedApp) -> Result<Vec<String>, String> {
    let version_code = app
        .latest_apk()
        .ok_or("the live release's version isn't known")?
        .version_code;
    let files = tokio::time::timeout(
        LOOKUP_TIMEOUT,
        crate::play::files(state, &app.package_name, version_code),
    )
    .await
    .map_err(|_| "Google Play took too long".to_string())??;
    let mut urls = vec![files.main_url];
    for split in app.latest_splits() {
        let url = files
            .splits
            .iter()
            .find(|(name, _)| *name == split.name)
            .map(|(_, url)| url.clone())
            .ok_or_else(|| format!("Google Play has no '{}' piece", split.name))?;
        urls.push(url);
    }
    Ok(urls)
}

#[derive(serde::Deserialize)]
struct GithubAsset {
    browser_download_url: String,
}

/// The live release asset's public download link (GitHub's own links don't expire).
async fn github_url(app: &TrackedApp) -> Result<String, String> {
    let asset_id = app
        .latest_release_asset_id
        .ok_or("no GitHub asset id recorded")?;
    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, github.com)")
        .timeout(LOOKUP_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "https://api.github.com/repos/{}/releases/assets/{asset_id}",
        app.github_repo
    );
    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub API returned {}", response.status()));
    }
    let asset: GithubAsset = response.json().await.map_err(|e| e.to_string())?;
    Ok(asset.browser_download_url)
}

#[cfg(test)]
mod tests {
    use super::parse_fingerprint;

    #[test]
    fn parses_fingerprints() {
        let hex = "ab".repeat(32);
        assert_eq!(
            parse_fingerprint(&format!("{hex} 1234\n")),
            Some((hex.clone(), 1234))
        );
        assert_eq!(
            parse_fingerprint(&format!("{} 1234", "AB".repeat(32))),
            Some((hex, 1234))
        );
        assert_eq!(parse_fingerprint("abc 1234"), None);
        assert_eq!(parse_fingerprint(&format!("{} x", "ab".repeat(32))), None);
        assert_eq!(parse_fingerprint(""), None);
    }
}
