//! Google Play as an app source (v0.24.0): looks apps up and fetches their download links through
//! Google's own Play API, the same way Aurora Store does, using a vendored copy of EFF's gpapi
//! crate (vendor/gpapi). The server signs in with the parent's spare Google account - see
//! migrations/0025_google_play.sql for what's stored. Downloading, review and publishing reuse
//! the existing tracked-app pipeline (`handlers::tracked_apps::sync_play_app`).
//!
//! Google can block an account it sees using Play this way (it's against Play's terms), which is
//! why the admin page asks for a spare account rather than the parent's main one.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gpapi::Gpapi;
use gpapi::error::ErrorKind as GpapiErrorKind;
use tokio::sync::Mutex;

use crate::AppState;

/// gpapi's built-in Pixel 9a profile (arm64-v8a, Android 15): what Play is told the downloads are
/// for. Matches every kid phone/tablet this project supports (arm64, Android 14+).
const DEVICE_PROFILE: &str = "px_9a";

/// Google's AUTH tokens last about an hour - log in again a little before that.
const SESSION_MAX_AGE: Duration = Duration::from_secs(45 * 60);

/// How long "Sign in using a phone" stays open on the admin page.
pub const SIGNIN_WINDOW_MINUTES: i64 = 10;

#[derive(sqlx::FromRow, Clone, Default)]
pub struct PlaySettings {
    pub id: i64,
    pub email: Option<String>,
    pub aas_token: Option<String>,
    pub signed_in_at: Option<String>,
    pub signin_window_until_ms: Option<i64>,
    pub signin_email: Option<String>,
    pub last_error: Option<String>,
    pub last_ok_at: Option<String>,
}

impl PlaySettings {
    pub fn signed_in(&self) -> bool {
        self.email.is_some() && self.aas_token.is_some()
    }

    /// The "Sign in using a phone" window is open right now.
    pub fn signin_window_open(&self, now_ms: i64) -> bool {
        self.signin_window_until_ms
            .is_some_and(|until| now_ms < until)
    }
}

pub async fn settings(state: &AppState) -> PlaySettings {
    sqlx::query_as::<_, PlaySettings>("SELECT * FROM play_settings WHERE id = 1")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Runs one gpapi call to completion on a blocking-pool thread. gpapi's futures aren't `Send`
/// (they hold its non-`Send` `Box<dyn Error>` across awaits), so they can't be awaited directly
/// inside axum handlers or the spawned hourly sync - but `Handle::block_on` has no `Send`
/// requirement, and the future is only ever built inside the blocking thread. Its output must be
/// `Send`, which is why every error is flattened to a `String` in there.
async fn run_gpapi<T, F, Fut>(make_future: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>>,
{
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(make_future()))
        .await
        .map_err(|e| format!("Google Play call crashed: {e}"))?
}

/// One logged-in Play session shared by every caller, so the hourly update check and the admin
/// pages don't each do a full checkin + login. Dropped on sign-out and whenever a call fails.
static SESSION: Mutex<Option<(Arc<Gpapi>, Instant)>> = Mutex::const_new(None);

/// Logs in (checkin, device config upload, AUTH token, terms of service) with the stored AAS
/// token unless a fresh enough session already exists. Records the outcome on `play_settings`
/// so the settings page can say whether Play is working.
async fn session(state: &AppState) -> Result<Arc<Gpapi>, String> {
    let mut guard = SESSION.lock().await;
    if let Some((api, at)) = guard.as_ref() {
        if at.elapsed() < SESSION_MAX_AGE {
            return Ok(api.clone());
        }
    }
    *guard = None;

    let settings = settings(state).await;
    let (Some(email), Some(aas_token)) = (settings.email, settings.aas_token) else {
        return Err("Not signed in to Google Play yet - see Settings → Google Play.".to_string());
    };
    let result = login(email, aas_token).await;
    record_outcome(state, result.as_ref().err()).await;
    let api = Arc::new(result?);
    *guard = Some((api.clone(), Instant::now()));
    Ok(api)
}

async fn login(email: String, aas_token: String) -> Result<Gpapi, String> {
    run_gpapi(move || async move {
        let mut api = Gpapi::new(DEVICE_PROFILE, email.as_str());
        api.set_aas_token(aas_token.as_str());
        let first = api
            .login()
            .await
            .map_err(|e| (e.to_string(), e.kind_is_tos()));
        match first {
            Ok(()) => Ok(api),
            // A fresh account has to accept Play's terms once before anything else works.
            Err((_, true)) => {
                api.accept_tos().await.map_err(|e| e.to_string())?;
                api.login().await.map_err(|e| e.to_string())?;
                Ok(api)
            }
            Err((message, false)) => Err(format!("Google Play sign-in failed: {message}")),
        }
    })
    .await
}

trait TosCheck {
    fn kind_is_tos(&self) -> bool;
}

impl TosCheck for gpapi::error::Error {
    fn kind_is_tos(&self) -> bool {
        matches!(self.kind(), GpapiErrorKind::TermsOfService)
    }
}

async fn record_outcome(state: &AppState, error: Option<&String>) {
    let query = match error {
        Some(_) => "UPDATE play_settings SET last_error = ? WHERE id = 1",
        None => {
            "UPDATE play_settings SET last_error = ?, last_ok_at = datetime('now') WHERE id = 1"
        }
    };
    sqlx::query(query).bind(error).execute(&state.db).await.ok();
}

/// Any failed Play call might mean the session went stale - start over next time.
async fn drop_session() {
    *SESSION.lock().await = None;
}

/// Swaps a one-time `oauth_token` (the cookie Google's EmbeddedSetup sign-in page sets) for a
/// long-lived AAS token, checks it actually logs in, then stores it. Used by both the phone
/// sign-in (`device_api::play_signin`) and the manual fallback on the settings page.
pub async fn sign_in(state: &AppState, email: &str, oauth_token: &str) -> Result<(), String> {
    let email = email.trim();
    let oauth_token = oauth_token.trim();
    if email.is_empty() || oauth_token.is_empty() {
        return Err("Both the account's email and the sign-in code are needed.".to_string());
    }
    let (owned_email, owned_code) = (email.to_string(), oauth_token.to_string());
    let aas_token = run_gpapi(move || async move {
        let mut api = Gpapi::new(DEVICE_PROFILE, owned_email.as_str());
        api.request_aas_token(owned_code.as_str())
            .await
            .map_err(|e| {
                format!(
                    "Google didn't accept the sign-in code ({e}). Codes only work once - sign \
                     in again for a new one."
                )
            })?;
        api.get_aas_token()
            .map(str::to_string)
            .ok_or_else(|| "Google didn't return a token".to_string())
    })
    .await?;
    // Proves the token works before replacing whatever was stored.
    login(email.to_string(), aas_token.clone()).await?;

    sqlx::query(
        "UPDATE play_settings SET email = ?, aas_token = ?, signed_in_at = datetime('now'), \
         signin_window_until_ms = NULL, signin_email = NULL, last_error = NULL, \
         last_ok_at = datetime('now') WHERE id = 1",
    )
    .bind(email)
    .bind(&aas_token)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;
    drop_session().await;
    Ok(())
}

pub async fn sign_out(state: &AppState) {
    sqlx::query(
        "UPDATE play_settings SET email = NULL, aas_token = NULL, signed_in_at = NULL, \
         signin_window_until_ms = NULL, last_error = NULL WHERE id = 1",
    )
    .execute(&state.db)
    .await
    .ok();
    drop_session().await;
}

/// Logs in from scratch (ignoring any cached session) - the settings page's "Test" button.
pub async fn test(state: &AppState) -> Result<(), String> {
    drop_session().await;
    session(state).await.map(|_| ())
}

/// What the "Add from Google Play" preview and the update check need to know about an app.
pub struct PlayApp {
    pub package_name: String,
    pub title: String,
    pub developer: String,
    pub version_code: i64,
    pub version_name: String,
    pub icon_url: Option<String>,
    pub download_size: Option<i64>,
}

/// The current Play listing for `package_name`, or an error a parent can read.
pub async fn lookup(state: &AppState, package_name: &str) -> Result<PlayApp, String> {
    let api = session(state).await?;
    let package = package_name.to_string();
    let response = run_gpapi(move || async move {
        api.details(package.as_str())
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            drop_session().await;
            return Err(format!("Google Play lookup failed: {e}"));
        }
    };

    let item = response
        .and_then(|r| r.item)
        .ok_or_else(|| format!("{package_name} isn't on Google Play (or isn't available here)."))?;
    let app = item
        .details
        .as_ref()
        .and_then(|d| d.app_details.as_ref())
        .ok_or_else(|| format!("{package_name} isn't an Android app on Google Play."))?;
    let version_code = app
        .version_code
        .ok_or_else(|| format!("Google Play has no installable version of {package_name}."))?;
    // Image type 4 is the app icon in Play's listing data (same as Aurora Store reads it).
    let icon_url = item
        .image
        .iter()
        .find(|i| i.image_type == Some(4))
        .and_then(|i| i.image_url.clone());

    Ok(PlayApp {
        package_name: package_name.to_string(),
        title: item
            .title
            .clone()
            .or_else(|| app.title.clone())
            .unwrap_or_else(|| package_name.to_string()),
        developer: item
            .creator
            .clone()
            .or_else(|| app.developer_name.clone())
            .unwrap_or_default(),
        version_code,
        version_name: app
            .version_string
            .clone()
            .unwrap_or_else(|| version_code.to_string()),
        icon_url,
        download_size: app.info_download_size,
    })
}

/// Where to download one Play release from.
pub struct PlayFiles {
    pub main_url: String,
    /// Names of the extra "split" APKs Play delivers alongside the main one - not installable by
    /// launchers yet, so a release with any is refused for now.
    pub split_names: Vec<String>,
    /// Extra data files (OBB) some games need - not supported.
    pub has_additional_files: bool,
}

pub async fn files(
    state: &AppState,
    package_name: &str,
    version_code: i64,
) -> Result<PlayFiles, String> {
    let api = session(state).await?;
    let package = package_name.to_string();
    let info = run_gpapi(move || async move {
        api.get_download_info(package.as_str(), Some(version_code))
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    let (main_url, splits, additional, _dex_metadata) = match info {
        Ok(info) => info,
        Err(e) => {
            drop_session().await;
            return Err(format!("Google Play wouldn't provide a download: {e}"));
        }
    };
    Ok(PlayFiles {
        main_url: main_url.ok_or("Google Play didn't provide a download link")?,
        split_names: splits.into_iter().filter_map(|(name, _)| name).collect(),
        has_additional_files: !additional.is_empty(),
    })
}

/// Accepts a Play Store link (`https://play.google.com/store/apps/details?id=com.example&hl=en`)
/// or a bare package name, and returns the package name if it looks like a real one.
pub fn parse_package(input: &str) -> Option<String> {
    let input = input.trim();
    let candidate = match input.split_once("id=") {
        Some((_, rest)) if input.contains("play.google.com") => {
            rest.split(['&', '#']).next().unwrap_or("")
        }
        _ => input,
    };
    let valid_segment = |s: &str| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let segments: Vec<&str> = candidate.split('.').collect();
    (segments.len() >= 2 && segments.iter().all(|s| valid_segment(s)))
        .then(|| candidate.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_package;

    #[test]
    fn parses_links_and_package_names() {
        assert_eq!(
            parse_package(
                "https://play.google.com/store/apps/details?id=com.disney.disneyplus&hl=en_US"
            ),
            Some("com.disney.disneyplus".to_string())
        );
        assert_eq!(
            parse_package("  com.example.app_2 "),
            Some("com.example.app_2".to_string())
        );
        assert_eq!(parse_package("disney plus"), None);
        assert_eq!(parse_package("com"), None);
        assert_eq!(parse_package("com..app"), None);
        assert_eq!(parse_package("1com.app"), None);
    }
}
