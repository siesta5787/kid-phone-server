use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use totp_rs::{Algorithm, Secret, TOTP};
use tower_sessions::Session;

use crate::AppState;
use crate::models::{AdminUser, Device};

pub const MIN_PASSWORD_LEN: usize = 12;

/// Failed *password or TOTP* attempts against one account before it locks.
pub const MAX_FAILED_ATTEMPTS: i64 = 5;
/// How long a locked account stays locked before auto-unlocking.
pub const LOCKOUT_MINUTES: i64 = 15;
/// Failed attempts from one IP (across any account) within the window below
/// before that IP is banned from reaching the login page at all.
pub const MAX_FAILED_PER_IP: i64 = 15;
pub const IP_FAILURE_WINDOW_MINUTES: i64 = 15;
/// How long an IP ban lasts before auto-expiring.
pub const IP_BAN_HOURS: i64 = 1;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("hashing a non-empty password should not fail")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Short, human-typeable, unambiguous (no 0/O/1/I/L) enrollment code shown in
/// the admin UI and typed once into the phone's Settings screen - this
/// replaces the old flow of typing a raw server URL + made-up device number.
pub fn generate_enrollment_code() -> String {
    const CHARS: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let mut rng = OsRng;
    (0..8)
        .map(|_| CHARS[(rng.next_u32() as usize) % CHARS.len()] as char)
        .collect()
}

/// High-entropy bearer token handed to a device once, at enrollment. Only
/// its SHA-256 hash (see `hash_token`) is ever stored - the plaintext value
/// is shown/returned exactly once and can't be recovered afterward, the same
/// way a password reset works.
pub fn generate_device_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Best-effort client IP: prefers X-Forwarded-For (set by a reverse proxy -
/// relevant once this is behind Tailscale Funnel), falling back to the TCP
/// peer address.
pub fn client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| addr.ip().to_string())
}

pub async fn record_security_event(
    db: &sqlx::SqlitePool,
    event_type: &str,
    username: Option<&str>,
    ip: Option<&str>,
    detail: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO security_events (event_type, username, ip_address, detail) VALUES (?, ?, ?, ?)",
    )
    .bind(event_type)
    .bind(username)
    .bind(ip)
    .bind(detail)
    .execute(db)
    .await
    .ok();
}

pub async fn is_ip_banned(db: &sqlx::SqlitePool, ip: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip_address = ? AND banned_until > datetime('now'))",
    )
    .bind(ip)
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

/// Counts recent failed attempts from this IP and bans it if over threshold.
/// Call after recording a failed-login-type security event.
pub async fn check_and_ban_ip_if_needed(db: &sqlx::SqlitePool, ip: &str) {
    let recent_failures: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM security_events \
         WHERE ip_address = ? AND event_type IN ('login_failed', 'totp_failed') \
         AND created_at > datetime('now', ?)",
    )
    .bind(ip)
    .bind(format!("-{IP_FAILURE_WINDOW_MINUTES} minutes"))
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if recent_failures >= MAX_FAILED_PER_IP {
        sqlx::query(
            "INSERT INTO banned_ips (ip_address, banned_until, reason) VALUES (?, datetime('now', ?), ?) \
             ON CONFLICT(ip_address) DO UPDATE SET banned_until = excluded.banned_until, reason = excluded.reason",
        )
        .bind(ip)
        .bind(format!("+{IP_BAN_HOURS} hours"))
        .bind(format!(
            "{recent_failures} failed login attempts within {IP_FAILURE_WINDOW_MINUTES} minutes"
        ))
        .execute(db)
        .await
        .ok();

        record_security_event(
            db,
            "ip_banned",
            None,
            Some(ip),
            Some(&format!("{recent_failures} failed attempts")),
        )
        .await;
    }
}

/// True if this account is currently locked out (and the lock hasn't expired).
pub async fn is_account_locked(db: &sqlx::SqlitePool, admin_id: i64) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT locked_until IS NOT NULL AND locked_until > datetime('now') FROM admin_users WHERE id = ?",
    )
    .bind(admin_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// Records one failed password/TOTP attempt against a known account, locking
/// it once MAX_FAILED_ATTEMPTS is reached. Deliberately does nothing if the
/// account is already locked, so repeated hammering can't extend the lockout
/// and lock a legitimate user out indefinitely.
pub async fn record_failed_login(db: &sqlx::SqlitePool, admin_id: i64) {
    if is_account_locked(db, admin_id).await {
        return;
    }

    sqlx::query(
        "UPDATE admin_users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
    )
    .bind(admin_id)
    .execute(db)
    .await
    .ok();

    let attempts: i64 =
        sqlx::query_scalar("SELECT failed_login_attempts FROM admin_users WHERE id = ?")
            .bind(admin_id)
            .fetch_one(db)
            .await
            .unwrap_or(0);

    if attempts >= MAX_FAILED_ATTEMPTS {
        sqlx::query("UPDATE admin_users SET locked_until = datetime('now', ?) WHERE id = ?")
            .bind(format!("+{LOCKOUT_MINUTES} minutes"))
            .bind(admin_id)
            .execute(db)
            .await
            .ok();
    }
}

pub async fn reset_failed_login(db: &sqlx::SqlitePool, admin_id: i64) {
    sqlx::query(
        "UPDATE admin_users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
    )
    .bind(admin_id)
    .execute(db)
    .await
    .ok();
}

/// Builds a TOTP object for a given admin from a stored (or freshly
/// generated) base32 secret. All accounts share the same algorithm/digits/
/// step, so the secret alone is enough to reconstruct it.
pub fn totp_for_secret(secret_base32: &str, username: &str) -> TOTP {
    let secret = Secret::Encoded(secret_base32.to_string());
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .expect("stored secret should be valid base32"),
        Some("Kids Device MDM".to_string()),
        username.to_string(),
    )
    .expect("fixed TOTP parameters should always be valid")
}

/// Rounds recommended (OWASP, 2023) as a PBKDF2-HMAC-SHA256 minimum.
const PIN_PBKDF2_ROUNDS: u32 = 210_000;
const PIN_SALT_LEN: usize = 16;
const PIN_HASH_LEN: usize = 32;

/// Hashes a device's offline-override PIN with PBKDF2-HMAC-SHA256 and a
/// fresh random salt, returning `(hash_hex, salt_hex)`. Deliberately not the
/// Argon2 used for admin passwords: this hash+salt pair gets shipped down to
/// the device in its policy payload so `LockActivity` can verify a
/// locally-entered PIN with zero network at all, and PBKDF2 is available on
/// Android via the built-in `javax.crypto.SecretKeyFactory` with no extra
/// client dependency, unlike Argon2. Nothing on the server itself ever
/// verifies a PIN - there's no server-side flow that takes one - so there's
/// no matching `verify_pin` here, only the client needs that half.
pub fn hash_pin(pin: &str) -> (String, String) {
    let mut salt = [0u8; PIN_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut hash = [0u8; PIN_HASH_LEN];
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), &salt, PIN_PBKDF2_ROUNDS, &mut hash);
    (hex::encode(hash), hex::encode(salt))
}

pub fn generate_totp_secret_base32() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(_) => unreachable!("to_encoded() always returns the Encoded variant"),
    }
}

/// Plain read of whatever version install.sh last stamped into
/// `data/watcher_version`, purely for display ("System helper scripts:
/// vX.Y.Z"). Whether that's actually a *problem* is answered separately by
/// `watcher_needs_update` below.
pub async fn installed_watcher_version() -> Option<String> {
    let installed = tokio::fs::read_to_string("data/watcher_version")
        .await
        .ok()?;
    let installed = installed.trim();
    if installed.is_empty() {
        None
    } else {
        Some(installed.to_string())
    }
}

/// The watcher "schema" version: a small counter, independent of the app's
/// own release version, bumped only when install.sh's root-side scripts
/// (actions.sh/watcher.sh/scheduler.sh/backup_sync.sh) actually gain or
/// change a privileged action - see board-game-tracker's CLAUDE.md for why
/// comparing raw version strings directly was the wrong check (it fired on
/// every single app release regardless of whether the watcher itself had
/// changed at all).
pub const REQUIRED_WATCHER_SCHEMA: u32 = 2;

async fn installed_watcher_schema() -> Option<u32> {
    let raw = tokio::fs::read_to_string("data/watcher_schema_version")
        .await
        .ok()?;
    raw.trim().parse::<u32>().ok()
}

/// Whether the installed watcher is missing a privileged action the app
/// might need to request. An unknown schema (no marker at all - a fresh
/// install that hasn't run install.sh's watcher setup yet) is treated as
/// needing an update too, since it can't be confirmed safe either way.
pub async fn watcher_needs_update() -> bool {
    installed_watcher_schema()
        .await
        .is_none_or(|schema| schema < REQUIRED_WATCHER_SCHEMA)
}

/// Re-run hint shown wherever the watcher version is displayed - the
/// root-side watcher/scheduler scripts are only ever refreshed by re-running
/// install.sh (the in-app "Update now" button only swaps the app binary).
pub const REINSTALL_HINT: &str = "curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash";

/// Creates the first admin account from ADMIN_USERNAME/ADMIN_PASSWORD env
/// vars if the admin_users table is empty - there's no self-registration, so
/// this is the only way to get a first account onto a fresh install.
pub async fn bootstrap_admin(db: &sqlx::SqlitePool) {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
        .fetch_one(db)
        .await
        .expect("failed to count admin_users");
    if count > 0 {
        return;
    }

    let username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let password = std::env::var("ADMIN_PASSWORD")
        .expect("ADMIN_PASSWORD must be set in .env to bootstrap the first admin account");

    let hash = hash_password(&password);
    sqlx::query(
        "INSERT INTO admin_users (username, password_hash, must_change_password) VALUES (?, ?, 1)",
    )
    .bind(&username)
    .bind(&hash)
    .execute(db)
    .await
    .expect("failed to create bootstrap admin");

    tracing::info!("bootstrapped initial admin account: {username}");
}

#[derive(Clone)]
pub struct CurrentAdmin(pub AdminUser);

async fn load_active_admin(state: &AppState, session: &Session) -> Option<AdminUser> {
    let admin_id: i64 = session.get("admin_id").await.ok().flatten()?;
    sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE id = ?")
        .bind(admin_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

/// Requires a valid session, but does not enforce the forced-password-change
/// gate - used for the change-password page itself and logout, which must
/// stay reachable mid-onboarding.
pub async fn require_session(
    State(state): State<AppState>,
    session: Session,
    mut request: Request,
    next: Next,
) -> Response {
    match load_active_admin(&state, &session).await {
        Some(admin) => {
            request.extensions_mut().insert(CurrentAdmin(admin));
            next.run(request).await
        }
        None => {
            session.flush().await.ok();
            Redirect::to("/login").into_response()
        }
    }
}

/// Requires a logged-in admin who has completed the forced password change
/// and mandatory 2FA setup. Use this on every route in the actual admin UI.
pub async fn require_full_auth(
    State(state): State<AppState>,
    session: Session,
    mut request: Request,
    next: Next,
) -> Response {
    match load_active_admin(&state, &session).await {
        Some(admin) if admin.must_change_password => {
            Redirect::to("/auth/change-password").into_response()
        }
        Some(admin) if !admin.totp_enabled => Redirect::to("/auth/setup-2fa").into_response(),
        Some(admin) => {
            request.extensions_mut().insert(CurrentAdmin(admin));
            next.run(request).await
        }
        None => {
            session.flush().await.ok();
            Redirect::to("/login").into_response()
        }
    }
}

#[derive(Clone)]
pub struct AuthedDevice(pub Device);

/// Bearer-token auth for the device-facing API (`/api/devices/*`, excluding
/// enroll) - completely separate from the admin session system above, since
/// a kid's phone is never an admin session.
pub async fn require_device_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (axum::http::StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };

    let token_hash = hash_token(token);
    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE token_hash = ?")
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    match device {
        Some(device) => {
            request.extensions_mut().insert(AuthedDevice(device));
            next.run(request).await
        }
        None => (axum::http::StatusCode::UNAUTHORIZED, "invalid device token").into_response(),
    }
}
