use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use sha2::{Digest, Sha256};
use tower_sessions::Session;

use crate::AppState;
use crate::models::{AdminUser, Device};

pub const MIN_PASSWORD_LEN: usize = 12;

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

/// Requires a logged-in admin who has completed the forced password change.
/// Use this on every route in the actual admin UI.
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
