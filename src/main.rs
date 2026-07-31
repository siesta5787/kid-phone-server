mod handlers;
mod models;
mod security;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteSynchronous};
use std::str::FromStr;
use tower_http::services::ServeDir;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::session_store::ExpiredDeletion;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

pub const APP_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("Kid Phone Server {APP_VERSION} starting");

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data/kidphone.db".into());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3100".into());

    std::fs::create_dir_all("data").expect("failed to create data directory");

    let connect_options = SqliteConnectOptions::from_str(&database_url)
        .expect("invalid DATABASE_URL")
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let db = SqlitePoolOptions::new()
        .connect_with(connect_options)
        .await
        .expect("failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("failed to run migrations");

    security::bootstrap_admin(&db).await;

    let session_store = SqliteStore::new(db.clone());
    session_store
        .migrate()
        .await
        .expect("failed to run session store migrations");

    tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60 * 60)),
    );

    let insecure_cookies = std::env::var("INSECURE_COOKIES")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if insecure_cookies {
        tracing::warn!(
            "INSECURE_COOKIES is set - session cookies will be sent over plain HTTP. \
             This is for local LAN testing only and must never be set in production."
        );
    }

    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(CookieDuration::days(30)))
        .with_secure(!insecure_cookies);

    let state = AppState { db };

    // Reachable without any session at all. /sw.js lives here too - a
    // service-worker fetch has no session cookie context the way a page
    // load does, so it can't sit behind require_full_auth.
    let public_routes = Router::new()
        .route(
            "/login",
            get(handlers::auth::login_form).post(handlers::auth::login),
        )
        .route(
            "/auth/verify-2fa",
            get(handlers::auth::verify_2fa_form).post(handlers::auth::verify_2fa),
        )
        .route("/sw.js", get(handlers::sw::serve_sw));

    // Reachable with a valid session, even mid-onboarding (forced password
    // change / mandatory 2FA setup) - these routes ARE the onboarding gate,
    // so they can't themselves require onboarding to be complete.
    let onboarding_routes = Router::new()
        .route(
            "/auth/change-password",
            get(handlers::auth::change_password_form).post(handlers::auth::change_password),
        )
        .route(
            "/auth/setup-2fa",
            get(handlers::auth::setup_2fa_form).post(handlers::auth::setup_2fa_verify),
        )
        .route("/logout", post(handlers::auth::logout))
        .layer(from_fn_with_state(state.clone(), security::require_session));

    let admin_routes = Router::new()
        .route("/", get(handlers::devices::dashboard))
        .route("/devices", get(handlers::devices::list_devices))
        .route(
            "/devices/new",
            get(handlers::devices::new_device_form).post(handlers::devices::create_device),
        )
        .route("/devices/{id}", get(handlers::devices::view_device))
        .route(
            "/devices/{id}/policy",
            post(handlers::devices::update_policy),
        )
        .route(
            "/devices/{id}/regenerate-code",
            post(handlers::devices::regenerate_code),
        )
        .route(
            "/devices/{id}/delete",
            post(handlers::devices::delete_device),
        )
        .route("/apps", get(handlers::releases::list_apps))
        .route("/apps/launcher", get(handlers::releases::list_releases))
        .route(
            "/apps/launcher/upload",
            post(handlers::releases::upload_release)
                .layer(DefaultBodyLimit::max(200 * 1024 * 1024)),
        )
        .route(
            "/apps/launcher/{id}/delete",
            post(handlers::releases::delete_release),
        )
        .route("/settings", get(handlers::settings::settings_hub))
        .route("/backups", get(handlers::backups::list_backups))
        .route("/backups/create", post(handlers::backups::create_backup))
        .route(
            "/backups/upload",
            post(handlers::backups::upload_backup).layer(DefaultBodyLimit::max(200 * 1024 * 1024)),
        )
        .route(
            "/backups/{filename}/download",
            get(handlers::backups::download_backup),
        )
        .route(
            "/backups/{filename}/delete",
            post(handlers::backups::delete_backup),
        )
        .route(
            "/backups/{filename}/restore",
            post(handlers::backups::restore_backup),
        )
        .route(
            "/backups/schedule",
            post(handlers::backups::save_backup_schedule),
        )
        .route(
            "/backups/format-drive",
            post(handlers::backups::format_drive),
        )
        .route("/updates", get(handlers::updates::show_updates_page))
        .route(
            "/update/trigger",
            post(handlers::system_update::trigger_update),
        )
        .route(
            "/update/restart",
            post(handlers::system_update::trigger_restart),
        )
        .route(
            "/update/schedule",
            post(handlers::system_update::save_app_update_schedule),
        )
        .route(
            "/system/os/check",
            post(handlers::system_maintenance::trigger_os_check),
        )
        .route(
            "/system/os/upgrade",
            post(handlers::system_maintenance::trigger_os_upgrade),
        )
        .route(
            "/system/tailscale/update",
            post(handlers::system_maintenance::trigger_tailscale_update),
        )
        .route(
            "/system/reboot",
            post(handlers::system_maintenance::trigger_reboot),
        )
        .route(
            "/system/schedule",
            post(handlers::system_maintenance::save_schedule),
        )
        .route("/security", get(handlers::admin::security_log))
        .route("/security/unban/{ip}", post(handlers::admin::unban_ip))
        .route("/account", get(handlers::auth::account_page))
        .route(
            "/account/password",
            post(handlers::auth::update_account_password),
        )
        .route("/account/reset-2fa", post(handlers::auth::reset_totp))
        .layer(from_fn_with_state(
            state.clone(),
            security::require_full_auth,
        ));

    // Device-facing API. Enrollment is unauthenticated (the enrollment code
    // itself is the one-shot credential); policy/status require the bearer
    // token issued at enrollment.
    let device_public_routes =
        Router::new().route("/api/devices/enroll", post(handlers::device_api::enroll));

    let device_authed_routes = Router::new()
        .route("/api/devices/policy", get(handlers::device_api::policy))
        .route("/api/devices/status", post(handlers::device_api::status))
        .route(
            "/api/devices/launcher-update",
            get(handlers::device_api::launcher_update),
        )
        .route(
            "/api/devices/launcher-update/download",
            get(handlers::device_api::launcher_update_download),
        )
        .layer(from_fn_with_state(
            state.clone(),
            security::require_device_token,
        ));

    tokio::task::spawn(handlers::backups::run_scheduled_backups(state.clone()));
    tokio::task::spawn(handlers::backups::run_live_mirror(state.clone()));
    tokio::task::spawn(handlers::system_update::run_scheduled_app_update_check(
        state.clone(),
    ));

    let app = Router::new()
        .merge(public_routes)
        .merge(onboarding_routes)
        .merge(admin_routes)
        .merge(device_public_routes)
        .merge(device_authed_routes)
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(session_layer);

    tracing::info!("listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
