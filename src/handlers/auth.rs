use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;
use tower_sessions::Session;

use crate::AppState;
use crate::models::AdminUser;
use crate::security::{self, CurrentAdmin};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    title: String,
    error: Option<String>,
}

pub async fn login_form() -> impl IntoResponse {
    Html(
        LoginTemplate {
            title: "Sign in".to_string(),
            error: None,
        }
        .render()
        .unwrap(),
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let admin = sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let valid = match &admin {
        Some(a) => security::verify_password(&form.password, &a.password_hash),
        None => false,
    };

    if !valid {
        return Html(
            LoginTemplate {
                title: "Sign in".to_string(),
                error: Some("Incorrect username or password.".to_string()),
            }
            .render()
            .unwrap(),
        )
        .into_response();
    }

    let admin = admin.unwrap();
    session.insert("admin_id", admin.id).await.ok();
    Redirect::to("/").into_response()
}

pub async fn logout(session: Session) -> impl IntoResponse {
    session.flush().await.ok();
    Redirect::to("/login")
}

#[derive(Template)]
#[template(path = "change_password.html")]
struct ChangePasswordTemplate {
    title: String,
    error: Option<String>,
}

pub async fn change_password_form(
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    if !admin.must_change_password {
        return Redirect::to("/").into_response();
    }
    Html(
        ChangePasswordTemplate {
            title: "Change password".to_string(),
            error: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(form): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let render_error = |msg: &str| -> axum::response::Response {
        Html(
            ChangePasswordTemplate {
                title: "Change password".to_string(),
                error: Some(msg.to_string()),
            }
            .render()
            .unwrap(),
        )
        .into_response()
    };

    if !security::verify_password(&form.current_password, &admin.password_hash) {
        return render_error("Current password is incorrect.");
    }
    if form.new_password.len() < security::MIN_PASSWORD_LEN {
        return render_error("New password must be at least 12 characters.");
    }
    if form.new_password != form.confirm_password {
        return render_error("New passwords don't match.");
    }

    let new_hash = security::hash_password(&form.new_password);
    sqlx::query("UPDATE admin_users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
        .bind(&new_hash)
        .bind(admin.id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/").into_response()
}
