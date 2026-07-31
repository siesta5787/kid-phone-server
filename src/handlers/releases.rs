use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::response::{Html, IntoResponse, Redirect};

use crate::AppState;
use crate::models::LauncherRelease;
use crate::security::generate_device_token;

const RELEASES_DIR: &str = "data/launcher_releases";

#[derive(Template)]
#[template(path = "apps_list.html")]
struct AppsListTemplate {
    title: String,
    current: Option<LauncherRelease>,
}

/// The Apps tab - a list of installable apps, one card each. Only "Kids
/// Launcher" exists today, but this is deliberately a list+detail structure
/// (mirroring how Devices already works) so a second app has somewhere to
/// go later without another restructuring.
pub async fn list_apps(State(state): State<AppState>) -> impl IntoResponse {
    let current = sqlx::query_as::<_, LauncherRelease>(
        "SELECT * FROM launcher_releases ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    Html(
        AppsListTemplate {
            title: "Apps".to_string(),
            current,
        }
        .render()
        .unwrap(),
    )
}

#[derive(Template)]
#[template(path = "releases.html")]
struct ReleasesTemplate {
    title: String,
    current: Option<LauncherRelease>,
    history: Vec<LauncherRelease>,
    error: Option<String>,
}

pub async fn list_releases(State(state): State<AppState>) -> impl IntoResponse {
    render(&state, None).await
}

async fn render(state: &AppState, error: Option<String>) -> axum::response::Response {
    let releases =
        sqlx::query_as::<_, LauncherRelease>("SELECT * FROM launcher_releases ORDER BY id DESC")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let mut releases = releases.into_iter();
    let current = releases.next();
    let history = releases.collect();

    Html(
        ReleasesTemplate {
            title: "Kids Launcher".to_string(),
            current,
            history,
            error,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// A random on-disk filename, not the browser-supplied one - same pattern used for every other
/// uploaded file in this style of app, avoids trusting client input for a filesystem path.
/// Reuses the device-token generator purely for its randomness, not as a credential here.
fn random_filename() -> String {
    format!("{}.apk", generate_device_token())
}

pub async fn upload_release(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut version_code: Option<i64> = None;
    let mut version_name: Option<String> = None;
    let mut apk_bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "version_code" => {
                version_code = field.text().await.ok().and_then(|s| s.trim().parse().ok());
            }
            "version_name" => {
                version_name = field.text().await.ok().map(|s| s.trim().to_string());
            }
            "apk" => {
                apk_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
        }
    }

    let (Some(version_code), Some(version_name), Some(apk_bytes)) =
        (version_code, version_name, apk_bytes)
    else {
        return render(
            &state,
            Some("Fill in the version code, version name, and choose a file.".to_string()),
        )
        .await;
    };

    if apk_bytes.is_empty() || version_name.is_empty() {
        return render(
            &state,
            Some("Fill in the version code, version name, and choose a file.".to_string()),
        )
        .await;
    }

    tokio::fs::create_dir_all(RELEASES_DIR).await.ok();
    let filename = random_filename();
    let file_path = format!("{RELEASES_DIR}/{filename}");
    if tokio::fs::write(&file_path, &apk_bytes).await.is_err() {
        return render(
            &state,
            Some("Failed to save the uploaded file.".to_string()),
        )
        .await;
    }

    sqlx::query(
        "INSERT INTO launcher_releases (version_code, version_name, file_path) VALUES (?, ?, ?)",
    )
    .bind(version_code)
    .bind(&version_name)
    .bind(&file_path)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to("/apps/launcher").into_response()
}

pub async fn delete_release(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Ok(Some(release)) =
        sqlx::query_as::<_, LauncherRelease>("SELECT * FROM launcher_releases WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
    {
        tokio::fs::remove_file(&release.file_path).await.ok();
    }

    sqlx::query("DELETE FROM launcher_releases WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/apps/launcher")
}
