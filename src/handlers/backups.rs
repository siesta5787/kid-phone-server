//! Admin-triggered and scheduled backups: a consistent snapshot of the
//! SQLite database, zipped up and stored under `data/backups/`.
//!
//! Backup creation itself never needs root - it only touches `data/`, which
//! this process can already write to - so scheduling lives entirely in this
//! process as a background task (see `run_scheduled_backups` in main.rs),
//! unlike the OS/Tailscale scheduler which needs a separate root component.
//! The one piece that *does* need root is copying backups to an external
//! drive (outside `data/`), which the root scheduler in install.sh handles.

use askama::Template;
use axum::Extension;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse};
use serde::Deserialize;
use std::io::Write;

use crate::AppState;
use crate::security::{self, CurrentAdmin};

const BACKUP_DIR: &str = "data/backups";
const SCHEDULE_FILE: &str = "data/backup_schedule.conf";
const LAST_RUN_FILE: &str = "data/backup_schedule_last_run";
const EXTERNAL_MOUNT: &str = "/mnt/kid-phone-server-backup";
const LIVE_MIRROR_DB: &str = "data/live_mirror.db";
const FLAG_FILE: &str = "data/update_requested";

struct BackupRow {
    filename: String,
    size_display: String,
    created_display: String,
}

#[derive(Clone)]
pub struct BackupScheduleConfig {
    frequency: String,
    day_of_week: String,
    day_of_month: String,
    backup_time: String,
    retention_count: String,
    external_copy_enabled: bool,
    continuous_mirror_enabled: bool,
}

impl BackupScheduleConfig {
    fn defaults() -> Self {
        BackupScheduleConfig {
            frequency: "daily".to_string(),
            day_of_week: "0".to_string(),
            day_of_month: "1".to_string(),
            backup_time: "02:00".to_string(),
            retention_count: "14".to_string(),
            external_copy_enabled: false,
            continuous_mirror_enabled: false,
        }
    }

    pub async fn load() -> Self {
        let Ok(contents) = tokio::fs::read_to_string(SCHEDULE_FILE).await else {
            return Self::defaults();
        };
        let mut config = Self::defaults();
        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_string();
            match key.trim() {
                "FREQUENCY" => config.frequency = value,
                "DAY_OF_WEEK" => config.day_of_week = value,
                "DAY_OF_MONTH" => config.day_of_month = value,
                "BACKUP_TIME" => config.backup_time = value,
                "RETENTION_COUNT" => config.retention_count = value,
                "EXTERNAL_COPY_ENABLED" => config.external_copy_enabled = value == "true",
                "CONTINUOUS_MIRROR_ENABLED" => config.continuous_mirror_enabled = value == "true",
                _ => {}
            }
        }
        config
    }

    fn to_file_contents(&self) -> String {
        format!(
            "FREQUENCY={}\nDAY_OF_WEEK={}\nDAY_OF_MONTH={}\nBACKUP_TIME={}\nRETENTION_COUNT={}\nEXTERNAL_COPY_ENABLED={}\nCONTINUOUS_MIRROR_ENABLED={}\n",
            self.frequency,
            self.day_of_week,
            self.day_of_month,
            self.backup_time,
            self.retention_count,
            self.external_copy_enabled,
            self.continuous_mirror_enabled,
        )
    }

    fn retention_count(&self) -> Option<usize> {
        self.retention_count
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
    }

    /// Plain-language readout of what's actually configured right now -
    /// scheduled backups run unconditionally as a background task from the
    /// moment the app starts (there's no separate "enable scheduling"
    /// toggle, just these settings, which default to daily/02:00/keep-14 if
    /// this file has never been saved), so without this an admin who set it
    /// up once has no way to check months later what it's actually doing.
    fn summary(&self) -> String {
        let when = match self.frequency.as_str() {
            "weekly" => format!(
                "every {} at {}",
                day_of_week_name(&self.day_of_week),
                self.backup_time
            ),
            "monthly" => format!(
                "on day {} of the month at {}",
                self.day_of_month, self.backup_time
            ),
            _ => format!("daily at {}", self.backup_time),
        };
        let retention = match self.retention_count() {
            Some(n) => format!("keeping the last {n}"),
            None => "keeping all of them (no automatic deletion)".to_string(),
        };
        let external = if self.external_copy_enabled {
            "on"
        } else {
            "off"
        };
        let mirror = if self.continuous_mirror_enabled {
            "on"
        } else {
            "off"
        };
        format!(
            "Backing up {when}, {retention}. Copy to external drive: {external}. Continuous mirror: {mirror}."
        )
    }
}

pub(crate) fn day_of_week_name(day_of_week: &str) -> &'static str {
    match day_of_week {
        "0" => "Sunday",
        "1" => "Monday",
        "2" => "Tuesday",
        "3" => "Wednesday",
        "4" => "Thursday",
        "5" => "Friday",
        "6" => "Saturday",
        _ => "Sunday",
    }
}

async fn external_drive_mounted() -> bool {
    tokio::process::Command::new("mountpoint")
        .args(["-q", EXTERNAL_MOUNT])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn is_safe_backup_filename(name: &str) -> bool {
    name.starts_with("backup-")
        && name.ends_with(".zip")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
}

async fn list_backup_filenames() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(BACKUP_DIR).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let filename = entry.file_name().to_string_lossy().to_string();
            if is_safe_backup_filename(&filename) {
                names.push(filename);
            }
        }
    }
    names.sort();
    names
}

/// Deletes the oldest backups beyond `retention_count` (filenames are
/// timestamp-prefixed, so lexical order is chronological order).
pub async fn prune_old_backups(retention_count: usize) {
    let names = list_backup_filenames().await;
    if names.len() <= retention_count {
        return;
    }
    for name in &names[..names.len() - retention_count] {
        let _ = tokio::fs::remove_file(format!("{BACKUP_DIR}/{name}")).await;
    }
}

fn build_backup_zip(db_snapshot_path: &str, zip_path: &str) -> std::io::Result<()> {
    let file = std::fs::File::create(zip_path)?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    writer.start_file("kidphone.db", options)?;
    writer.write_all(&std::fs::read(db_snapshot_path)?)?;

    writer.finish()?;
    Ok(())
}

/// Creates a full backup (a DB snapshot, zipped). Used by both the
/// admin-triggered handler and the background scheduled-backup task, so the
/// actual backup logic only needs to be reviewed/maintained in one place.
pub async fn perform_backup(state: &AppState) -> Result<String, String> {
    tokio::fs::create_dir_all(BACKUP_DIR)
        .await
        .map_err(|_| "Couldn't create the backups folder.".to_string())?;

    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let snapshot_path = format!("{BACKUP_DIR}/tmp-{timestamp}.db");
    let zip_filename = format!("backup-{timestamp}.zip");
    let zip_path = format!("{BACKUP_DIR}/{zip_filename}");

    // VACUUM INTO takes a consistent, complete snapshot of the live database
    // (including anything only committed to the WAL so far) without needing
    // to stop the app or risk a torn read from copying the file directly.
    let vacuum_result = sqlx::query("VACUUM INTO ?")
        .bind(&snapshot_path)
        .execute(&state.db)
        .await;

    if let Err(e) = vacuum_result {
        let _ = tokio::fs::remove_file(&snapshot_path).await;
        return Err(format!("Snapshot failed: {e}"));
    }

    let snapshot_path_for_zip = snapshot_path.clone();
    let zip_path_for_zip = zip_path.clone();
    let zip_result = tokio::task::spawn_blocking(move || {
        build_backup_zip(&snapshot_path_for_zip, &zip_path_for_zip)
    })
    .await;

    let _ = tokio::fs::remove_file(&snapshot_path).await;

    match zip_result {
        Ok(Ok(())) => Ok(zip_filename),
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&zip_path).await;
            Err(format!("Failed to build backup zip: {e}"))
        }
        Err(e) => Err(format!("Backup zip task panicked: {e}")),
    }
}

#[derive(Template)]
#[template(path = "backups.html")]
struct BackupsTemplate {
    title: String,
    backups: Vec<BackupRow>,
    success: Option<String>,
    error: Option<String>,
    schedule: BackupScheduleConfig,
    schedule_summary: String,
    external_mount: String,
    external_drive_mounted: bool,
    removable_drives: Vec<RemovableDrive>,
}

async fn render_backups(success: Option<String>, error: Option<String>) -> Html<String> {
    let mut backups: Vec<BackupRow> = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(BACKUP_DIR).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let filename = entry.file_name().to_string_lossy().to_string();
            if !is_safe_backup_filename(&filename) {
                continue;
            }
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            // The filename's own timestamp (e.g. backup-20260714-140000.zip)
            // is generated from chrono::Local::now() in perform_backup above -
            // format this the same way (Local, not UTC) so the date shown
            // here always matches the date in the filename next to it.
            let created_display = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| {
                    chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                })
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string()
                })
                .unwrap_or_default();
            backups.push(BackupRow {
                filename,
                size_display: human_size(meta.len()),
                created_display,
            });
        }
    }
    backups.sort_by(|a, b| b.filename.cmp(&a.filename));

    let schedule = BackupScheduleConfig::load().await;
    let schedule_summary = schedule.summary();

    Html(
        BackupsTemplate {
            title: "Backups".to_string(),
            backups,
            success,
            error,
            schedule,
            schedule_summary,
            external_mount: EXTERNAL_MOUNT.to_string(),
            external_drive_mounted: external_drive_mounted().await,
            removable_drives: list_removable_drives().await,
        }
        .render()
        .unwrap(),
    )
}

pub async fn list_backups() -> impl IntoResponse {
    render_backups(None, None).await
}

pub async fn create_backup(State(state): State<AppState>) -> impl IntoResponse {
    match perform_backup(&state).await {
        Ok(_) => {
            let schedule = BackupScheduleConfig::load().await;
            if let Some(retention) = schedule.retention_count() {
                prune_old_backups(retention).await;
            }
            render_backups(Some("Backup created.".to_string()), None)
                .await
                .into_response()
        }
        Err(e) => {
            tracing::error!("manual backup failed: {e}");
            render_backups(
                None,
                Some("Something went wrong creating the backup.".to_string()),
            )
            .await
            .into_response()
        }
    }
}

pub async fn download_backup(Path(filename): Path<String>) -> impl IntoResponse {
    if !is_safe_backup_filename(&filename) {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    match tokio::fs::read(format!("{BACKUP_DIR}/{filename}")).await {
        Ok(bytes) => {
            let headers = [
                (header::CONTENT_TYPE, "application/zip".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
            ];
            (headers, bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

pub async fn delete_backup(Path(filename): Path<String>) -> impl IntoResponse {
    if is_safe_backup_filename(&filename) {
        let _ = tokio::fs::remove_file(format!("{BACKUP_DIR}/{filename}")).await;
    }
    render_backups(Some("Backup deleted.".to_string()), None).await
}

#[derive(Deserialize)]
pub struct BackupScheduleForm {
    frequency: String,
    day_of_week: String,
    day_of_month: String,
    backup_time: String,
    retention_count: String,
    external_copy_enabled: Option<String>,
    continuous_mirror_enabled: Option<String>,
}

const VALID_FREQUENCIES: [&str; 3] = ["daily", "weekly", "monthly"];

pub async fn save_backup_schedule(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    axum::Form(form): axum::Form<BackupScheduleForm>,
) -> impl IntoResponse {
    if !VALID_FREQUENCIES.contains(&form.frequency.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            render_backups(None, Some("Invalid frequency.".to_string())).await,
        )
            .into_response();
    }
    let day_of_week: i32 = form.day_of_week.trim().parse().unwrap_or(0).clamp(0, 6);
    let day_of_month: i32 = form.day_of_month.trim().parse().unwrap_or(1).clamp(1, 28);
    let backup_time = if form.backup_time.trim().is_empty() {
        "02:00".to_string()
    } else {
        form.backup_time.trim().to_string()
    };
    let retention_count: i64 = form
        .retention_count
        .trim()
        .parse()
        .unwrap_or(14)
        .clamp(0, 3650);

    let config = BackupScheduleConfig {
        frequency: form.frequency,
        day_of_week: day_of_week.to_string(),
        day_of_month: day_of_month.to_string(),
        backup_time,
        retention_count: retention_count.to_string(),
        external_copy_enabled: form.external_copy_enabled.is_some(),
        continuous_mirror_enabled: form.continuous_mirror_enabled.is_some(),
    };

    let message = if tokio::fs::write(SCHEDULE_FILE, config.to_file_contents())
        .await
        .is_ok()
    {
        security::record_security_event(
            &state.db,
            "backup_schedule_changed",
            Some(&admin.username),
            None,
            None,
        )
        .await;
        "Backup schedule saved.".to_string()
    } else {
        "Couldn't save the schedule.".to_string()
    };

    render_backups(Some(message), None).await.into_response()
}

/// Background task (spawned once at startup, see main.rs) that creates a
/// backup when the configured schedule says it's due, and prunes old
/// backups per the retention setting. Entirely in-process since backup
/// creation only touches data/, which this process already owns - no root
/// component needed, unlike the OS/Tailscale scheduler.
pub async fn run_scheduled_backups(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    loop {
        interval.tick().await;

        let schedule = BackupScheduleConfig::load().await;
        if !is_due(&schedule).await {
            continue;
        }

        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        if tokio::fs::write(LAST_RUN_FILE, &today).await.is_err() {
            tracing::warn!("couldn't write backup schedule last-run marker, skipping this cycle");
            continue;
        }

        match perform_backup(&state).await {
            Ok(filename) => {
                tracing::info!("scheduled backup created: {filename}");
                if let Some(retention) = schedule.retention_count() {
                    prune_old_backups(retention).await;
                }
            }
            Err(e) => tracing::error!("scheduled backup failed: {e}"),
        }
    }
}

async fn is_due(schedule: &BackupScheduleConfig) -> bool {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let last_run = tokio::fs::read_to_string(LAST_RUN_FILE)
        .await
        .unwrap_or_default();
    if last_run.trim() == today {
        return false;
    }

    use chrono::{Datelike, Timelike};
    let now = chrono::Local::now();
    match schedule.frequency.as_str() {
        "weekly" => {
            let configured: u32 = schedule.day_of_week.parse().unwrap_or(0);
            // chrono's weekday: Mon=0..Sun=6; our config uses Sun=0..Sat=6
            let today_dow = now.weekday().num_days_from_sunday();
            if today_dow != configured {
                return false;
            }
        }
        "monthly" => {
            let configured: u32 = schedule.day_of_month.parse().unwrap_or(1);
            if now.day() != configured {
                return false;
            }
        }
        _ => {}
    }

    let Some((hour_str, minute_str)) = schedule.backup_time.split_once(':') else {
        return false;
    };
    let (Ok(target_hour), Ok(target_minute)) = (
        hour_str.trim().parse::<i64>(),
        minute_str.trim().parse::<i64>(),
    ) else {
        return false;
    };
    let target_minutes = target_hour * 60 + target_minute;
    let now_minutes = now.hour() as i64 * 60 + now.minute() as i64;
    let diff = now_minutes - target_minutes;
    (0..5).contains(&diff)
}

/// Background task: keeps `data/live_mirror.db` refreshed as a consistent,
/// up-to-date snapshot of the live database, every couple of minutes - a
/// much tighter recovery point than the named point-in-time backups above.
/// Only does anything if continuous mirroring is actually enabled, since
/// otherwise this would just burn CPU/IO on a Pi for no benefit (a snapshot
/// refreshed on the same SD card the original lives on protects against
/// nothing on its own - the value is entirely in the root scheduler mirroring
/// this file out to external media, see deploy/install.sh's backup_sync.sh).
///
/// Written to a temp path and renamed into place atomically, so the external
/// copy step (a separate process) can never read a half-written file.
pub async fn run_live_mirror(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(90));
    loop {
        interval.tick().await;

        let schedule = BackupScheduleConfig::load().await;
        if !schedule.continuous_mirror_enabled {
            continue;
        }

        let tmp_path = format!("{LIVE_MIRROR_DB}.tmp");
        let vacuum_result = sqlx::query("VACUUM INTO ?")
            .bind(&tmp_path)
            .execute(&state.db)
            .await;

        match vacuum_result {
            Ok(_) => {
                if let Err(e) = tokio::fs::rename(&tmp_path, LIVE_MIRROR_DB).await {
                    tracing::warn!("live mirror: couldn't rename snapshot into place: {e}");
                }
            }
            Err(e) => {
                tracing::warn!("live mirror snapshot failed: {e}");
                let _ = tokio::fs::remove_file(&tmp_path).await;
            }
        }
    }
}

#[derive(Clone)]
pub struct RemovableDrive {
    device: String,
    size_display: String,
}

/// The block device backing a mount point, with any trailing partition
/// number stripped (e.g. `/dev/mmcblk0p2` -> `/dev/mmcblk0`, `/dev/sda1` ->
/// `/dev/sda`) - used to make sure the format-drive feature can never even
/// list the Pi's own boot/root device as a candidate.
async fn base_device_of(mount_point: &str) -> Option<String> {
    let output = tokio::process::Command::new("findmnt")
        .args(["-no", "SOURCE", mount_point])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let source = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if source.is_empty() {
        return None;
    }
    let base = source.trim_end_matches(|c: char| c.is_ascii_digit());
    let base = base.strip_suffix('p').unwrap_or(base);
    Some(base.to_string())
}

/// Lists devices the kernel reports as removable, excluding whatever backs
/// the root and boot filesystems by identity (not just by "removable"
/// classification, which some SD card controllers also report as true) -
/// this list is what both the UI and the format-drive confirmation step
/// treat as safe-to-format candidates.
async fn list_removable_drives() -> Vec<RemovableDrive> {
    let mut drives = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir("/sys/block").await else {
        return drives;
    };

    let root_device = base_device_of("/").await;
    let boot_device = base_device_of("/boot").await;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let removable = tokio::fs::read_to_string(format!("/sys/block/{name}/removable"))
            .await
            .unwrap_or_default();
        if removable.trim() != "1" {
            continue;
        }

        let device = format!("/dev/{name}");
        if Some(&device) == root_device.as_ref() || Some(&device) == boot_device.as_ref() {
            continue;
        }

        let size_sectors: u64 = tokio::fs::read_to_string(format!("/sys/block/{name}/size"))
            .await
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if size_sectors == 0 {
            continue;
        }

        drives.push(RemovableDrive {
            device,
            size_display: human_size(size_sectors * 512),
        });
    }
    drives
}

#[derive(Deserialize)]
pub struct FormatDriveForm {
    device: String,
    confirm_size: String,
}

/// Formats a removable drive as ext4 and mounts it at the external backup
/// path. The actual mkfs/mount work happens root-side (see
/// action_format_drive in deploy/install.sh's actions.sh) - this handler's
/// job is just the two checks that make the request safe to forward: the
/// device must be in the *freshly re-fetched* list of detected removable
/// drives (never trust a stale value from an old page load), and the admin
/// must type the drive's exact displayed size, not just click a button -
/// a plain confirm() dialog is bypassable by anyone who can hit this route
/// directly, and formatting is the one action here with no undo.
/// The root side independently re-validates the device again from scratch
/// regardless of what this handler already checked.
pub async fn format_drive(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    axum::Form(form): axum::Form<FormatDriveForm>,
) -> impl IntoResponse {
    let drives = list_removable_drives().await;
    let Some(drive) = drives.iter().find(|d| d.device == form.device) else {
        return render_backups(
            None,
            Some("That drive is no longer detected - nothing was formatted.".to_string()),
        )
        .await
        .into_response();
    };
    if form.confirm_size.trim() != drive.size_display {
        return render_backups(
            None,
            Some(
                "Confirmation text didn't match the drive size - nothing was formatted."
                    .to_string(),
            ),
        )
        .await
        .into_response();
    }

    let flag_content = format!("format_drive {}", drive.device);
    let message = if tokio::fs::write(FLAG_FILE, &flag_content).await.is_ok() {
        security::record_security_event(
            &state.db,
            "drive_format_triggered",
            Some(&admin.username),
            None,
            Some(&drive.device),
        )
        .await;
        format!(
            "Formatting {} now - this can take a minute. Refresh this page shortly.",
            drive.device
        )
    } else {
        "Couldn't write the request file.".to_string()
    };

    render_backups(Some(message), None).await.into_response()
}

#[derive(Deserialize)]
pub struct RestoreBackupForm {
    confirm_filename: String,
}

/// Restores a named backup: stops the app, swaps the live database for the
/// backup's contents, and restarts - all root-side (see
/// action_restore_backup in deploy/install.sh's actions.sh), since this
/// process can't safely replace the very database file it has open under
/// its own running SQLite connection. This handler's job is just the two
/// checks that make the request safe to forward: the backup must still be
/// in the *freshly re-listed* set of files on disk (never trust a stale
/// page load), and the admin must type the exact filename to confirm - this
/// discards whatever's in the live database right now, so a plain confirm()
/// dialog (bypassable via a direct POST) isn't enough. The root side takes
/// its own safety copy of the current data before overwriting anything, in
/// case the wrong backup gets picked.
pub async fn restore_backup(
    State(state): State<AppState>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Path(filename): Path<String>,
    axum::Form(form): axum::Form<RestoreBackupForm>,
) -> impl IntoResponse {
    if !is_safe_backup_filename(&filename) {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let names = list_backup_filenames().await;
    if !names.contains(&filename) {
        return render_backups(
            None,
            Some("That backup is no longer there - nothing was restored.".to_string()),
        )
        .await
        .into_response();
    }
    if form.confirm_filename.trim() != filename {
        return render_backups(
            None,
            Some("Confirmation text didn't match the filename - nothing was restored.".to_string()),
        )
        .await
        .into_response();
    }

    let flag_content = format!("restore_backup {filename}");
    let message = if tokio::fs::write(FLAG_FILE, &flag_content).await.is_ok() {
        security::record_security_event(
            &state.db,
            "backup_restore_triggered",
            Some(&admin.username),
            None,
            Some(&filename),
        )
        .await;
        "Restoring now - the app will stop, swap in the backup, and restart. \
         This can take a minute; the app will be unreachable until it's done."
            .to_string()
    } else {
        "Couldn't write the request file.".to_string()
    };

    render_backups(Some(message), None).await.into_response()
}

/// Accepts an uploaded backup zip - e.g. one downloaded earlier and saved
/// elsewhere, or recovered from the external drive after this Pi's own copy
/// was lost - and adds it to the list above so it can be restored like any
/// other backup. Never trusts the browser-supplied filename or the .zip
/// extension alone: the archive is actually opened and checked for a
/// `kidphone.db` entry before being accepted.
pub async fn upload_backup(mut multipart: axum::extract::Multipart) -> impl IntoResponse {
    let Ok(Some(field)) = multipart.next_field().await else {
        return render_backups(None, Some("No file was uploaded.".to_string()))
            .await
            .into_response();
    };
    let Ok(bytes) = field.bytes().await else {
        return render_backups(None, Some("Couldn't read the uploaded file.".to_string()))
            .await
            .into_response();
    };
    if bytes.is_empty() {
        return render_backups(None, Some("That file is empty.".to_string()))
            .await
            .into_response();
    }

    let bytes_for_check = bytes.clone();
    let valid = tokio::task::spawn_blocking(move || {
        let cursor = std::io::Cursor::new(&bytes_for_check[..]);
        zip::ZipArchive::new(cursor)
            .ok()
            .is_some_and(|mut archive| archive.by_name("kidphone.db").is_ok())
    })
    .await
    .unwrap_or(false);

    if !valid {
        return render_backups(
            None,
            Some(
                "That doesn't look like a Kids Device MDM backup (couldn't find \
                 kidphone.db inside the zip)."
                    .to_string(),
            ),
        )
        .await
        .into_response();
    }

    if tokio::fs::create_dir_all(BACKUP_DIR).await.is_err() {
        return render_backups(
            None,
            Some("Couldn't create the backups folder.".to_string()),
        )
        .await
        .into_response();
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let filename = format!("backup-{timestamp}-uploaded-{nanos}.zip");
    let path = format!("{BACKUP_DIR}/{filename}");

    let message = if tokio::fs::write(&path, &bytes).await.is_ok() {
        format!("Uploaded and added to the list below as {filename}.")
    } else {
        "Couldn't save the uploaded file.".to_string()
    };

    render_backups(Some(message), None).await.into_response()
}
