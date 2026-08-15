use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Extension, Form};
use serde::Deserialize;

use crate::AppState;
use crate::models::{Device, DevicePolicy, DeviceStatus, InstalledApp, TrackedApp};
use crate::security::{self, CurrentAdmin};

/// How long a freshly-generated enrollment code stays valid before it must
/// be regenerated - long enough to walk from the computer to the phone and
/// type it in, short enough that a code shown once on screen isn't a
/// standing credential.
const ENROLLMENT_CODE_MINUTES: i64 = 30;

struct DeviceListRow {
    id: i64,
    name: String,
    status_text: String,
}

#[derive(Template)]
#[template(path = "devices_list.html")]
struct DevicesListTemplate {
    title: String,
    devices: Vec<DeviceListRow>,
}

pub async fn list_devices(State(state): State<AppState>) -> impl IntoResponse {
    let devices = sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let rows = devices
        .into_iter()
        .map(|d| {
            let status_text = if d.enrolled_at.is_none() {
                "Not enrolled yet".to_string()
            } else {
                match &d.last_seen_at {
                    Some(t) => format!("Last seen {t}"),
                    None => "Enrolled, not seen yet".to_string(),
                }
            };
            DeviceListRow {
                id: d.id,
                name: d.name,
                status_text,
            }
        })
        .collect();

    Html(
        DevicesListTemplate {
            title: "Devices".to_string(),
            devices: rows,
        }
        .render()
        .unwrap(),
    )
}

#[derive(Template)]
#[template(path = "device_add.html")]
struct DeviceAddTemplate {
    title: String,
}

pub async fn new_device_form() -> impl IntoResponse {
    Html(
        DeviceAddTemplate {
            title: "Add a device".to_string(),
        }
        .render()
        .unwrap(),
    )
}

#[derive(Deserialize)]
pub struct CreateDeviceForm {
    name: String,
}

pub async fn create_device(
    State(state): State<AppState>,
    Form(form): Form<CreateDeviceForm>,
) -> impl IntoResponse {
    let code = security::generate_enrollment_code();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (name, enrollment_code, enrollment_code_expires_at) \
         VALUES (?, ?, datetime('now', ?)) RETURNING id",
    )
    .bind(&form.name)
    .bind(&code)
    .bind(format!("+{ENROLLMENT_CODE_MINUTES} minutes"))
    .fetch_one(&state.db)
    .await
    .expect("failed to create device");

    // Kiosk mode on, with the full always-on feature set, is the default for every newly
    // enrolled device now - previously every new device started wide open, requiring an admin to
    // remember to turn kiosk mode on (and, before that got simplified too, separately check the
    // notifications/power-button boxes) every single time. Still just a starting point, not
    // mandatory: the "Restrict this phone to only the apps allowed below" checkbox on the device's
    // own page is untouched, so unchecking it after enrollment still fully disables kiosk mode.
    sqlx::query(
        "INSERT INTO device_policy (device_id, kiosk_desired, lock_task_features) VALUES (?, 1, ?)",
    )
    .bind(id)
    .bind(DEFAULT_LOCK_TASK_FEATURES)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to(&format!("/devices/{id}"))
}

pub async fn regenerate_code(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let code = security::generate_enrollment_code();
    sqlx::query(
        "UPDATE devices SET enrollment_code = ?, \
         enrollment_code_expires_at = datetime('now', ?) WHERE id = ?",
    )
    .bind(&code)
    .bind(format!("+{ENROLLMENT_CODE_MINUTES} minutes"))
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    Redirect::to(&format!("/devices/{id}"))
}

/// One row in the unified Apps list - either an app the device has actually reported installed
/// (`status` is `Preinstalled` or `Installed`), or a catalog (`tracked_apps`) app it doesn't have
/// yet (`status` is `NotInstalled`). Replaces what used to be two separate lists/cards ("Allowed
/// apps" from `device_status.installed_apps_json`, "Apps to install" from the full `tracked_apps`
/// catalog) - an app that's both installed *and* in the catalog now gets exactly one row, not two
/// independently-checkable ones telling two different, sometimes-contradictory stories.
///
/// `package_name` can be empty only for a manual-upload catalog app nobody's typed a package name
/// for yet - it can never be matched against a real installed app by name, so it always shows as
/// `NotInstalled` until an admin adds one (see `tracked_apps.rs`).
struct UnifiedAppRow {
    package_name: String,
    label: String,
    tracked_app_id: Option<i64>,
    is_launcher: bool,
    checked: bool,
    /// Precomputed display text rather than a template-side call to `status.label()` - lets a
    /// `NotInstalled` row show live download progress ("Installing 42%") instead of the plain
    /// static label when a fresh `device_install_progress` row exists for it - see `view_device`.
    status_label: String,
    /// True exactly when `status_label` carries a live percentage - drives device_detail.html's
    /// self-polling reload (there's no push mechanism to this page, so it has to ask again) rather
    /// than the template trying to parse `status_label`'s text back apart.
    is_installing: bool,
    /// True when the device reported a failed install attempt for this app that hasn't cleared yet
    /// (see `device_install_progress.failed`) - a separate flag from `is_installing` so
    /// device_detail.html can style it distinctly rather than parsing `status_label`'s text.
    install_failed: bool,
    /// Precomputed rather than compared in the template (`status == AppRowStatus::NotInstalled`) -
    /// flags a catalog app that's checked but has nothing to actually push yet (no GitHub release
    /// synced, or a manual-upload app nobody's uploaded a build to yet). Selecting it used to
    /// silently do nothing until a release showed up, with no indication why.
    show_no_release_hint: bool,
}

/// The six parent-facing LockTask features, decoded from/encoded into the
/// raw `lock_task_features` bitmask Android's `setLockTaskFeatures` expects.
/// Not exposing `LOCK_TASK_FEATURE_BLOCK_ACTIVITY_START_IN_TASK` (64) - no
/// clear parent-facing meaning.
const LOCK_FEATURE_SYSTEM_INFO: i64 = 1;
const LOCK_FEATURE_NOTIFICATIONS: i64 = 2;
const LOCK_FEATURE_HOME: i64 = 4;
const LOCK_FEATURE_OVERVIEW: i64 = 8;
const LOCK_FEATURE_GLOBAL_ACTIONS: i64 = 16;
const LOCK_FEATURE_KEYGUARD: i64 = 32;

/// None of the six are admin-configurable anymore - see `update_policy`'s doc comment on why each
/// one is always on whenever kiosk mode is - so this is just the one value `lock_task_features`
/// ever takes for a kiosk-mode device. Used both there and in `create_device`, so a newly enrolled
/// device starts with the exact same features a save from the device detail page would produce.
const DEFAULT_LOCK_TASK_FEATURES: i64 = LOCK_FEATURE_SYSTEM_INFO
    | LOCK_FEATURE_HOME
    | LOCK_FEATURE_OVERVIEW
    | LOCK_FEATURE_KEYGUARD
    | LOCK_FEATURE_NOTIFICATIONS
    | LOCK_FEATURE_GLOBAL_ACTIONS;

/// Bits for `quick_controls_mask` - which switches show up on the launcher's
/// swipe-left-from-home "Quick Controls" screen (see kids-launcher-mdm's
/// `ui/quickcontrols/QuickControlsActivity`), the kid-facing replacement for
/// Android's native Quick Settings shade.
const QUICK_CONTROL_WIFI: i64 = 1;
const QUICK_CONTROL_BLUETOOTH: i64 = 2;
const QUICK_CONTROL_BRIGHTNESS: i64 = 4;

#[derive(Template)]
#[template(path = "device_detail.html")]
struct DeviceDetailTemplate {
    title: String,
    device: Device,
    apps: Vec<UnifiedAppRow>,
    /// Precomputed rather than an `{% if %}` expression in the template - Askama's expression
    /// grammar doesn't support closures, so `apps.iter().any(|a| a.is_installing)` can't be
    /// written directly there.
    any_app_installing: bool,
    pin_configured: bool,
    offline_override_used: bool,
    vpn_filter_enabled: bool,
    quick_control_wifi: bool,
    quick_control_bluetooth: bool,
    quick_control_brightness: bool,
    latest_status: Option<DeviceStatus>,
}

pub async fn view_device(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some(device) = device else {
        return (axum::http::StatusCode::NOT_FOUND, "Device not found").into_response();
    };

    let policy =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(DevicePolicy {
                device_id: id,
                // See the matching comment in device_api::policy - bool::default() is false,
                // but a never-configured device must still show/default to filtering on.
                vpn_filter_enabled: true,
                ..Default::default()
            });

    let latest_status = sqlx::query_as::<_, DeviceStatus>(
        "SELECT * FROM device_status WHERE device_id = ? ORDER BY reported_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let allowed: std::collections::HashSet<String> = policy
        .allowlist_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .unwrap_or_default()
        .into_iter()
        .collect();

    let installed: Vec<InstalledApp> = latest_status
        .as_ref()
        .and_then(|s| s.installed_apps_json.as_deref())
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();

    let all_tracked = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    let selected_app_ids: std::collections::HashSet<i64> =
        sqlx::query_scalar("SELECT tracked_app_id FROM device_tracked_apps WHERE device_id = ?")
            .bind(id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

    // Fresh (not stale) download-progress rows for this device - only ever meaningful for a
    // NotInstalled row below, so this is the only place they're consulted. The 10-minute window
    // matches the client's own in-flight-attempt timeout (TrackedAppUpdateState) for consistency -
    // long enough to cover a slow download, short enough that an abandoned attempt's last-reported
    // percentage doesn't linger looking "in progress" forever.
    let install_progress: std::collections::HashMap<i64, (i64, bool)> =
        sqlx::query_as::<_, (i64, i64, bool)>(
            "SELECT tracked_app_id, percent, failed FROM device_install_progress \
             WHERE device_id = ? AND updated_at > datetime('now', '-10 minutes')",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(tracked_app_id, percent, failed)| (tracked_app_id, (percent, failed)))
        .collect();

    let mut apps: Vec<UnifiedAppRow> = Vec::new();
    let mut seen_packages: std::collections::HashSet<String> = std::collections::HashSet::new();

    // First pass: every app the device actually reports installed (preinstalled or otherwise),
    // matched against the catalog by package name where possible so an app that's both installed
    // *and* trackable still gets exactly one row.
    for app in &installed {
        let tracked_match = all_tracked
            .iter()
            .find(|t| !t.package_name.is_empty() && t.package_name == app.package_name);
        apps.push(UnifiedAppRow {
            status_label: if app.preinstalled {
                "Preinstalled".to_string()
            } else {
                "Installed".to_string()
            },
            is_installing: false,
            install_failed: false,
            checked: allowed.contains(&app.package_name),
            tracked_app_id: tracked_match.map(|t| t.id),
            show_no_release_hint: false,
            package_name: app.package_name.clone(),
            label: app.label.clone(),
            is_launcher: false,
        });
        seen_packages.insert(app.package_name.clone());
    }

    // Second pass: catalog apps not currently installed (including manual-upload apps with no
    // package name typed yet, which can never match an installed app by name) - the launcher's
    // own row is handled separately below, it never belongs here.
    for t in &all_tracked {
        if t.is_launcher {
            continue;
        }
        if !t.package_name.is_empty() && seen_packages.contains(&t.package_name) {
            continue;
        }
        let has_release = t.latest_release_tag.is_some();
        let progress = install_progress.get(&t.id).copied();
        let (status_label, is_installing, install_failed) = match progress {
            Some((_, true)) => ("Install failed".to_string(), false, true),
            Some((percent, false)) => (format!("Installing {percent}%"), true, false),
            None => ("Not installed".to_string(), false, false),
        };
        apps.push(UnifiedAppRow {
            status_label,
            is_installing,
            install_failed,
            checked: selected_app_ids.contains(&t.id),
            tracked_app_id: Some(t.id),
            show_no_release_hint: !has_release,
            package_name: t.package_name.clone(),
            label: t.name.clone(),
            is_launcher: false,
        });
    }

    apps.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));

    // The launcher's own row is pinned first rather than sorted alphabetically with everything
    // else - it's not really "one app among many" the way the rest of this list is, it's the
    // thing enforcing the rest of this list, so calling that out up top reads better than letting
    // it land wherever its name happens to sort.
    if let Some(launcher) = all_tracked.iter().find(|t| t.is_launcher) {
        apps.insert(
            0,
            UnifiedAppRow {
                status_label: "Installed".to_string(),
                is_installing: false,
                install_failed: false,
                checked: true,
                tracked_app_id: Some(launcher.id),
                show_no_release_hint: false,
                package_name: launcher.package_name.clone(),
                label: launcher.name.clone(),
                is_launcher: true,
            },
        );
    }

    let offline_override_used = latest_status
        .as_ref()
        .map(|s| s.offline_override_used)
        .unwrap_or(false);
    let any_app_installing = apps.iter().any(|a| a.is_installing);

    Html(
        DeviceDetailTemplate {
            title: device.name.clone(),
            any_app_installing,
            pin_configured: policy.override_pin_hash.is_some(),
            offline_override_used,
            vpn_filter_enabled: policy.vpn_filter_enabled,
            quick_control_wifi: policy.quick_controls_mask & QUICK_CONTROL_WIFI != 0,
            quick_control_bluetooth: policy.quick_controls_mask & QUICK_CONTROL_BLUETOOTH != 0,
            quick_control_brightness: policy.quick_controls_mask & QUICK_CONTROL_BRIGHTNESS != 0,
            device,
            apps,
            latest_status,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Flips one row of the unified Apps list for one device - a standalone auto-submitting toggle
/// (see device_detail.html), not folded into the big `update_policy` form like the rest of a
/// device's settings. Deliberately different from that form's "edit several things, then click
/// Save" pattern - live testing (back when this was two separate lists) showed an admin checking
/// a box and *not* separately scrolling down to hit an unrelated form's Save button, since every
/// other on/off switch in this app already auto-saves on change. The launcher's own row never
/// reaches this handler - its checkbox in the template is `disabled`, and a disabled control can't
/// be interacted with to submit a request in the first place.
///
/// Takes both `package_name` and `tracked_app_id` as (independently optional) form fields rather
/// than a single path-scoped id, since a row here might be catalog-only (no package name on file
/// yet), install-only (a preinstalled or otherwise-installed app never added to the catalog), or
/// both - see `UnifiedAppRow`'s own doc comment. At least one is expected to be present; a toggle
/// with neither is a no-op.
///
/// Checking: adds the `device_tracked_apps` row if there's a catalog entry to track (so a
/// not-yet-installed app actually gets pushed, and an already-installed one starts picking up
/// future updates), and allows the package if there's one on file - both no-ops if already in
/// that state.
///
/// Unchecking: removes the `device_tracked_apps` row and disallows the package the same way.
/// Whether it *also* queues a silent uninstall depends on current on-device status - a preinstalled
/// app can never actually be uninstalled (only suspended/hidden), so that step is skipped entirely
/// for one; any other currently-installed package gets queued via `device_pending_uninstalls`,
/// same as before this was generalized from tracked-apps-only.
pub async fn toggle_app(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let checked = form.contains_key("selected");
    let package_name = form
        .get("package_name")
        .map(String::as_str)
        .unwrap_or("")
        .to_string();
    let tracked_app_id: Option<i64> = form.get("tracked_app_id").and_then(|s| s.parse().ok());

    if checked {
        if let Some(tid) = tracked_app_id {
            sqlx::query(
                "INSERT OR IGNORE INTO device_tracked_apps (device_id, tracked_app_id) VALUES (?, ?)",
            )
            .bind(id)
            .bind(tid)
            .execute(&state.db)
            .await
            .ok();
        }
        if !package_name.is_empty() {
            add_to_allowlist(&state, id, &package_name).await;
        }
    } else {
        if let Some(tid) = tracked_app_id {
            sqlx::query(
                "DELETE FROM device_tracked_apps WHERE device_id = ? AND tracked_app_id = ?",
            )
            .bind(id)
            .bind(tid)
            .execute(&state.db)
            .await
            .ok();
        }
        if !package_name.is_empty() {
            remove_from_allowlist(&state, id, &package_name).await;
            let (installed, preinstalled) = installed_app_status(&state, id, &package_name).await;
            if installed && !preinstalled {
                sqlx::query(
                    "INSERT OR IGNORE INTO device_pending_uninstalls (device_id, package_name) \
                     VALUES (?, ?)",
                )
                .bind(id)
                .bind(&package_name)
                .execute(&state.db)
                .await
                .ok();
            }
        }
    }

    let _ = state.command_notify.send(id);
    Redirect::to(&format!("/devices/{id}"))
}

/// Whether the device's most recent status report lists this package as installed, and if so,
/// whether it was reported as a preinstalled (`ApplicationInfo.FLAG_SYSTEM`) app - gates both
/// whether [toggle_app] has anything to uninstall at all, and whether it should even try (a
/// preinstalled app can only ever be suspended/hidden, never actually removed).
async fn installed_app_status(
    state: &AppState,
    device_id: i64,
    package_name: &str,
) -> (bool, bool) {
    let json: Option<String> = sqlx::query_scalar(
        "SELECT installed_apps_json FROM device_status WHERE device_id = ? \
         ORDER BY reported_at DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let installed: Vec<InstalledApp> = json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    match installed.iter().find(|a| a.package_name == package_name) {
        Some(a) => (true, a.preinstalled),
        None => (false, false),
    }
}

/// Adds one package to a device's allowlist if it isn't already there. Used by
/// [toggle_app] - see its own doc comment for why. `updated_at` is bumped like every other
/// `device_policy` write, so the "changed since last sync" nudge story stays consistent even though
/// this isn't going through the normal `update_policy` form save.
pub(crate) async fn add_to_allowlist(state: &AppState, device_id: i64, package_name: &str) {
    let current: Option<String> =
        sqlx::query_scalar("SELECT allowlist_json FROM device_policy WHERE device_id = ?")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let mut packages: Vec<String> = current
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();

    if packages.iter().any(|p| p == package_name) {
        return;
    }
    packages.push(package_name.to_string());

    let Ok(json) = serde_json::to_string(&packages) else {
        return;
    };
    sqlx::query(
        "UPDATE device_policy SET allowlist_json = ?, updated_at = datetime('now') \
         WHERE device_id = ?",
    )
    .bind(&json)
    .bind(device_id)
    .execute(&state.db)
    .await
    .ok();
}

/// Removes one package from a device's allowlist if present - the uncheck-side counterpart to
/// [add_to_allowlist], used by [toggle_app].
async fn remove_from_allowlist(state: &AppState, device_id: i64, package_name: &str) {
    let current: Option<String> =
        sqlx::query_scalar("SELECT allowlist_json FROM device_policy WHERE device_id = ?")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let mut packages: Vec<String> = current
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();

    let original_len = packages.len();
    packages.retain(|p| p != package_name);
    if packages.len() == original_len {
        return;
    }

    let Ok(json) = serde_json::to_string(&packages) else {
        return;
    };
    sqlx::query(
        "UPDATE device_policy SET allowlist_json = ?, updated_at = datetime('now') \
         WHERE device_id = ?",
    )
    .bind(&json)
    .bind(device_id)
    .execute(&state.db)
    .await
    .ok();
}

/// Handles everything on a device's page *except* the Apps list, which is now its own set of
/// per-row [toggle_app] saves - this form used to also carry "Allowed apps" checkboxes, which
/// needed the allowlist-reconciliation dance now gone from here entirely (see git history if that
/// logic is ever needed for reference). `Form<HashMap<...>>` is safe to use directly again now
/// that nothing here is a repeated-name checkbox group.
pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    Form(fields): Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();

    // Home, status bar info, recents, notifications, and the power button menu don't let a kid
    // reach anything outside the pinned/allowed app set - Home just re-navigates within it,
    // recents only lists apps already in it, status bar info is read-only, notifications can only
    // come from allowed apps, and the power button menu just offers power off/restart/etc, not
    // app access. None of these are real restrictions, just navigation/system convenience, so
    // they're always on rather than admin-configurable - previously notifications and the power
    // button menu had their own checkboxes, but there was never a real reason for a parent to want
    // either one off while kiosk mode is on, so those were removed (see device_detail.html).
    //
    // Keyguard is also forced on unconditionally, for a very different reason: a real device got
    // stuck at boot after GrapheneOS's own auto-reboot-after-inactivity feature re-locked storage
    // (Before First Unlock/FBE) while this bit was off. LOCK_TASK_FEATURE_KEYGUARD is disabled by
    // default in lock-task mode, and that suppression is a DevicePolicyManager-level setting
    // enforced by system_server itself - it keeps applying even before the device is decrypted,
    // when this app's own process can't run at all (its components aren't resolvable pre-unlock).
    // With keyguard off and this app the exclusive enforced Home app, there was no lock screen to
    // enter a PIN into *and* no launcher available either - a total deadlock recoverable only via
    // hardware-level recovery mode. Forcing this bit on guarantees Android's own (already
    // direct-boot-aware) keyguard can always come up after any reboot, regardless of kiosk
    // config. The real tradeoff: every kiosk-mode device now also requires a PIN to resume from
    // sleep, not just after a reboot - Android doesn't expose those as separate bits.
    let lock_task_features: i64 = DEFAULT_LOCK_TASK_FEATURES;

    let mut quick_controls_mask: i64 = 0;
    if fields.contains_key("quick_control_wifi") {
        quick_controls_mask |= QUICK_CONTROL_WIFI;
    }
    if fields.contains_key("quick_control_bluetooth") {
        quick_controls_mask |= QUICK_CONTROL_BLUETOOTH;
    }
    if fields.contains_key("quick_control_brightness") {
        quick_controls_mask |= QUICK_CONTROL_BRIGHTNESS;
    }

    let vpn_filter_enabled = fields.contains_key("vpn_filter_enabled");

    // The PIN fields are optional on every save (this form saves everything
    // together) - leave the stored hash/salt untouched unless the admin
    // actually typed a new PIN or explicitly asked to clear it, so blank
    // fields on an unrelated save can't silently wipe an already-configured
    // PIN.
    let current =
        sqlx::query_as::<_, DevicePolicy>("SELECT * FROM device_policy WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let current_pin = current.as_ref().and_then(|p| p.override_pin_hash.clone());
    let current_salt = current.as_ref().and_then(|p| p.override_pin_salt.clone());

    let new_pin = field("new_pin");
    let new_pin = new_pin.trim();
    let (override_pin_hash, override_pin_salt, pin_event) = if fields.contains_key("clear_pin") {
        (None, None, Some("override_pin_cleared"))
    } else if !new_pin.is_empty() {
        if new_pin.len() >= 6 && new_pin.chars().all(|c| c.is_ascii_digit()) {
            let (hash, salt) = security::hash_pin(new_pin);
            (Some(hash), Some(salt), Some("override_pin_changed"))
        } else {
            // Invalid PIN typed - ignore it rather than fail the whole save,
            // keeping whatever was already configured.
            (current_pin, current_salt, None)
        }
    } else {
        (current_pin, current_salt, None)
    };

    if let Some(event_type) = pin_event {
        security::record_security_event(
            &state.db,
            event_type,
            Some(&admin.username),
            None,
            Some(&format!("device {id}")),
        )
        .await;
    }

    sqlx::query(
        "UPDATE device_policy SET kiosk_desired = 1, \
         lock_task_features = ?, override_pin_hash = ?, override_pin_salt = ?, \
         quick_controls_mask = ?, vpn_filter_enabled = ?, \
         updated_at = datetime('now') WHERE device_id = ?",
    )
    .bind(lock_task_features)
    .bind(&override_pin_hash)
    .bind(&override_pin_salt)
    .bind(quick_controls_mask)
    .bind(vpn_filter_enabled)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    // Nudges the device to re-sync immediately over the same SSE connection Find My Device uses
    // for ring/lock, rather than waiting out the rest of the background poll interval - the nudge
    // itself carries no data, the device just re-fetches /api/devices/policy on it, so this reuses
    // the exact same dispatch path as a normal scheduled sync.
    let _ = state.command_notify.send(id);

    Redirect::to(&format!("/devices/{id}"))
}

pub async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(_admin): Extension<CurrentAdmin>,
) -> impl IntoResponse {
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    Redirect::to("/")
}
