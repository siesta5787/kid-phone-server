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

struct AppCheckbox {
    package_name: String,
    label: String,
    checked: bool,
}

/// One row per app from the global Apps list (`tracked_apps`), scoped to whether *this* device
/// gets it pushed - see migrations/0013_device_tracked_apps.sql. The launcher's own row is always
/// `checked` and rendered disabled in device_detail.html (also enforced server-side - see
/// `toggle_tracked_app`'s own doc comment) - there's no real-world case for a kid's phone not
/// running the app that enforces every other restriction on it. `has_release` is surfaced so
/// device_detail.html can flag an app that's checked but has nothing to actually push yet (no
/// GitHub release synced, or a manual-upload app nobody's uploaded a build to yet) - selecting it
/// used to silently do nothing until a release showed up, with no indication why.
struct TrackedAppCheckbox {
    id: i64,
    name: String,
    checked: bool,
    is_launcher: bool,
    has_release: bool,
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
    apps: Vec<AppCheckbox>,
    tracked_apps: Vec<TrackedAppCheckbox>,
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

    let apps = installed
        .into_iter()
        .map(|a| AppCheckbox {
            checked: allowed.contains(&a.package_name),
            package_name: a.package_name,
            label: a.label,
        })
        .collect();

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
    let tracked_apps = all_tracked
        .into_iter()
        .map(|a| TrackedAppCheckbox {
            checked: a.is_launcher || selected_app_ids.contains(&a.id),
            id: a.id,
            name: a.name,
            is_launcher: a.is_launcher,
            has_release: a.latest_release_tag.is_some(),
        })
        .collect();

    let offline_override_used = latest_status
        .as_ref()
        .map(|s| s.offline_override_used)
        .unwrap_or(false);

    Html(
        DeviceDetailTemplate {
            title: device.name.clone(),
            pin_configured: policy.override_pin_hash.is_some(),
            offline_override_used,
            vpn_filter_enabled: policy.vpn_filter_enabled,
            quick_control_wifi: policy.quick_controls_mask & QUICK_CONTROL_WIFI != 0,
            quick_control_bluetooth: policy.quick_controls_mask & QUICK_CONTROL_BLUETOOTH != 0,
            quick_control_brightness: policy.quick_controls_mask & QUICK_CONTROL_BRIGHTNESS != 0,
            device,
            apps,
            tracked_apps,
            latest_status,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Flips whether one tracked app is pushed to one device - a standalone auto-submitting toggle
/// (see device_detail.html's "Apps to install" card), not folded into the big `update_policy` form
/// like the rest of a device's settings. Deliberately different from that form's "edit several
/// things, then click Save" pattern - live testing showed an admin checking one of these boxes and
/// *not* separately scrolling down to hit the unrelated form's Save button, since every other
/// on/off switch in this app (tracked_apps.rs's `set_enabled`/`set_include_prereleases`, this
/// file's own quick-toggles elsewhere) already auto-saves on change. The launcher's own row never
/// reaches this handler - its checkbox in the template is `disabled`, and a disabled control can't
/// be interacted with to submit a request in the first place.
///
/// Checking and unchecking are symmetric now, both keyed on the tracked app's package name (a
/// no-op either direction without one on file - see tracked_apps.rs's create/update handlers):
/// checking adds it to the allowlist so a kiosk-mode device doesn't have it pushed-but-invisible
/// until a second manual step; unchecking removes it from the allowlist *and* queues a silent
/// uninstall (`device_pending_uninstalls`) if the device currently reports it installed. Confirmed
/// live this is what an admin actually wants from "uncheck this app" - not "stop pushing updates
/// but leave it on the phone."
pub async fn toggle_tracked_app(
    State(state): State<AppState>,
    Path((id, app_id)): Path<(i64, i64)>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let app = sqlx::query_as::<_, TrackedApp>("SELECT * FROM tracked_apps WHERE id = ?")
        .bind(app_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    if form.contains_key("selected") {
        sqlx::query(
            "INSERT OR IGNORE INTO device_tracked_apps (device_id, tracked_app_id) VALUES (?, ?)",
        )
        .bind(id)
        .bind(app_id)
        .execute(&state.db)
        .await
        .ok();

        if let Some(app) = &app {
            if !app.package_name.is_empty() {
                add_to_allowlist(&state, id, &app.package_name).await;
            }
        }
    } else {
        sqlx::query("DELETE FROM device_tracked_apps WHERE device_id = ? AND tracked_app_id = ?")
            .bind(id)
            .bind(app_id)
            .execute(&state.db)
            .await
            .ok();

        if let Some(app) = &app {
            if !app.package_name.is_empty() {
                remove_from_allowlist(&state, id, &app.package_name).await;
                if is_installed_on_device(&state, id, &app.package_name).await {
                    sqlx::query(
                        "INSERT OR IGNORE INTO device_pending_uninstalls (device_id, package_name) \
                         VALUES (?, ?)",
                    )
                    .bind(id)
                    .bind(&app.package_name)
                    .execute(&state.db)
                    .await
                    .ok();
                }
            }
        }
    }

    let _ = state.command_notify.send(id);
    Redirect::to(&format!("/devices/{id}"))
}

/// Whether the device's most recent status report lists this package as installed - gates queuing
/// an uninstall in [toggle_tracked_app], since there's nothing to uninstall otherwise (and no harm
/// either way; the client silently no-ops uninstalling an already-absent package).
async fn is_installed_on_device(state: &AppState, device_id: i64, package_name: &str) -> bool {
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
    installed.iter().any(|a| a.package_name == package_name)
}

/// Adds one package to a device's allowlist if it isn't already there. Used by
/// [toggle_tracked_app] - see its own doc comment for why. `updated_at` is bumped like every other
/// `device_policy` write, so the "changed since last sync" nudge story stays consistent even though
/// this isn't going through the normal `update_policy` form save.
async fn add_to_allowlist(state: &AppState, device_id: i64, package_name: &str) {
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
/// [add_to_allowlist], used by [toggle_tracked_app].
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

/// Repeated `allowed_packages` checkbox values can't be collected into a
/// `Vec<String>` via axum's built-in `Form` extractor (it deserializes each
/// key as a single scalar, so a form with one or more identically-named
/// fields fails with "expected a sequence") - parsed manually instead.
pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(CurrentAdmin(admin)): Extension<CurrentAdmin>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let mut allowed_packages = Vec::new();
    let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (key, value) in form_urlencoded::parse(&body) {
        if key == "allowed_packages" {
            allowed_packages.push(value.into_owned());
        } else {
            fields.insert(key.into_owned(), value.into_owned());
        }
    }
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();

    // The "Allowed apps" checkboxes on device_detail.html only ever render one row per package the
    // device has actually reported installed (see view_device's `apps`) - so a package that's on
    // the allowlist but not yet installed (e.g. just auto-added by toggle_tracked_app's
    // add_to_allowlist, ahead of the device actually installing it) was never an option on this
    // page and can't have been in the submitted `allowed_packages` list either way. Naively trusting
    // that submitted list as the complete new allowlist would silently drop it - any unrelated
    // save (schedule, WiFi mode, whatever) in the window before the device installs and reports
    // back would erase the pre-authorization.
    //
    // Only preserve entries that are *actually* pending like that - a package name belonging to a
    // tracked app still selected for this device (`device_tracked_apps`) that the device hasn't
    // yet reported as installed. Preserving every not-rendered package unconditionally was tried
    // first and was wrong: it also protects a package that WAS installed and allowed, then got
    // uninstalled (by the kid, or any other way) - that package's checkbox simply stops rendering,
    // so it could never be unchecked again either, and would silently regain kiosk access if ever
    // reinstalled without the admin re-approving it. Restricting the preserve-list to genuinely
    // pending tracked-app installs keeps the original self-cleaning behavior for everything else -
    // an allowed-but-no-longer-installed package still falls out of the allowlist on the next save,
    // same as before this whole pending-preserve mechanism existed.
    let installed_packages: std::collections::HashSet<String> = {
        let json: Option<String> = sqlx::query_scalar(
            "SELECT installed_apps_json FROM device_status WHERE device_id = ? \
             ORDER BY reported_at DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        let installed: Vec<InstalledApp> = json
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok())
            .unwrap_or_default();
        installed.into_iter().map(|a| a.package_name).collect()
    };
    let current_allowlist: Vec<String> = {
        let json: Option<String> =
            sqlx::query_scalar("SELECT allowlist_json FROM device_policy WHERE device_id = ?")
                .bind(id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        json.as_deref()
            .and_then(|j| serde_json::from_str(j).ok())
            .unwrap_or_default()
    };
    let pending_tracked_packages: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT ta.package_name FROM tracked_apps ta \
         JOIN device_tracked_apps dta ON dta.tracked_app_id = ta.id \
         WHERE dta.device_id = ? AND ta.package_name != ''",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();
    let mut final_allowed = allowed_packages.clone();
    for pkg in current_allowlist {
        if !installed_packages.contains(&pkg)
            && !final_allowed.contains(&pkg)
            && pending_tracked_packages.contains(&pkg)
        {
            final_allowed.push(pkg);
        }
    }
    let allowlist_json = serde_json::to_string(&final_allowed).ok();

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
        "UPDATE device_policy SET allowlist_json = ?, kiosk_desired = 1, \
         lock_task_features = ?, override_pin_hash = ?, override_pin_salt = ?, \
         quick_controls_mask = ?, vpn_filter_enabled = ?, \
         updated_at = datetime('now') WHERE device_id = ?",
    )
    .bind(&allowlist_json)
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
