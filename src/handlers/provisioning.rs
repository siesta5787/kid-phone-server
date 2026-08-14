use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::models::{Device, ProvisioningSettings};

/// Android's standard zero-touch Device Owner provisioning flow: on a
/// factory-reset device, tap the Welcome screen 6 times in the same spot,
/// then scan a QR code encoding this JSON payload. Works on any Android
/// device whose setup wizard implements the standard `ManagedProvisioning`
/// hand-off (stock Android, most custom ROMs) - notably, as of this writing,
/// NOT on GrapheneOS, whose own setup wizard has no `ManagedProvisioning`
/// trigger of any kind (QR or NFC) built in yet - see
/// github.com/GrapheneOS/platform_packages_apps_SetupWizard2/pull/40
/// (open, unmerged). Built anyway so it works everywhere else already, and
/// on GrapheneOS the moment that PR (or equivalent) lands.
///
/// The same QR/JSON is also read by the launcher's own in-app "Scan setup QR" flow
/// (`ui/settings/launcher/SettingsFragmentLauncher` client-side) for exactly the
/// GrapheneOS case above - once Device Owner is granted some other way
/// (currently only `adb shell dpm set-device-owner`), scanning this same
/// code applies `admin_extras`'s three fields and enrolls, collapsing what
/// would otherwise be three manual Settings entries into one scan. The
/// native ManagedProvisioning path ignores `PROVISIONING_ADMIN_EXTRAS_BUNDLE`'s
/// contents entirely and just hands it to the app unopened via
/// `DeviceAdminReceiver.onProfileProvisioningComplete` - see
/// `MdmDeviceAdminReceiver.kt` on the client for that side.
///
/// The admin component and signature checksum are effectively constant -
/// they only change if the receiver class is renamed or the signing key is
/// ever rotated, not per release. The download location is the `kids-launcher-mdm`
/// repo's rolling `pre-release` GitHub Release tag (`allowUpdates: true`,
/// always the latest `master` build - see that repo's CLAUDE.md), so this
/// QR code stays valid across every new build with nothing to regenerate.
const ADMIN_COMPONENT: &str =
    "com.kidslauncher.mdm.debug/com.kidslauncher.mdm.server.MdmDeviceAdminReceiver";

/// SHA-256 digest of the signing certificate embedded in every release APK
/// (from the repo's `ANDROID_DEBUG_KEYSTORE` CI secret), base64url-encoded
/// with no padding - the format `PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`
/// requires. Computed via:
///   apksigner verify --print-certs app-debug.apk   # gives the SHA-256 digest as hex
/// then hex -> raw bytes -> base64 -> replace + with -, / with _, strip
/// trailing =. Matches the SHA-1 fingerprint (a70b3763f8a378e3e32da9154b7c2808891bf5f4)
/// already trusted elsewhere in this project's deploy discipline - same
/// certificate, different digest algorithm. Recompute and update this
/// constant if the signing key is ever rotated.
const SIGNATURE_CHECKSUM: &str = "TLXcVaskQBZyh0S88O29PvHa9RaiCCl-7TybpGlbmkg";

const APK_DOWNLOAD_URL: &str =
    "https://github.com/siesta5787/kids-launcher-mdm/releases/download/pre-release/app-debug.apk";

/// android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE's contents - Android's own
/// documented mechanism for passing arbitrary DPC-defined data through zero-touch/QR/NFC
/// provisioning untouched. Field names here are this project's own choice (unlike the
/// top-level PROVISIONING_* keys, which are Android's), read back on the client via
/// `ProvisioningExtras.fromBundle`/`fromJson` - keep both sides in sync if these change.
#[derive(Serialize)]
struct AdminExtras {
    server_url: String,
    tailscale_auth_key: String,
    enrollment_code: String,
}

#[derive(Serialize)]
struct ProvisioningPayload {
    #[serde(rename = "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME")]
    admin_component: &'static str,
    #[serde(rename = "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM")]
    signature_checksum: &'static str,
    #[serde(rename = "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION")]
    download_location: &'static str,
    #[serde(
        rename = "android.app.extra.PROVISIONING_WIFI_SSID",
        skip_serializing_if = "Option::is_none"
    )]
    wifi_ssid: Option<String>,
    #[serde(
        rename = "android.app.extra.PROVISIONING_WIFI_PASSWORD",
        skip_serializing_if = "Option::is_none"
    )]
    wifi_password: Option<String>,
    #[serde(
        rename = "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE",
        skip_serializing_if = "Option::is_none"
    )]
    wifi_security_type: Option<&'static str>,
    #[serde(rename = "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE")]
    admin_extras: AdminExtras,
}

#[derive(Template)]
#[template(path = "provision_qr.html")]
struct ProvisionQrTemplate {
    title: String,
    device: Device,
    qr_svg: String,
    missing_server_url: bool,
    wifi_ssid: String,
}

#[derive(Deserialize, Default)]
pub struct ProvisionQueryParams {
    #[serde(default)]
    wifi_ssid: String,
    #[serde(default)]
    wifi_password: String,
}

/// Regenerates this device's enrollment code every time the page loads (same "always fresh"
/// treatment `regenerate_code` already gives the plain-code flow) - simpler than reasoning about
/// whether a previously-generated code is still unexpired, and this page has no reason to prefer
/// reusing an old one. WiFi fields come in as query params from a plain GET form on the page
/// itself (not a separate POST route) so filling them in and regenerating stays one handler.
pub async fn provision_form(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<ProvisionQueryParams>,
) -> impl IntoResponse {
    let code = crate::security::generate_enrollment_code();
    sqlx::query(
        "UPDATE devices SET enrollment_code = ?, \
         enrollment_code_expires_at = datetime('now', '+30 minutes') WHERE id = ?",
    )
    .bind(&code)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    let device = sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .expect("device must exist to provision it");

    let settings = sqlx::query_as::<_, ProvisioningSettings>(
        "SELECT * FROM provisioning_settings WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

    let ssid = params.wifi_ssid.trim();
    let password = params.wifi_password.trim();

    let payload = ProvisioningPayload {
        admin_component: ADMIN_COMPONENT,
        signature_checksum: SIGNATURE_CHECKSUM,
        download_location: APK_DOWNLOAD_URL,
        wifi_ssid: if ssid.is_empty() {
            None
        } else {
            Some(ssid.to_string())
        },
        wifi_password: if ssid.is_empty() || password.is_empty() {
            None
        } else {
            Some(password.to_string())
        },
        wifi_security_type: if ssid.is_empty() || password.is_empty() {
            None
        } else {
            Some("WPA")
        },
        admin_extras: AdminExtras {
            server_url: settings.server_url.clone(),
            tailscale_auth_key: settings.tailscale_auth_key,
            enrollment_code: code,
        },
    };

    let json = serde_json::to_string(&payload).expect("provisioning payload always serializes");
    let code = QrCode::new(json.as_bytes()).expect("provisioning payload always fits a QR code");
    let qr_svg = code
        .render()
        .min_dimensions(320, 320)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Html(
        ProvisionQrTemplate {
            title: format!("Provision {}", device.name),
            missing_server_url: settings.server_url.is_empty(),
            wifi_ssid: ssid.to_string(),
            device,
            qr_svg,
        }
        .render()
        .unwrap(),
    )
}
