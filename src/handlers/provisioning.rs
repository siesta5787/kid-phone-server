use askama::Template;
use axum::Form;
use axum::response::{Html, IntoResponse};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::Serialize;

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

/// Field names are Android's own long-form `PROVISIONING_*` extra keys -
/// this struct's only job is producing the exact JSON shape
/// `ManagedProvisioning` expects. The whole-APK package checksum
/// (`PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM`) is deliberately omitted -
/// it changes every release (unlike the signature checksum, which is tied
/// to the signing key, not the build), would need recomputing and
/// republishing here on every push, and is optional: the signature checksum
/// plus HTTPS transport already establish trust in what's downloaded.
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
}

#[derive(Template)]
#[template(path = "provision_qr.html")]
struct ProvisionQrTemplate {
    title: String,
    qr_svg: Option<String>,
    wifi_ssid: String,
}

pub async fn provision_form() -> impl IntoResponse {
    Html(
        ProvisionQrTemplate {
            title: "Provision a new device".to_string(),
            qr_svg: None,
            wifi_ssid: String::new(),
        }
        .render()
        .unwrap(),
    )
}

#[derive(serde::Deserialize)]
pub struct ProvisionFormInput {
    #[serde(default)]
    wifi_ssid: String,
    #[serde(default)]
    wifi_password: String,
}

pub async fn generate_qr(Form(form): Form<ProvisionFormInput>) -> impl IntoResponse {
    let ssid = form.wifi_ssid.trim();
    let password = form.wifi_password.trim();

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
    };

    let json = serde_json::to_string(&payload).expect("provisioning payload always serializes");
    let code = QrCode::new(json.as_bytes()).expect("provisioning payload always fits a QR code");
    let svg_markup = code
        .render()
        .min_dimensions(320, 320)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Html(
        ProvisionQrTemplate {
            title: "Provision a new device".to_string(),
            qr_svg: Some(svg_markup),
            wifi_ssid: ssid.to_string(),
        }
        .render()
        .unwrap(),
    )
}
