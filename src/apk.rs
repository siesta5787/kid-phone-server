//! Reads the facts the Apps tab's review step needs straight out of an APK file: package name,
//! version, minimum Android version, requested permissions, native-code architectures, and the
//! signing certificate. Self-contained on purpose (only `zip`, `sha2` and `hex`, already
//! dependencies) - an APK's `AndroidManifest.xml` is Android's compiled "binary XML", not text, and
//! the signing certificate lives in the APK Signing Block outside the zip entries.
//!
//! **This does not verify signatures.** It only reads which certificate the APK claims to be
//! signed with. That's enough here: Android itself verifies the signature at install time and
//! rejects a tampered APK, so the server's job is only to notice when a release claims a
//! *different* (validly signed) key than before and hold it for the parent - see
//! `handlers::tracked_apps::review_reasons`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApkInfo {
    pub package_name: String,
    pub version_code: i64,
    pub version_name: Option<String>,
    pub min_sdk: Option<i64>,
    pub permissions: Vec<String>,
    /// Lowercase hex SHA-256 of the signing certificate (DER) - the same value
    /// `apksigner verify --print-certs` prints as "certificate SHA-256 digest". `None` if no
    /// signature was found at all.
    pub cert_sha256: Option<String>,
    /// The `lib/<abi>/` folders present, e.g. `arm64-v8a`. Empty for apps with no native code,
    /// which run on any architecture.
    pub native_abis: Vec<String>,
}

impl ApkInfo {
    /// Plain-language names for the sensitive permissions this APK asks for, deduplicated, in a
    /// stable order. See `sensitive_permission_label`.
    pub fn sensitive_labels(&self) -> Vec<&'static str> {
        let mut labels: Vec<&'static str> = self
            .permissions
            .iter()
            .filter_map(|p| sensitive_permission_label(p))
            .collect();
        labels.sort_unstable();
        labels.dedup();
        labels
    }

    /// `C1:01:C6:F4:...` style, first 8 bytes only - enough to tell keys apart at a glance.
    pub fn cert_short(&self) -> String {
        match &self.cert_sha256 {
            Some(hex) => hex
                .as_bytes()
                .chunks(2)
                .take(8)
                .map(|c| String::from_utf8_lossy(c).to_uppercase())
                .collect::<Vec<_>>()
                .join(":"),
            None => "none".to_string(),
        }
    }

    /// "1.2.3 (45)", or just the version code when there's no readable version name.
    pub fn version_label(&self) -> String {
        match &self.version_name {
            Some(name) => format!("{name} ({})", self.version_code),
            None => self.version_code.to_string(),
        }
    }
}

/// The permissions worth a parent's attention when an update newly asks for them. Several Android
/// permissions can map to the same label (fine and coarse location are both "Location").
/// Everything not listed here is either harmless or not grantable to a normal app anyway.
pub fn sensitive_permission_label(permission: &str) -> Option<&'static str> {
    let short = permission
        .strip_prefix("android.permission.")
        .unwrap_or(permission);
    Some(match short {
        "CAMERA" => "Camera",
        "RECORD_AUDIO" => "Microphone",
        "ACCESS_FINE_LOCATION" | "ACCESS_COARSE_LOCATION" => "Location",
        "ACCESS_BACKGROUND_LOCATION" => "Location in the background",
        "ACCESS_MEDIA_LOCATION" => "Location stored in photos",
        "READ_CONTACTS" | "WRITE_CONTACTS" | "GET_ACCOUNTS" => "Contacts",
        "READ_CALENDAR" | "WRITE_CALENDAR" => "Calendar",
        "READ_SMS" | "SEND_SMS" | "RECEIVE_SMS" | "RECEIVE_MMS" | "RECEIVE_WAP_PUSH" => {
            "Text messages"
        }
        "READ_CALL_LOG" | "WRITE_CALL_LOG" | "PROCESS_OUTGOING_CALLS" => "Call history",
        "CALL_PHONE" | "ANSWER_PHONE_CALLS" | "READ_PHONE_STATE" | "READ_PHONE_NUMBERS"
        | "USE_SIP" | "ADD_VOICEMAIL" => "Phone calls",
        "BODY_SENSORS" | "BODY_SENSORS_BACKGROUND" | "ACTIVITY_RECOGNITION" => {
            "Body sensors and activity"
        }
        "READ_EXTERNAL_STORAGE"
        | "WRITE_EXTERNAL_STORAGE"
        | "READ_MEDIA_IMAGES"
        | "READ_MEDIA_VIDEO"
        | "READ_MEDIA_AUDIO"
        | "READ_MEDIA_VISUAL_USER_SELECTED" => "Photos, videos and files",
        "MANAGE_EXTERNAL_STORAGE" => "All files on the phone",
        "BLUETOOTH_SCAN"
        | "BLUETOOTH_CONNECT"
        | "BLUETOOTH_ADVERTISE"
        | "NEARBY_WIFI_DEVICES"
        | "UWB_RANGING" => "Nearby devices",
        "SYSTEM_ALERT_WINDOW" => "Draw over other apps",
        "REQUEST_INSTALL_PACKAGES" => "Install other apps",
        "QUERY_ALL_PACKAGES" => "See every installed app",
        "PACKAGE_USAGE_STATS" => "App usage history",
        "INTERNET" => "Internet",
        _ => return None,
    })
}

/// Reads everything `ApkInfo` holds from the APK at `path`. Blocking file I/O - call it from
/// `tokio::task::spawn_blocking`. Only the manifest entry and the signing block are read, never
/// the whole APK, so memory use stays small even for very large APKs (this runs on a Pi Zero).
pub fn analyze(path: &Path) -> Result<ApkInfo, String> {
    let file = File::open(path).map_err(|e| format!("can't open file: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("not a valid APK/zip file: {e}"))?;

    let mut manifest = Vec::new();
    archive
        .by_name("AndroidManifest.xml")
        .map_err(|_| "no AndroidManifest.xml inside - not an APK".to_string())?
        .take(16 * 1024 * 1024)
        .read_to_end(&mut manifest)
        .map_err(|e| format!("can't read AndroidManifest.xml: {e}"))?;
    let mut info = parse_manifest(&manifest)?;

    let mut abis: Vec<String> = archive
        .file_names()
        .filter_map(|name| {
            let rest = name.strip_prefix("lib/")?;
            let (abi, file) = rest.split_once('/')?;
            (!abi.is_empty() && !file.is_empty()).then(|| abi.to_string())
        })
        .collect();
    abis.sort();
    abis.dedup();
    info.native_abis = abis;

    let mut file = File::open(path).map_err(|e| format!("can't open file: {e}"))?;
    let cert = match signing_block_cert(&mut file) {
        Some(cert) => Some(cert),
        None => v1_signature_cert(&mut archive),
    };
    info.cert_sha256 = cert.map(|der| hex::encode(Sha256::digest(der)));

    Ok(info)
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

// --- Binary XML (AndroidManifest.xml) ---------------------------------------------------------
//
// Layout (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h): a file header chunk,
// then a sequence of chunks - a string pool, a resource-id map, and one chunk per XML start/end
// element. Each chunk starts with {u16 type, u16 header size, u32 total size}.

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

const TYPE_STRING: u8 = 0x03;
const TYPE_FIRST_INT: u8 = 0x10;
const TYPE_LAST_INT: u8 = 0x1f;

// android.R.attr ids. Attributes are matched by these when the manifest has a resource map
// (always, for anything built by aapt2) - some apps obfuscate the attribute *names*, never the ids.
const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_MIN_SDK_VERSION: u32 = 0x0101_020c;
const ATTR_VERSION_CODE: u32 = 0x0101_021b;
const ATTR_VERSION_NAME: u32 = 0x0101_021c;
const ATTR_VERSION_CODE_MAJOR: u32 = 0x0101_0576;

fn parse_string_pool(chunk: &[u8]) -> Option<Vec<String>> {
    let header_size = u16_at(chunk, 2)? as usize;
    let count = u32_at(chunk, 8)? as usize;
    let utf8 = u32_at(chunk, 16)? & (1 << 8) != 0;
    let strings_start = u32_at(chunk, 20)? as usize;
    // Every string needs at least a 4-byte offset entry, so this bounds `count` by the chunk size
    // before allocating anything for a corrupt header.
    if count > chunk.len() / 4 {
        return None;
    }
    let mut strings = Vec::with_capacity(count);
    for i in 0..count {
        let start = strings_start + u32_at(chunk, header_size + i * 4)? as usize;
        let s = if utf8 {
            read_utf8_string(chunk, start)
        } else {
            read_utf16_string(chunk, start)
        };
        strings.push(s.unwrap_or_default());
    }
    Some(strings)
}

fn read_utf8_string(b: &[u8], mut p: usize) -> Option<String> {
    // Two lengths: UTF-16 units (skipped), then UTF-8 bytes. Each is 1 byte, or 2 if the high bit
    // of the first is set.
    p += if b.get(p)? & 0x80 != 0 { 2 } else { 1 };
    let mut len = *b.get(p)? as usize;
    if len & 0x80 != 0 {
        len = ((len & 0x7f) << 8) | *b.get(p + 1)? as usize;
        p += 2;
    } else {
        p += 1;
    }
    Some(String::from_utf8_lossy(b.get(p..p + len)?).into_owned())
}

fn read_utf16_string(b: &[u8], mut p: usize) -> Option<String> {
    let mut len = u16_at(b, p)? as usize;
    p += 2;
    if len & 0x8000 != 0 {
        len = ((len & 0x7fff) << 16) | u16_at(b, p)? as usize;
        p += 2;
    }
    let units: Vec<u16> = (0..len)
        .map(|i| u16_at(b, p + i * 2))
        .collect::<Option<_>>()?;
    Some(String::from_utf16_lossy(&units))
}

enum AttrValue {
    Str(String),
    Int(i64),
    Other,
}

fn parse_manifest(xml: &[u8]) -> Result<ApkInfo, String> {
    let bad = || "AndroidManifest.xml is damaged or in an unknown format".to_string();
    if u16_at(xml, 0) != Some(RES_XML_TYPE) {
        return Err(bad());
    }

    let mut strings: Vec<String> = Vec::new();
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut info = ApkInfo::default();
    let mut version_code_major: i64 = 0;
    let mut saw_manifest = false;

    let mut pos = u16_at(xml, 2).ok_or_else(bad)? as usize;
    while pos + 8 <= xml.len() {
        let chunk_type = u16_at(xml, pos).ok_or_else(bad)?;
        let header_size = u16_at(xml, pos + 2).ok_or_else(bad)? as usize;
        let size = u32_at(xml, pos + 4).ok_or_else(bad)? as usize;
        if size < 8 || pos + size > xml.len() {
            return Err(bad());
        }
        let chunk = &xml[pos..pos + size];
        pos += size;

        match chunk_type {
            RES_STRING_POOL_TYPE => strings = parse_string_pool(chunk).ok_or_else(bad)?,
            RES_XML_RESOURCE_MAP_TYPE => {
                resource_ids = (header_size..size)
                    .step_by(4)
                    .filter_map(|o| u32_at(chunk, o))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                // ResXMLTree_attrExt follows the chunk header: ns, name, attributeStart,
                // attributeSize, attributeCount, ...
                let ext = header_size;
                let string = |idx: u32| strings.get(idx as usize).map(String::as_str);
                let element = string(u32_at(chunk, ext + 4).ok_or_else(bad)?).unwrap_or("");
                let attr_start = u16_at(chunk, ext + 8).ok_or_else(bad)? as usize;
                let attr_size = u16_at(chunk, ext + 10).ok_or_else(bad)? as usize;
                let attr_count = u16_at(chunk, ext + 12).ok_or_else(bad)? as usize;

                for i in 0..attr_count {
                    // ResXMLTree_attribute: ns, name, rawValue, then Res_value {size, res0,
                    // dataType, data}.
                    let a = ext + attr_start + i * attr_size;
                    let name_idx = u32_at(chunk, a + 4).ok_or_else(bad)?;
                    let raw = u32_at(chunk, a + 8).ok_or_else(bad)?;
                    let data_type = *chunk.get(a + 15).ok_or_else(bad)?;
                    let data = u32_at(chunk, a + 16).ok_or_else(bad)?;

                    let res_id = resource_ids.get(name_idx as usize).copied();
                    let attr_name = string(name_idx).unwrap_or("");
                    let is = |id: u32, name: &str| match res_id {
                        Some(r) => r == id,
                        None => attr_name == name,
                    };
                    let value = if data_type == TYPE_STRING {
                        AttrValue::Str(string(data).unwrap_or("").to_string())
                    } else if (TYPE_FIRST_INT..=TYPE_LAST_INT).contains(&data_type) {
                        AttrValue::Int(data as i64)
                    } else if raw != u32::MAX {
                        AttrValue::Str(string(raw).unwrap_or("").to_string())
                    } else {
                        AttrValue::Other
                    };

                    match element {
                        "manifest" => {
                            saw_manifest = true;
                            if res_id.is_none() && attr_name == "package" {
                                if let AttrValue::Str(s) = value {
                                    info.package_name = s;
                                }
                            } else if is(ATTR_VERSION_CODE, "versionCode") {
                                info.version_code = match value {
                                    AttrValue::Int(n) => n,
                                    AttrValue::Str(s) => s.trim().parse().unwrap_or(0),
                                    AttrValue::Other => 0,
                                };
                            } else if is(ATTR_VERSION_CODE_MAJOR, "versionCodeMajor") {
                                if let AttrValue::Int(n) = value {
                                    version_code_major = n;
                                }
                            } else if is(ATTR_VERSION_NAME, "versionName") {
                                // A reference into resources.arsc (@string/...) can't be resolved
                                // without parsing that too - left as None, the version code is
                                // what actually matters.
                                if let AttrValue::Str(s) = value {
                                    info.version_name = (!s.is_empty()).then_some(s);
                                }
                            }
                        }
                        "uses-sdk" if is(ATTR_MIN_SDK_VERSION, "minSdkVersion") => {
                            info.min_sdk = match value {
                                AttrValue::Int(n) => Some(n),
                                // A preview SDK codename ("Baklava") - no number to show.
                                AttrValue::Str(s) => s.trim().parse().ok(),
                                AttrValue::Other => None,
                            };
                        }
                        "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m"
                            if is(ATTR_NAME, "name") =>
                        {
                            if let AttrValue::Str(s) = value {
                                if !s.is_empty() && !info.permissions.contains(&s) {
                                    info.permissions.push(s);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if !saw_manifest || info.package_name.is_empty() {
        return Err("AndroidManifest.xml has no package name".to_string());
    }
    info.version_code |= version_code_major << 32;
    info.permissions.sort();
    Ok(info)
}

// --- Signing certificate ----------------------------------------------------------------------

const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const SIGNATURE_SCHEME_V2_ID: u32 = 0x7109_871a;
const SIGNATURE_SCHEME_V3_ID: u32 = 0xf053_68c0;
const SIGNATURE_SCHEME_V31_ID: u32 = 0x1b93_ad61;

/// The first signer's certificate (DER) from the APK Signing Block (schemes v2/v3/v3.1), or
/// `None` if the APK has no signing block. Prefers v3.1, then v3, then v2 - after a key rotation
/// the newest scheme carries the key current Android versions treat as the app's signer.
///
/// Layout (source.android.com/docs/security/features/apksigning/v2): the block sits right before
/// the zip central directory and ends with {u64 size, "APK Sig Block 42"}; inside it is a list of
/// {u64 length, u32 id, value} pairs.
fn signing_block_cert(file: &mut File) -> Option<Vec<u8>> {
    let len = file.metadata().ok()?.len();
    // End-of-central-directory record: 22 bytes plus a comment of up to 65535 bytes.
    let tail_len = len.min(22 + 65535);
    file.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    file.read_exact(&mut tail).ok()?;
    let eocd = (0..=tail.len().checked_sub(22)?)
        .rev()
        .find(|&i| tail[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])?;
    let cd_offset = u32_at(&tail, eocd + 16)? as u64;

    if cd_offset < 24 {
        return None;
    }
    file.seek(SeekFrom::Start(cd_offset - 24)).ok()?;
    let mut footer = [0u8; 24];
    file.read_exact(&mut footer).ok()?;
    if &footer[8..24] != APK_SIG_BLOCK_MAGIC {
        return None;
    }
    let block_size = u64_at(&footer, 0)?;
    if block_size > 16 * 1024 * 1024 || block_size + 8 > cd_offset {
        return None;
    }
    file.seek(SeekFrom::Start(cd_offset - block_size - 8))
        .ok()?;
    let mut block = vec![0u8; (block_size + 8) as usize];
    file.read_exact(&mut block).ok()?;
    if u64_at(&block, 0)? != block_size {
        return None;
    }

    let mut found: [Option<&[u8]>; 3] = [None, None, None];
    let end = block.len() - 24;
    let mut pos = 8;
    while pos + 12 <= end {
        let pair_len = u64_at(&block, pos)? as usize;
        if pair_len < 4 || pos + 8 + pair_len > end {
            break;
        }
        let value = &block[pos + 12..pos + 8 + pair_len];
        match u32_at(&block, pos + 8)? {
            SIGNATURE_SCHEME_V31_ID => found[0] = Some(value),
            SIGNATURE_SCHEME_V3_ID => found[1] = Some(value),
            SIGNATURE_SCHEME_V2_ID => found[2] = Some(value),
            _ => {}
        }
        pos += 8 + pair_len;
    }

    found
        .into_iter()
        .flatten()
        .find_map(first_cert_in_scheme_block)
        .map(<[u8]>::to_vec)
}

/// A u32-length-prefixed slice at `offset` - the encoding every v2/v3 structure uses.
fn length_prefixed(b: &[u8], offset: usize) -> Option<&[u8]> {
    let n = u32_at(b, offset)? as usize;
    b.get(offset + 4..offset + 4 + n)
}

/// v2 and v3 share this prefix: signers → first signer → signed data → (digests, certificates)
/// → first certificate.
fn first_cert_in_scheme_block(value: &[u8]) -> Option<&[u8]> {
    let signers = length_prefixed(value, 0)?;
    let signer = length_prefixed(signers, 0)?;
    let signed_data = length_prefixed(signer, 0)?;
    let digests_len = u32_at(signed_data, 0)? as usize;
    let certificates = length_prefixed(signed_data, 4 + digests_len)?;
    length_prefixed(certificates, 0)
}

/// Fallback for old APKs signed only with the original JAR scheme (v1): the certificate is inside
/// the PKCS#7 file `META-INF/*.RSA` (or `.DSA`/`.EC`).
fn v1_signature_cert(archive: &mut zip::ZipArchive<File>) -> Option<Vec<u8>> {
    let name = archive
        .file_names()
        .find(|n| {
            let upper = n.to_ascii_uppercase();
            upper.starts_with("META-INF/")
                && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
        })?
        .to_string();
    let mut pkcs7 = Vec::new();
    archive
        .by_name(&name)
        .ok()?
        .take(1024 * 1024)
        .read_to_end(&mut pkcs7)
        .ok()?;
    first_cert_in_pkcs7(&pkcs7).map(<[u8]>::to_vec)
}

/// One DER element: (tag, contents, the whole element including its header, what follows it).
fn der_element(b: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
    let tag = *b.first()?;
    let first_len = *b.get(1)? as usize;
    let (len, header) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        let n = first_len & 0x7f;
        if n == 0 || n > 4 {
            return None; // indefinite (BER) or absurd lengths - jarsigner never writes these
        }
        let len = b
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | byte as usize);
        (len, 2 + n)
    };
    let whole = b.get(..header + len)?;
    Some((tag, &whole[header..], whole, &b[header + len..]))
}

/// ContentInfo { contentType, [0] SignedData { version, digestAlgorithms, contentInfo,
/// [0] certificates, ... } } → the first certificate.
fn first_cert_in_pkcs7(b: &[u8]) -> Option<&[u8]> {
    let (_, content_info, _, _) = der_element(b)?;
    let (_, _, _, after_oid) = der_element(content_info)?;
    let (_, explicit, _, _) = der_element(after_oid)?;
    let (_, mut signed_data, _, _) = der_element(explicit)?;
    while !signed_data.is_empty() {
        let (tag, contents, _, rest) = der_element(signed_data)?;
        if tag == 0xa0 {
            let (_, _, cert, _) = der_element(contents)?;
            return Some(cert);
        }
        signed_data = rest;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run against a real APK: `KPS_TEST_APK=/path/to/app.apk cargo test apk::tests -- --nocapture`.
    /// Skipped when the variable isn't set (CI has no APK to read).
    #[test]
    fn analyze_real_apk_from_env() {
        let Ok(path) = std::env::var("KPS_TEST_APK") else {
            return;
        };
        let info = analyze(Path::new(&path)).expect("analyze failed");
        println!("{info:#?}");
        assert!(!info.package_name.is_empty());
        assert!(info.version_code > 0);
        assert!(info.cert_sha256.is_some());

        // When the APK also carries a v1 (JAR) signature, the fallback reader must find the same
        // key as the signing block (true unless the app has rotated keys).
        let mut archive = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
        if let Some(der) = v1_signature_cert(&mut archive) {
            let v1 = hex::encode(Sha256::digest(der));
            println!("v1 signature cert: {v1}");
            assert_eq!(Some(v1), info.cert_sha256);
        }
    }

    #[test]
    fn labels_group_and_dedupe() {
        let info = ApkInfo {
            permissions: vec![
                "android.permission.ACCESS_COARSE_LOCATION".into(),
                "android.permission.ACCESS_FINE_LOCATION".into(),
                "android.permission.CAMERA".into(),
                "android.permission.VIBRATE".into(),
            ],
            ..Default::default()
        };
        assert_eq!(info.sensitive_labels(), vec!["Camera", "Location"]);
    }

    #[test]
    fn cert_short_formats_first_eight_bytes() {
        let info = ApkInfo {
            cert_sha256: Some("c101c6f44b7ecc27af0ce8b42a81647f".into()),
            ..Default::default()
        };
        assert_eq!(info.cert_short(), "C1:01:C6:F4:4B:7E:CC:27");
    }
}
