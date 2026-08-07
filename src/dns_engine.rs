//! Pi-hole-style DNS content filtering, built in-process on `hickory-server`
//! (MIT/Apache-2.0) - not on crab-hole (AGPL-3.0), which was only ever read
//! as a design reference, never depended on or copied from. Runs as another
//! background task alongside the axum HTTP server and the other
//! `tokio::task::spawn`'d loops in `main.rs`.
//!
//! Global/singleton, not per-device: nothing in here needs to know about
//! individual devices. Two independent ways a device's DNS queries actually
//! reach this engine: (1) plain port 53, requires the device to be using
//! this Pi as its Tailscale exit node *and* the `iptables` redirect (a
//! privileged action, requested the same way `system_maintenance.rs`
//! requests a reboot) to be in place - confirmed live to have a lot of
//! failure modes (exit-node routing quirks, OS/browser-level DNS-over-HTTPS
//! bypassing plain port 53 entirely, Tailscale's own MagicDNS override
//! intercepting queries before they ever reach this Pi); (2) DNS-over-TLS on
//! [DOT_LISTEN_PORT], which the client force-locks Android's system Private
//! DNS setting to via `DevicePolicyManager.setGlobalPrivateDnsModeSpecifiedHost`
//! - this is the more reliable path, since it only requires the device to be
//! a normal tailnet peer (not exit-node routing), and Device-Owner-locks the
//! setting so it can't be switched back. See `AppEnforcer.applyPrivateDnsLock`
//! on the client for that side.
//!
//! Blocking uses `hickory_server::store::blocklist::BlocklistZoneHandler`
//! (a first-party, ready-made component of the library itself) chained
//! ahead of `hickory_server::store::forwarder::ForwardZoneHandler` in a
//! `Catalog` for the root zone - the library's own chaining mechanism
//! (`LookupControlFlow::Break` on a blocklist hit, `Continue` otherwise)
//! does the "check blocklist, else forward upstream" logic, not custom code
//! here. `Catalog` itself implements `RequestHandler`, wrapped by our own
//! thin `Handler` only to track query/blocked-query stats for the admin UI.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hickory_proto::rr::Name;
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_server::Server;
use hickory_server::net::runtime::Time;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, default_tls_server_config,
};
use hickory_server::store::blocklist::{
    BlocklistConfig, BlocklistConsultAction, BlocklistZoneHandler,
};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::zone_handler::{Catalog, ZoneHandler};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;

use crate::AppState;
use crate::models::{DnsBlocklist, DnsCustomDomain, DnsFilterSettings};

const BLOCKLIST_CACHE_DIR: &str = "data/dns_blocklists";
const CUSTOM_BLOCKLIST_FILE: &str = "custom.txt";
/// Not port 53 - deliberately unprivileged, so this needs no special
/// capability even though it's bound inside kid-phone-server's own hardened,
/// non-root systemd unit. The `iptables` redirect (privileged, requested
/// separately) is what routes real port-53 traffic here.
const LISTEN_PORT: u16 = 5300;
/// Same unprivileged-port-plus-iptables-redirect pattern as [LISTEN_PORT],
/// just for port 853 (DNS-over-TLS) instead of 53.
const DOT_LISTEN_PORT: u16 = 8853;
const TLS_CERT_PATH: &str = "data/tls/cert.pem";
const TLS_KEY_PATH: &str = "data/tls/key.pem";

pub struct Stats {
    pub total_queries: AtomicU64,
    pub blocked_queries: AtomicU64,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            started_at: chrono::Utc::now(),
        }
    }
}

/// Everything the running DNS engine needs, rebuilt from scratch and
/// swapped in whenever settings change (see `rebuild`) - simpler and safer
/// than trying to mutate a `Catalog`/`BlocklistZoneHandler` in place, and
/// cheap enough to do on every settings save given how small this data is.
pub struct DnsEngineState {
    pub enabled: bool,
    catalog: Catalog,
    /// A plain, non-wildcard copy of every blocked domain, kept only so the
    /// stats wrapper below can cheaply tell "was this query blocked" without
    /// needing a hook into `BlocklistZoneHandler`'s own (more sophisticated,
    /// wildcard-aware) internal matching - approximate for wildcard entries,
    /// exact for everything else, which is the vast majority of real entries.
    blocked_domains: HashSet<String>,
}

pub type SharedDnsState = Arc<RwLock<DnsEngineState>>;

pub fn empty_state() -> SharedDnsState {
    Arc::new(RwLock::new(DnsEngineState {
        enabled: false,
        catalog: Catalog::new(),
        blocked_domains: HashSet::new(),
    }))
}

/// Unconditionally resolves to the one cert this Pi has - there's only ever
/// a single hostname (this Pi's own tailnet MagicDNS name) a DoT client
/// would present via SNI, so no per-hostname lookup logic is needed.
struct SingleCertResolver(Arc<CertifiedKey>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleCertResolver").finish()
    }
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Loads the DoT certificate/key pair from disk, if present - `None` (not an
/// error) is the expected, normal state before `tailscale cert` has ever
/// been run on this Pi (see `deploy/install.sh`'s `action_tls_cert_renew`),
/// and just means DNS-over-TLS doesn't start this run; the plain port-53
/// path keeps working regardless.
fn load_tls_resolver() -> Option<Arc<dyn ResolvesServerCert>> {
    let cert_bytes = std::fs::read(TLS_CERT_PATH).ok()?;
    let key_bytes = std::fs::read(TLS_KEY_PATH).ok()?;

    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .ok()
        .flatten()?;

    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(certs, key, &provider).ok()?;
    Some(Arc::new(SingleCertResolver(Arc::new(certified_key))))
}

fn is_blocked(name: &str, blocked_domains: &HashSet<String>) -> bool {
    let mut labels: Vec<&str> = name.split('.').collect();
    while !labels.is_empty() {
        if blocked_domains.contains(&labels.join(".")) {
            return true;
        }
        labels.remove(0);
    }
    false
}

struct Handler {
    state: SharedDnsState,
    stats: Arc<Stats>,
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);

        let state = self.state.read().await;
        if state.enabled {
            if let Ok(info) = request.request_info() {
                let name = info.query.name().to_string();
                let name = name.trim_end_matches('.').to_lowercase();
                if is_blocked(&name, &state.blocked_domains) {
                    self.stats.blocked_queries.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        state
            .catalog
            .handle_request::<R, T>(request, response_handle)
            .await
    }
}

fn upstream_name_server(preset: &str) -> NameServerConfig {
    let (ip, server_name): (IpAddr, &str) = match preset {
        "quad9" => (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), "dns.quad9.net"),
        _ => (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "cloudflare-dns.com"),
    };
    NameServerConfig::tls(ip, server_name.into())
}

/// Strips comments/blank lines and writes hosts-file-format content to
/// `path`, skipping any domain present in `allow_domains` - the only way to
/// get "allow-list overrides a blocklist" semantics here, since
/// `BlocklistZoneHandler` has no remove/override call once a domain's been
/// added, only `add()`. Also folds every kept domain into `stats_domains`
/// so the stats wrapper's `is_blocked` check stays in sync with whatever
/// actually made it into the real blocklist.
async fn write_filtered_list(
    path: &std::path::Path,
    raw: &str,
    allow_domains: &HashSet<String>,
    stats_domains: &mut HashSet<String>,
) -> std::io::Result<()> {
    let mut out = String::new();
    for line in raw.lines() {
        let entry = line.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let domain = match entry.split_once(' ') {
            Some((ip, domain)) if ip.trim() == "0.0.0.0" => domain.trim(),
            Some(_) => continue,
            None => entry,
        };
        let domain = domain.trim_end_matches('.').to_lowercase();
        if domain.is_empty() || allow_domains.contains(&domain) {
            continue;
        }
        stats_domains.insert(domain.clone());
        out.push_str(&domain);
        out.push('\n');
    }
    tokio::fs::write(path, out).await
}

/// Rebuilds the whole DNS engine state from the database and swaps it into
/// `shared` - called after every settings/blocklist/custom-domain change,
/// and once at startup. Blocklists that fail to download are logged and
/// skipped for this rebuild (keeping whatever was cached from the last
/// successful fetch on disk, same "log and keep going" pattern used by
/// `tracked_apps::sync_one_app`) rather than aborting the whole rebuild.
pub async fn rebuild(state: &AppState, shared: &SharedDnsState) {
    let settings =
        sqlx::query_as::<_, DnsFilterSettings>("SELECT * FROM dns_filter_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .expect("dns_filter_settings singleton row always exists");

    let blocklists =
        sqlx::query_as::<_, DnsBlocklist>("SELECT * FROM dns_blocklists WHERE enabled = 1")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let custom = sqlx::query_as::<_, DnsCustomDomain>("SELECT * FROM dns_custom_domains")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let allow_domains: HashSet<String> = custom
        .iter()
        .filter(|d| d.list_type == "allow")
        .map(|d| d.domain.to_lowercase())
        .collect();
    let custom_block_domains: HashSet<String> = custom
        .iter()
        .filter(|d| d.list_type == "block")
        .map(|d| d.domain.to_lowercase())
        .collect();

    if tokio::fs::create_dir_all(BLOCKLIST_CACHE_DIR)
        .await
        .is_err()
    {
        tracing::error!(
            "failed to create {BLOCKLIST_CACHE_DIR}, keeping previous DNS filter state"
        );
        return;
    }

    let mut stats_domains = HashSet::new();
    let mut list_files = Vec::new();

    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, dns filter)")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client always builds");

    for list in &blocklists {
        let filename = format!("{}.txt", list.id);
        let path = Path::new(BLOCKLIST_CACHE_DIR).join(&filename);
        match client.get(&list.url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    if write_filtered_list(&path, &text, &allow_domains, &mut stats_domains)
                        .await
                        .is_ok()
                    {
                        list_files.push(filename);
                    }
                }
                Err(e) => tracing::warn!("failed to read blocklist '{}' body: {e}", list.name),
            },
            Err(e) => {
                tracing::warn!("failed to download blocklist '{}': {e}", list.name);
                // Fall back to whatever's already cached on disk from a previous successful fetch.
                if path.exists() {
                    list_files.push(filename);
                }
            }
        }
    }

    // Custom block-list domains, minus anything on the allow list.
    let custom_content: String = custom_block_domains
        .iter()
        .filter(|d| !allow_domains.contains(*d))
        .map(|d| {
            stats_domains.insert(d.clone());
            format!("{d}\n")
        })
        .collect();
    let custom_path = Path::new(BLOCKLIST_CACHE_DIR).join(CUSTOM_BLOCKLIST_FILE);
    if tokio::fs::write(&custom_path, custom_content).await.is_ok() {
        list_files.push(CUSTOM_BLOCKLIST_FILE.to_string());
    }

    let blocklist_config = BlocklistConfig {
        wildcard_match: false,
        min_wildcard_depth: 2,
        lists: list_files,
        sinkhole_ipv4: None,
        sinkhole_ipv6: None,
        block_message: None,
        ttl: 300,
        consult_action: BlocklistConsultAction::Disabled,
        log_clients: false,
    };
    let blocklist_handler = match BlocklistZoneHandler::try_from_config(
        Name::root(),
        blocklist_config,
        Some(Path::new(BLOCKLIST_CACHE_DIR)),
    ) {
        Ok(handler) => handler,
        Err(e) => {
            tracing::error!(
                "failed to build DNS blocklist handler: {e}, keeping previous DNS filter state"
            );
            return;
        }
    };

    let forward_config = ForwardConfig {
        name_servers: vec![upstream_name_server(&settings.upstream)],
        options: Some(ResolverOpts::default()),
    };
    let forward_handler = match ForwardZoneHandler::builder_tokio(forward_config).build() {
        Ok(handler) => handler,
        Err(e) => {
            tracing::error!(
                "failed to build DNS forwarder: {e}, keeping previous DNS filter state"
            );
            return;
        }
    };

    let mut catalog = Catalog::new();
    let handlers: Vec<Arc<dyn ZoneHandler>> =
        vec![Arc::new(blocklist_handler), Arc::new(forward_handler)];
    catalog.upsert(Name::root().into(), handlers);

    *shared.write().await = DnsEngineState {
        enabled: settings.enabled,
        catalog,
        blocked_domains: stats_domains,
    };
}

/// Spawned once at startup - binds the (always-on, harmless-if-unused)
/// listener and runs forever. Config changes never restart this; they just
/// swap `shared`'s contents via `rebuild` above.
pub async fn run(shared: SharedDnsState, stats: Arc<Stats>) {
    let handler = Handler {
        state: shared,
        stats,
    };
    let mut server = Server::new(handler);

    let udp_addr = format!("127.0.0.1:{LISTEN_PORT}");
    match UdpSocket::bind(&udp_addr).await {
        Ok(socket) => server.register_socket(socket),
        Err(e) => {
            tracing::error!("failed to bind DNS filter UDP socket {udp_addr}: {e}");
            return;
        }
    }

    let tcp_addr = format!("127.0.0.1:{LISTEN_PORT}");
    match TcpListener::bind(&tcp_addr).await {
        Ok(listener) => server.register_listener(listener, std::time::Duration::from_secs(5), 4096),
        Err(e) => tracing::warn!("failed to bind DNS filter TCP listener {tcp_addr}: {e}"),
    }

    match load_tls_resolver() {
        Some(resolver) => {
            let dot_addr = format!("127.0.0.1:{DOT_LISTEN_PORT}");
            match TcpListener::bind(&dot_addr).await {
                Ok(listener) => match default_tls_server_config(b"dot", resolver) {
                    Ok(tls_config) => {
                        if let Err(e) = server.register_tls_listener_with_tls_config(
                            listener,
                            std::time::Duration::from_secs(5),
                            Arc::new(tls_config),
                        ) {
                            tracing::error!("failed to register DoT listener: {e}");
                        } else {
                            tracing::info!("DNS-over-TLS listening on {dot_addr}");
                        }
                    }
                    Err(e) => tracing::error!("failed to build DoT TLS config: {e}"),
                },
                Err(e) => tracing::warn!("failed to bind DoT TCP listener {dot_addr}: {e}"),
            }
        }
        None => tracing::info!(
            "No TLS cert at {TLS_CERT_PATH} - DNS-over-TLS not started (run `tailscale cert` on the Pi, or wait for the scheduled renewal action, to enable it)"
        ),
    }

    if let Err(e) = server.block_until_done().await {
        tracing::error!("DNS filter server stopped unexpectedly: {e}");
    }
}

/// One curated feed's downloaded, normalized domain set - kept separate per
/// feed (rather than flattened into one big domain->category map) so a
/// device-level override can enable a feed the *global* default has off
/// (impossible if we'd only ever downloaded globally-enabled feeds).
pub struct CompiledList {
    pub blocklist_id: i64,
    pub category: String,
    pub domains: HashSet<String>,
}

/// The server's compiled view of "what could a device's on-device filter
/// block" - every defined blocklist feed's domains (regardless of that
/// feed's *global* enabled flag - see [CompiledList]'s doc comment), plus
/// global (device_id IS NULL) custom block domains, minus global custom
/// allow domains. A specific device's actual effective list is resolved from
/// this cheaply at request time (global `enabled` flags + this device's
/// `device_blocklist_overrides`/scoped `dns_custom_domains`, applied on top)
/// - see `handlers::device_api::dns_blocklist` - rather than precomputed per
/// device, since this base rarely changes and per-device overrides are
/// small. This is the client-side-filtering replacement for
/// `rebuild`/`DnsEngineState` above (which builds a live hickory `Catalog`
/// this Pi resolves against directly) - kept as a separate type rather than
/// folded into `DnsEngineState` so Phase E of the on-device-filtering
/// migration can delete the hickory-specific code above without touching
/// this.
pub struct CompiledBlocklist {
    pub lists: Vec<CompiledList>,
    /// Global (device_id IS NULL) custom block/allow domains, already
    /// lowercased/normalized - kept separate from `lists` since they're not
    /// tied to a `blocklist_id` and always apply regardless of any per-device
    /// blocklist-feed override.
    pub global_custom_block: HashSet<String>,
    pub global_custom_allow: HashSet<String>,
    /// Stable content hash (independent of any device's overrides) - part of
    /// `PolicyResponse.dns_filter_version`'s input, so a client can tell
    /// "did the global list change" without re-fetching the whole thing.
    pub content_hash: String,
}

pub type SharedCompiledBlocklist = Arc<RwLock<CompiledBlocklist>>;

pub fn empty_compiled_blocklist() -> SharedCompiledBlocklist {
    Arc::new(RwLock::new(CompiledBlocklist {
        lists: Vec::new(),
        global_custom_block: HashSet::new(),
        global_custom_allow: HashSet::new(),
        content_hash: String::new(),
    }))
}

/// Downloads/normalizes every *defined* blocklist feed (not just
/// globally-enabled ones - see [CompiledList]) plus global custom domains,
/// and swaps the result into `shared` - called after every
/// settings/blocklist/custom-domain change and on the same hourly refresh as
/// the legacy `rebuild` above (see `handlers::dns_filter::run_blocklist_refresh`).
/// If every feed fails to download this cycle (e.g. a total network outage),
/// skips the swap and keeps whatever was compiled last time rather than
/// blanking every device's filter out to nothing - same "log and keep going"
/// instinct as `rebuild`'s disk-cache fallback, just without needing an
/// actual disk cache here since there's no live server reading these files.
pub async fn compile_blocklist(state: &AppState, shared: &SharedCompiledBlocklist) {
    let blocklists = sqlx::query_as::<_, DnsBlocklist>("SELECT * FROM dns_blocklists")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let custom = sqlx::query_as::<_, DnsCustomDomain>(
        "SELECT * FROM dns_custom_domains WHERE device_id IS NULL",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let global_custom_allow: HashSet<String> = custom
        .iter()
        .filter(|d| d.list_type == "allow")
        .map(|d| d.domain.to_lowercase())
        .collect();
    let global_custom_block: HashSet<String> = custom
        .iter()
        .filter(|d| d.list_type == "block")
        .map(|d| d.domain.to_lowercase())
        .filter(|d| !global_custom_allow.contains(d))
        .collect();

    let client = reqwest::Client::builder()
        .user_agent("kid-phone-server (self-hosted, dns filter)")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client always builds");

    let mut lists = Vec::new();

    for list in &blocklists {
        let mut domains = HashSet::new();
        match client.get(&list.url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    for line in text.lines() {
                        let entry = line.split('#').next().unwrap_or("").trim();
                        if entry.is_empty() {
                            continue;
                        }
                        let domain = match entry.split_once(' ') {
                            Some((ip, domain)) if ip.trim() == "0.0.0.0" => domain.trim(),
                            Some(_) => continue,
                            None => entry,
                        };
                        let domain = domain.trim_end_matches('.').to_lowercase();
                        if domain.is_empty() || global_custom_allow.contains(&domain) {
                            continue;
                        }
                        domains.insert(domain);
                    }
                }
                Err(e) => tracing::warn!("failed to read blocklist '{}' body: {e}", list.name),
            },
            Err(e) => tracing::warn!("failed to download blocklist '{}': {e}", list.name),
        }
        lists.push(CompiledList {
            blocklist_id: list.id,
            category: list.name.clone(),
            domains,
        });
    }

    if lists.iter().all(|l| l.domains.is_empty()) && !blocklists.is_empty() {
        tracing::error!(
            "DNS blocklist compile produced zero domains across every feed - keeping previous compiled list"
        );
        return;
    }

    let content_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut list_ids: Vec<i64> = lists.iter().map(|l| l.blocklist_id).collect();
        list_ids.sort();
        for id in list_ids {
            let list = lists.iter().find(|l| l.blocklist_id == id).unwrap();
            let mut sorted: Vec<&String> = list.domains.iter().collect();
            sorted.sort();
            hasher.update(format!("list:{id}\n").as_bytes());
            for d in sorted {
                hasher.update(d.as_bytes());
                hasher.update(b"\n");
            }
        }
        let mut sorted_block: Vec<&String> = global_custom_block.iter().collect();
        sorted_block.sort();
        for d in sorted_block {
            hasher.update(d.as_bytes());
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    };

    *shared.write().await = CompiledBlocklist {
        lists,
        global_custom_block,
        global_custom_allow,
        content_hash,
    };
}

pub fn stats_snapshot(stats: &Stats) -> (u64, u64, chrono::DateTime<chrono::Utc>) {
    (
        stats.total_queries.load(Ordering::Relaxed),
        stats.blocked_queries.load(Ordering::Relaxed),
        stats.started_at,
    )
}
