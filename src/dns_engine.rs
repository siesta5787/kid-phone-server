//! Compiles the blocklist feeds/custom domains that every device's own
//! on-device DNS filter (the launcher's `KidVpnService`) resolves its
//! effective per-device list from - see `handlers::device_api::dns_blocklist`.
//!
//! This module used to also run a live, in-process DNS server
//! (`hickory-server`) that devices queried directly, either over plain port
//! 53 (via a Tailscale-exit-node + iptables redirect) or DNS-over-TLS (via
//! Android's Private DNS locked to this Pi's hostname). That approach hit a
//! hard Android limitation - Private DNS strict-mode bootstrap resolution
//! structurally cannot resolve a Tailscale MagicDNS hostname - and was
//! replaced by on-device filtering entirely (see this repo's CLAUDE.md for
//! the full migration writeup). This server's job shrank to just what's
//! below: distributing the compiled list, and ingesting a log of what got
//! blocked (`handlers::dns_filter::show_dns_log`).

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::AppState;
use crate::models::{DnsBlocklist, DnsCustomDomain};

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
/// small.
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
/// before (see `handlers::dns_filter::run_blocklist_refresh`). If every feed
/// fails to download this cycle (e.g. a total network outage), skips the
/// swap and keeps whatever was compiled last time rather than blanking every
/// device's filter out to nothing - same "log and keep going" instinct used
/// elsewhere in this codebase (e.g. `tracked_apps::sync_one_app`).
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
