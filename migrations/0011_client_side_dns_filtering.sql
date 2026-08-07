-- DNS filtering moves from a server-side hickory-dns engine (migration 0009)
-- to on-device blocking (the launcher's own VpnService) - see this repo's
-- CLAUDE.md for the full architecture writeup. The server's job shrinks to:
-- distributing the compiled blocklist/allowlist per device, and ingesting a
-- log of what got blocked so a parent can see it.

-- NULL = applies to all devices (the existing global behavior), set = this
-- device only. The first nullable-scope column in this schema - every other
-- device_id column elsewhere is NOT NULL (one row always belongs to exactly
-- one device). Chosen over a separate per-device custom-domains table so the
-- existing dns_custom_domains admin UI/CRUD just gains an optional scope
-- rather than needing a parallel code path.
ALTER TABLE dns_custom_domains ADD COLUMN device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE;
CREATE INDEX idx_dns_custom_domains_device_id ON dns_custom_domains(device_id);

-- Per-device on/off override for a curated blocklist feed (e.g. turn off
-- "Social media" for one specific kid while leaving it on globally for
-- others). Absence of a row for a given (device_id, blocklist_id) means
-- "use dns_blocklists.enabled" - this table only stores actual overrides,
-- not a full copy of every feed's state for every device.
CREATE TABLE device_blocklist_overrides (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    blocklist_id INTEGER NOT NULL REFERENCES dns_blocklists(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (device_id, blocklist_id)
);

-- Blocked-query log ("did my kid try to visit X") - append-only, same shape
-- as device_locations (migration 0010): device_id NOT NULL, a
-- (device_id, timestamp) index, pruned on a rolling schedule by a background
-- task rather than ever growing unbounded. category records which blocklist
-- feed/reason caused the block (e.g. "Adult content", "Ads & tracking",
-- "Custom") so the admin log can show *why*, not just *that*.
CREATE TABLE device_dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    category TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_device_dns_events_device_id ON device_dns_events(device_id, blocked_at);
