-- Pi-hole-style DNS content filtering, built in-process on hickory-dns (see
-- src/dns_engine.rs). Global/singleton, not per-device - the kid's phone is
-- scoped to this by choosing this Pi as its Tailscale exit node, not by
-- anything in this schema, so there's nothing per-device to model here.

-- blocking_mode was dropped during implementation: hickory-server's
-- BlocklistZoneHandler (see src/dns_engine.rs) only supports sinkhole-style
-- blocking (a 0.0.0.0/:: response), not NXDOMAIN - not worth hand-rolling
-- NXDOMAIN mode for a distinction most parents won't care about.
CREATE TABLE dns_filter_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    upstream TEXT NOT NULL DEFAULT 'cloudflare',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO dns_filter_settings (id) VALUES (1);

CREATE TABLE dns_blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO dns_blocklists (name, url) VALUES
    ('Ads & tracking', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'),
    ('Adult content', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts'),
    ('Gambling', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts'),
    ('Social media', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts');

CREATE TABLE dns_custom_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    list_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
