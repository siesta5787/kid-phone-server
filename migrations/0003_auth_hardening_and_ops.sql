-- Two-factor login (TOTP).
ALTER TABLE admin_users ADD COLUMN totp_secret TEXT;
ALTER TABLE admin_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

-- Account lockout after repeated failed logins.
ALTER TABLE admin_users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_users ADD COLUMN locked_until TEXT;

-- Audit trail: failed/successful logins, lockouts, IP bans, admin actions.
-- Doubles as the admin-facing security log.
CREATE TABLE security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    username    TEXT,
    ip_address  TEXT,
    detail      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_security_events_ip_time ON security_events(ip_address, created_at);
CREATE INDEX idx_security_events_created ON security_events(created_at);

-- IPs temporarily blocked from even reaching the login page after too many
-- failed attempts across any account. Auto-expires via banned_until.
CREATE TABLE banned_ips (
    ip_address    TEXT PRIMARY KEY,
    banned_until  TEXT NOT NULL,
    reason        TEXT
);
