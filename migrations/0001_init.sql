CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One row per kid's phone. `enrollment_code`/`enrollment_code_expires_at` are
-- only ever set while waiting for that specific device to enroll - cleared
-- (set NULL) the moment enrollment succeeds, so a code can never be reused
-- afterward. `token_hash` is SHA-256 of the bearer token handed to the device
-- at enrollment time; we only ever store/compare the hash, never the token
-- itself, the same way a password would be handled.
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enrollment_code TEXT UNIQUE,
    enrollment_code_expires_at TEXT,
    token_hash TEXT UNIQUE,
    enrolled_at TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One row per device (created on enrollment, updated in place thereafter).
-- `kiosk_desired` is the server-authoritative switch - the device applies it
-- automatically, no on-device confirmation required (see kid-phone-server
-- CLAUDE.md for why this differs from the client's original design).
-- `lock_task_features` is reserved for later per-device configurability of
-- which OS chrome features stay available in kiosk mode (system info,
-- notifications/quick-settings, home, overview, global actions, keyguard) -
-- unused for now, always NULL, until that client-side work happens.
CREATE TABLE device_policy (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    allowlist_json TEXT,
    weekday_start_minutes INTEGER,
    weekday_end_minutes INTEGER,
    weekend_start_minutes INTEGER,
    weekend_end_minutes INTEGER,
    bedtime_start_minutes INTEGER,
    bedtime_end_minutes INTEGER,
    kiosk_desired INTEGER NOT NULL DEFAULT 0,
    lock_task_features INTEGER,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Append-only heartbeat log posted by the device on every sync. Kept
-- separate from `devices`/`device_policy` (which hold current/desired state)
-- so the admin UI can show recent history, not just a single snapshot.
-- `installed_apps_json` is a JSON array of {package_name, label} pairs,
-- refreshed on every heartbeat - the admin UI's allowlist checkboxes are
-- built from the most recent row per device, not hand-typed package names.
CREATE TABLE device_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    lock_reason TEXT NOT NULL DEFAULT 'NONE',
    kiosk_engaged INTEGER NOT NULL DEFAULT 0,
    installed_apps_json TEXT,
    app_version TEXT,
    reported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_device_status_device_id_reported_at
    ON device_status (device_id, reported_at DESC);
