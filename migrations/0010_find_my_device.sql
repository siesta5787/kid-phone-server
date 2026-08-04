-- Find My Device: location history + a small remote-command queue
-- (ring/lock/wipe/locate), delivered to the device through the existing
-- policy-fetch/status-report sync cycle rather than any new push mechanism.

CREATE TABLE device_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    accuracy_meters REAL,
    captured_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_device_locations_device_id ON device_locations(device_id, captured_at);

-- A dedicated queue table (not columns bolted onto device_policy) so
-- requested/delivered/acknowledged is a real audit trail, not just current
-- state - matches the security_events table's audit-log instinct elsewhere
-- in this schema. delivered_at is set the moment the device's policy() call
-- serves the command, so a retry before it acknowledges never hands the same
-- command out twice. acknowledged_at is never set for 'wipe' - the device is
-- gone by the time it would report back.
CREATE TABLE device_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    delivered_at TEXT,
    acknowledged_at TEXT,
    result TEXT
);
CREATE INDEX idx_device_commands_device_id ON device_commands(device_id, delivered_at);
