-- Admin UI cleanup: kiosk mode is no longer a per-device on/off (every
-- device is kiosk-mode-only now, matching how this project is actually
-- used - see handlers::devices), and the WiFi/Bluetooth restriction-level
-- dropdowns are retired outright (not useful in practice). Schedules move
-- off the individual device page onto their own page, with a global
-- default plus an explicit opt-in per-device override - see
-- handlers::schedules.

ALTER TABLE device_policy DROP COLUMN wifi_mode;
ALTER TABLE device_policy DROP COLUMN bluetooth_mode;

-- Existing weekday/weekend/bedtime *_minutes columns on device_policy are
-- kept as-is - they're now this device's *override* values, only actually
-- used when custom_schedule_enabled is set. A device that's never had this
-- turned on just follows global_schedule below, whatever its own (unused)
-- columns happen to contain.
ALTER TABLE device_policy ADD COLUMN custom_schedule_enabled INTEGER NOT NULL DEFAULT 0;

-- Singleton, same pattern as dns_filter_settings - one global default
-- schedule, editable from the new Schedules page.
CREATE TABLE global_schedule (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    weekday_start_minutes INTEGER,
    weekday_end_minutes INTEGER,
    weekend_start_minutes INTEGER,
    weekend_end_minutes INTEGER,
    bedtime_start_minutes INTEGER,
    bedtime_end_minutes INTEGER,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO global_schedule (id) VALUES (1);
