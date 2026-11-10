-- A parent's "Lock now" / "Unlock now" from a device's page, overriding the
-- bedtime/screen-time schedule regardless of what it says. lock_override is
-- 'lock', 'unlock', or NULL (follow the schedule). lock_override_until_ms is
-- when it lapses back to the schedule (Unix epoch milliseconds, so the phone
-- can check it against its own clock while offline), or NULL for "until the
-- parent puts it back on the schedule". See handlers::devices::set_lock_override.
ALTER TABLE device_policy ADD COLUMN lock_override TEXT;
ALTER TABLE device_policy ADD COLUMN lock_override_until_ms INTEGER;
