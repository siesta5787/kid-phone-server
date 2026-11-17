-- App groups: a parent-named set of apps on one device (e.g. "Streaming",
-- "Games") that share one daily time limit, one allowed-hours window, and
-- one pause/allow override - so a parent manages a handful of groups rather
-- than a setting per app. Per device, since the apps to pick from come from
-- that device's own installed-app report. An app belongs to at most one
-- group per device (enforced in handlers::app_groups, not by the schema,
-- since packages live in a JSON list like device_policy.allowlist_json).
--
-- The phone does the actual enforcing (suspends the group's apps while the
-- group is blocked, see kids-launcher-mdm's AppGroups.kt) and counts time
-- used itself, against its own clock - so it keeps working offline. The
-- server only stores the rules and the phone's last usage report.
CREATE TABLE app_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    -- JSON array of Android package names.
    packages_json TEXT NOT NULL DEFAULT '[]',
    -- Shared daily budget across every app in the group, in minutes. NULL =
    -- no limit. Resets at midnight on the phone's clock.
    daily_limit_minutes INTEGER,
    -- Allowed hours, minutes-since-midnight like the schedule columns. NULL
    -- (or start == end) = any time. Overnight windows (start > end) wrap.
    allowed_start_minutes INTEGER,
    allowed_end_minutes INTEGER,
    -- A parent's "Pause" ('pause') / "Allow" ('allow') from the device page,
    -- beating the limit and allowed hours until override_until_ms (epoch
    -- millis, checked on the phone's clock), or NULL = until changed. Same
    -- shape as device_policy.lock_override.
    override_mode TEXT,
    override_until_ms INTEGER,
    -- Last usage report from the phone: minutes used on usage_day (the
    -- phone's local date, YYYY-MM-DD), and why the phone has the group
    -- blocked right now ('PAUSED', 'OUTSIDE_HOURS', 'TIME_UP', or NULL).
    used_minutes INTEGER,
    usage_day TEXT,
    blocked_reason TEXT,
    usage_reported_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_app_groups_device_id ON app_groups (device_id);

-- Whether the launcher has Android's "usage access" (needed to count time
-- for daily limits). NULL = a launcher too old to report it.
ALTER TABLE device_status ADD COLUMN usage_access_granted INTEGER;
