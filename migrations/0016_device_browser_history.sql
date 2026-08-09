-- Browsing history pulled from the kids-mdm-browser fork's own journal
-- `ContentProvider` by the launcher client and forwarded here - same shape and
-- rationale as migrations/0015_device_journal.sql (kids-mdm-im), but URL
-- visits don't have a thread/recipient, so this is its own table rather than
-- reusing device_journal_entries. remote_id is the provider's own monotonic
-- `_id`, unique per device (not globally) - the UNIQUE constraint plus an
-- upsert on conflict is what makes retrying an unacknowledged batch safe.
CREATE TABLE device_browser_history_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    remote_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    visited_at INTEGER NOT NULL,
    device_created_at INTEGER NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(device_id, remote_id)
);

CREATE INDEX idx_device_browser_history_entries_device_time
    ON device_browser_history_entries(device_id, visited_at DESC);
