-- Conversation journal pulled from kids-mdm-im (a Molly/Signal fork) by the
-- launcher client and forwarded here - see kids-launcher-mdm's JournalSync.kt
-- and this repo's CLAUDE.md. remote_id is the provider's own monotonic `_id`,
-- unique per device (not globally) - the UNIQUE constraint plus an upsert on
-- conflict is what makes retrying an unacknowledged batch safe.
CREATE TABLE device_journal_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    remote_id INTEGER NOT NULL,
    thread_id INTEGER NOT NULL,
    recipient_id TEXT NOT NULL,
    display_name TEXT,
    direction TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    body TEXT,
    media_content_type TEXT,
    media_path TEXT,
    call_type TEXT,
    call_event TEXT,
    device_created_at INTEGER NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(device_id, remote_id)
);

CREATE INDEX idx_device_journal_entries_thread
    ON device_journal_entries(device_id, thread_id, occurred_at);
