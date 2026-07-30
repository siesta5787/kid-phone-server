-- Uploaded launcher APKs. The highest id is always "current" - no per-device
-- pinning, no rollback UI beyond whatever's still on disk. version_code is
-- entered by the admin on upload rather than parsed out of the APK's binary
-- manifest, to avoid an AXML-parsing dependency for something a human only
-- has to type once per release.
CREATE TABLE launcher_releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_code INTEGER NOT NULL,
    version_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Lets the admin pages show "this device is on code X, latest available is
-- code Y" instead of just an opaque version string.
ALTER TABLE device_status ADD COLUMN app_version_code INTEGER;
