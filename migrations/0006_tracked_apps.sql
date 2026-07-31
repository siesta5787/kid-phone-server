-- Apps watched on GitHub Releases and auto-pushed to devices, generalizing
-- the launcher's own self-update mechanism to arbitrary third-party apps
-- (e.g. Tailscale). One row per app, one cached "current" release each - no
-- rollback history, since nobody's rolling e.g. Tailscale back to an old
-- build the way the launcher's release history is kept for review.
CREATE TABLE tracked_apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    package_name TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    asset_pattern TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    latest_release_tag TEXT,
    latest_release_file_path TEXT,
    last_checked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
