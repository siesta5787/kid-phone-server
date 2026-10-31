-- A review step between "a new release was found" and "phones get it". Every new release is read
-- (src/apk.rs) and either published straight away or held as this app's one pending release -
-- either for the parent's approval (new app, different signing key, older version, new sensitive
-- permissions, no 64-bit ARM build, unreadable APK) or just until its hold period runs out.
-- See handlers::tracked_apps::review_reasons/stage_release.
--
-- The live release keeps using the existing latest_release_* columns, so the device-facing API is
-- unchanged and never sees a pending release.

-- apk::ApkInfo of the live release, as JSON. NULL until read (backfilled for releases cached
-- before this migration - see tracked_apps::backfill_release_info).
ALTER TABLE tracked_apps ADD COLUMN latest_apk_json TEXT;
-- The pinned signing certificate (lowercase hex SHA-256). Set from the first published release
-- whose certificate could be read, and only changed when the parent approves a release signed
-- with a different key. Kept separate from latest_apk_json so publishing an unreadable APK (which
-- the parent can approve) never wipes out the pin.
ALTER TABLE tracked_apps ADD COLUMN signing_cert_sha256 TEXT;

ALTER TABLE tracked_apps ADD COLUMN pending_release_tag TEXT;
ALTER TABLE tracked_apps ADD COLUMN pending_release_asset_id INTEGER;
ALTER TABLE tracked_apps ADD COLUMN pending_release_file_path TEXT;
-- NULL when the pending APK couldn't be read.
ALTER TABLE tracked_apps ADD COLUMN pending_apk_json TEXT;
-- JSON array of plain-language reasons the parent needs to look at it. An empty array means it's
-- only waiting out the hold period.
ALTER TABLE tracked_apps ADD COLUMN pending_review_reasons TEXT;
-- When a release waiting out its hold period goes live (UTC, SQLite datetime format). NULL while
-- it needs the parent's approval instead.
ALTER TABLE tracked_apps ADD COLUMN pending_publish_after TEXT;
ALTER TABLE tracked_apps ADD COLUMN pending_found_at TEXT;
-- "{tag}@{asset_id}" of the last release the parent rejected, so the hourly check doesn't download
-- and offer the same one again.
ALTER TABLE tracked_apps ADD COLUMN rejected_release_key TEXT;
-- Days a GitHub release waits before going live, so a broken or malicious release has time to be
-- noticed and pulled upstream. 0 = no wait. Never applied to the launcher's own row or to the
-- parent's own uploads.
ALTER TABLE tracked_apps ADD COLUMN hold_days INTEGER NOT NULL DEFAULT 0;
