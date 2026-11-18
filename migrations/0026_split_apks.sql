-- Split APKs: many Google Play apps come as a base APK plus "split" APKs
-- (per processor type, screen density, language), which have to be
-- installed together in one go. A release's base APK stays in
-- latest/pending_release_file_path; these hold the rest, as a JSON list of
-- {"name": ..., "path": ...}. NULL or [] = a single-APK release (every
-- GitHub/manual release). Play releases with splits live in their own
-- folder, so deleting one removes the whole folder. Launchers older than
-- v0.55.0 can't install these and aren't offered them
-- (handlers::device_api::tracked_app_updates).
ALTER TABLE tracked_apps ADD COLUMN latest_release_splits_json TEXT;
ALTER TABLE tracked_apps ADD COLUMN pending_release_splits_json TEXT;
