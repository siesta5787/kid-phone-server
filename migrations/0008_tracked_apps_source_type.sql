-- Unifies the launcher's own self-update (previously the separate
-- launcher_releases table) into tracked_apps: source_type distinguishes
-- GitHub-tracked apps (existing behavior) from manually-uploaded ones.
-- include_prereleases lets a GitHub-tracked app follow a rolling/
-- prerelease-only tag (e.g. the launcher's own "pre-release" tag, which
-- GitHub's /releases/latest endpoint would otherwise never return).
-- latest_release_asset_id is the GitHub release asset's own numeric id -
-- needed because a rolling tag's tag_name never changes between pushes,
-- so tag_name alone can't detect a new build; the asset gets a new id each
-- time it's replaced. NULL for manually-uploaded apps, which don't have
-- this problem (the admin types a new label on every upload).
ALTER TABLE tracked_apps ADD COLUMN source_type TEXT NOT NULL DEFAULT 'github';
ALTER TABLE tracked_apps ADD COLUMN include_prereleases INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tracked_apps ADD COLUMN latest_release_asset_id INTEGER;
