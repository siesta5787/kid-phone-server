-- Scopes which tracked apps get pushed to which devices - previously every
-- enabled tracked app installed on every device, with no way to give one
-- kid an app without giving it to all of them. Presence of a row here means
-- "install this app on this device"; absence means "don't" - opt-in, not
-- opt-out, since a newly-added app in the global Apps list shouldn't
-- silently start installing everywhere.
CREATE TABLE device_tracked_apps (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tracked_app_id INTEGER NOT NULL REFERENCES tracked_apps(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, tracked_app_id)
);

-- Marks the one tracked_apps row that is the launcher/MDM agent itself -
-- can't be deleted from the Apps list or deselected on any device (enforced
-- in handlers::tracked_apps::delete_tracked_app and handlers::devices, not
-- just hidden in the UI). It's deliberately never given a row in
-- device_tracked_apps above - it's unconditionally included in the resolved
-- per-device app list instead (see handlers::device_api::tracked_app_updates),
-- since there's no real-world case for a kid's phone not running the app
-- that enforces every other restriction on it, and a plain checkbox risks an
-- admin unchecking it by mistake.
ALTER TABLE tracked_apps ADD COLUMN is_launcher INTEGER NOT NULL DEFAULT 0;
UPDATE tracked_apps SET is_launcher = 1 WHERE package_name = 'com.kidslauncher.mdm';
