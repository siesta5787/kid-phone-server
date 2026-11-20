-- Where a phone is downloading a tracked app from (launcher v0.56.0+):
-- 'google_play' or 'github' when it fetches the files straight from there
-- (GET /api/devices/apps/{id}/direct), 'server' when it downloads this
-- server's copy. NULL from older launchers. Shown next to the download
-- progress on the device page.
ALTER TABLE device_install_progress ADD COLUMN source TEXT;
