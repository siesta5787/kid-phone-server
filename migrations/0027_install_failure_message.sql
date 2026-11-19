-- Why a device's install of a tracked app failed - Android's own status
-- message (e.g. "INSTALL_FAILED_OLDER_SDK: ...") or the download error, sent
-- by launcher v0.55.1+ with the failure report. NULL while installing, or
-- from older launchers. Shown under the app on the device page.
ALTER TABLE device_install_progress ADD COLUMN failure_message TEXT;
