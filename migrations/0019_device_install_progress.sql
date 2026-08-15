-- Transient per-device, per-tracked-app download/install progress, purely to drive the unified
-- Apps list's "Installing NN%" status label (see handlers::devices) - not permanent history, just
-- overwritten on every report from the device. A row here is only ever meaningful for a device's
-- own currently-selected-but-not-yet-installed catalog apps; once an app actually finishes
-- installing it moves to the Installed status via installed_apps_json instead, and a row here
-- becomes irrelevant (still cleaned up eventually by ON DELETE CASCADE if the device or tracked
-- app is removed, but otherwise left to just go stale - see the staleness window in devices.rs).
CREATE TABLE device_install_progress (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tracked_app_id INTEGER NOT NULL REFERENCES tracked_apps(id) ON DELETE CASCADE,
    percent INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (device_id, tracked_app_id)
);
