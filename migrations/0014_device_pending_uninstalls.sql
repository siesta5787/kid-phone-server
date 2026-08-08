-- Queued app-uninstalls, driven by unchecking "Apps to install" for an already-installed tracked
-- app (see handlers::devices::toggle_tracked_app). Deliberately not reusing the device_commands
-- table's ring/lock/wipe queue - that has "last action wins" single-slot replace semantics (see
-- handlers::locate::queue_command) that would let an unrelated ring/lock queued afterward silently
-- clobber a pending uninstall before the device ever saw it. Self-cleaning instead: once a
-- device's status report no longer lists the package as installed, handlers::device_api::status
-- deletes the row - no separate "uninstall result" round trip needed.
CREATE TABLE device_pending_uninstalls (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    PRIMARY KEY (device_id, package_name)
);
