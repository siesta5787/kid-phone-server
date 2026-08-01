-- Bitmask for the launcher's swipe-left-from-home "Quick Controls" screen,
-- the kid-facing replacement for Android's native Quick Settings shade (see
-- kids-launcher-mdm's AppEnforcer.applyVpnRestrictions doc comment for why
-- that shade can't be relied on). Bits: 1 = WiFi, 2 = Bluetooth, 4 = brightness.
ALTER TABLE device_policy ADD COLUMN quick_controls_mask INTEGER NOT NULL DEFAULT 0;
