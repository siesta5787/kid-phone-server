-- WiFi/Bluetooth restriction level, one of 'open' | 'restricted' | 'disabled'.
-- See handlers::devices::VALID_RADIO_MODES for the validated set.
ALTER TABLE device_policy ADD COLUMN wifi_mode TEXT NOT NULL DEFAULT 'open';
ALTER TABLE device_policy ADD COLUMN bluetooth_mode TEXT NOT NULL DEFAULT 'open';

-- Offline override PIN: PBKDF2-HMAC-SHA256 hash + salt, sent to the device so
-- it can verify a locally-entered PIN with no network at all. NULL means no
-- PIN configured for this device.
ALTER TABLE device_policy ADD COLUMN override_pin_hash TEXT;
ALTER TABLE device_policy ADD COLUMN override_pin_salt TEXT;

-- Set by the device itself on its next status report if the offline override
-- was used since its last check-in, so a parent notices even though it
-- happened without network.
ALTER TABLE device_status ADD COLUMN offline_override_used INTEGER NOT NULL DEFAULT 0;
