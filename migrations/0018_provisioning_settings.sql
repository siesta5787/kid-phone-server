-- Global settings embedded into every device's QR provisioning payload
-- (android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE, plus the app's own
-- in-app QR scanner for devices where Android's native zero-touch flow
-- doesn't run, e.g. GrapheneOS). Singleton, same pattern as
-- dns_filter_settings/global_schedule - one server, and a Tailscale
-- pre-auth key is reusable across every device by definition, so neither
-- value is meaningfully per-device.
CREATE TABLE provisioning_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_url TEXT NOT NULL DEFAULT '',
    tailscale_auth_key TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO provisioning_settings (id) VALUES (1);
