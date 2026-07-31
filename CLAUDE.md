# Kid Phone Server — Project Context for Claude Code

## What this is

A lightweight, purpose-built parental-control server for the Kid Phone project. It's the sole backend for the client - there is no other MDM server or protocol involved. An earlier prototype used a different MDM stack entirely; that's been fully replaced, not extended, and none of its code, protocol, or data model carried over.

The client is a separate repo: `kids-launcher-mdm` (a custom Kotlin Android launcher that's also the Device-Owner MDM agent, package `com.kidslauncher.mdm`, networking code in `server/`). It speaks this server's API directly - enrollment, policy fetch, and status reporting are all this repo's own device-facing routes under `/api/devices/*`. See that repo's own `CLAUDE.md` for client-side architecture.

**Both repos are public** (as of 2026-07-31): `siesta5787/kid-phone-server` (GPLv3) and `siesta5787/kids-launcher-mdm` (GPLv3 for its own code; the inherited app-list screen stays MIT per `LICENSE-MIT-UPSTREAM` in that repo - it's a fork of Josia Pietsch's µLauncher, though the fork no longer describes itself that way since almost everything else - the gesture system, Minimalist Mode, the whole parental-control layer - is original).

## Tech stack

Deliberately mirrors `board-game-tracker` (another self-hosted Pi app by the same developer) since it already solved the boring-but-essential infrastructure for this exact hardware target:

- **Language:** Rust, **Web framework:** Axum, **Database:** SQLite via `sqlx` (WAL mode)
- **Templating:** Askama (compile-time-checked server-rendered HTML, no JS build step, no frontend framework) - templates are compiled into the binary, so editing one requires a rebuild, not just a file save. A plain `cargo run` dev server (no `cargo watch`) needs to be manually killed and restarted after any template/static change.
- **Sessions/auth:** `tower-sessions` + `tower-sessions-sqlx-store`, `argon2` for the admin password, mandatory TOTP 2FA
- **UI:** mobile-first bottom tab bar (Dashboard / Devices / Apps / Settings, see `templates/partials/app_header.html`), installable PWA (`static/manifest.webmanifest`, minimal install-only service worker at `templates/sw.js` - no offline page caching, deliberately, since this app handles session cookies and device bearer tokens), light/dark theming via `prefers-color-scheme` CSS variables (no manual toggle)
- **Hosting target:** Raspberry Pi Zero 2 W (or similar aarch64 board), `aarch64-unknown-linux-musl` cross-compiled via GitHub Actions on every `v*` tag (`.github/workflows/release.yml`, uses `cross`) - `deploy/install.sh` downloads the latest release and sets up a systemd service

## About the developer

No prior programming experience - build features directly rather than explaining Rust concepts, but loop them in on real architecture/schema/UX decisions and explain the *why* in plain language.

## Architecture

- **Two completely separate auth systems**: admin sessions (`tower-sessions`, cookie-based, for the parent-facing web UI) and device bearer tokens (`Authorization: Bearer <token>`, for the phone's API calls). A device is never a session; an admin never touches the device API.
- **Enrollment is a one-shot code, not a device-number+URL pair.** The admin generates a short human-typeable code from a device's page; the phone POSTs it once to `/api/devices/enroll` and gets back a bearer token in return. The code is cleared from the DB the moment it's used - it can never be replayed.
- **`kiosk_desired` is server-authoritative** - the admin UI sets it, the device applies it automatically on its next sync, no on-device confirmation or local override switch. Fully built and confirmed working live on the physical test phone, including the full `lock_task_features` bitmask (status bar info, notifications, home, recents, power menu, keyguard - all six independently toggleable per device).
- **Friendlier allowlist**: the device reports its installed apps (`{package_name, label}` pairs) in every status heartbeat; the admin UI renders checkboxes from that real, current list rather than asking a parent to hand-type Android package names. See `device_status.installed_apps_json` and `handlers::devices::view_device`.
- **Schedule fields are minutes-since-midnight** (`weekday_start_minutes` etc.), matching the client's `KidModeEnforcer.kt` decision logic (including overnight-wraparound for bedtime windows crossing midnight) - the server just stores/serves this data. The admin UI converts to/from HTML `<input type="time">` values at the handler boundary (`devices::minutes_to_time_input`/`time_input_to_minutes`); an empty string round-trips to `NULL`/no-restriction correctly (there are explicit "Clear schedule" buttons in `device_detail.html` since native time inputs don't reliably expose a way to blank themselves).
- **WiFi/Bluetooth restrictions**: `wifi_mode`/`bluetooth_mode` per device, `"open" | "restricted" | "disabled"`. WiFi only supports open/restricted (the "disabled" mode was removed client-side - unreliable in testing, no strong use case). Bluetooth keeps all three, confirmed working.
- **Offline override PIN**: a per-device PIN (PBKDF2-HMAC-SHA256, `security::hash_pin`/`verify_pin`), cached hashed on the device so it verifies with zero network. Entering it correctly on the phone lifts every restriction for a bounded window and self-heals the moment the device can reach the server again. The client's Settings screen is also gated behind this same PIN, plus a separate manually-toggled "pause all restrictions" kill-switch that does *not* auto-clear (unlike the PIN override) - an emergency escape hatch if a policy or client update ever ships something broken.
- **Apps tab is a list+detail structure** (`/apps` → `/apps/launcher`), not a single page - deliberately future-proofed for more than just the launcher, even though only the launcher exists today.

## Non-obvious gotchas hit so far

- **axum's built-in `Form` extractor cannot deserialize repeated same-named form fields** (e.g. multiple checked checkboxes named `allowed_packages`) into a `Vec<String>` - errors with `invalid type: string "...", expected a sequence`. Fixed in `handlers::devices::update_policy` by taking raw `axum::body::Bytes` and parsing manually with `form_urlencoded` instead of `Form<T>`. Reuse this pattern for any future repeated-checkbox-group field.
- **Browsers cache `/static/*` assets aggressively with no revalidation** - editing `style.css` and reloading can silently keep serving the old cached copy even after a hard navigate. `partials/head.html` links it with a `?v=N` cache-busting query param (bump `N` when the stylesheet changes) - the same pattern `board-game-tracker` already uses.
- **The dev server is a plain `cargo run`, not `cargo watch`** - it will not pick up template or static-file changes on its own. Kill the running `cargo`/`kid_phone_server` processes and restart after any such edit, or you'll be testing against stale HTML/CSS while genuinely-fresh files sit on disk (this has caused real confusion mid-session more than once).

## Data model (SQLite, see `migrations/`)

- `admin_users` - parent login accounts, TOTP secret, forced-password-change flag
- `devices` - one row per kid's phone: name, enrollment code (+ expiry, cleared on use), hashed bearer token, enrolled/last-seen timestamps
- `device_policy` - one row per device: allowlist JSON, schedule windows, `kiosk_desired`, `lock_task_features` (bitmask), `wifi_mode`/`bluetooth_mode`, `override_pin_hash`/`override_pin_salt`
- `device_status` - append-only heartbeat log: lock reason, kiosk-engaged, installed-app snapshot, app version, timestamp, `offline_override_used`
- `security_events` / `banned_ips` - admin login audit trail and lockout tracking
- `launcher_releases` - uploaded APK builds the device-facing update endpoints serve from

## Device-facing API (plain JSON, no envelope)

- `POST /api/devices/enroll` - `{enrollment_code}` → `{device_id, device_token}`
- `GET /api/devices/policy` (bearer) → allowlist, schedule, `kiosk_desired`, `lock_task_features`, `wifi_mode`, `bluetooth_mode`, `override_pin_hash`/`override_pin_salt`
- `POST /api/devices/status` (bearer) - `{lock_reason, kiosk_engaged, installed_apps, app_version, app_version_code, offline_override_used}` → 204
- `GET /api/devices/launcher-update` / `GET /api/devices/launcher-update/download` (bearer) - silent self-update check/download

## Current status (2026-07-31)

Feature-complete relative to the original build plan and confirmed working end-to-end on the physical test phone, not just built-and-reviewed: enrollment, allowlist, kiosk mode + full lock-task feature bitmask, schedule (with working clear), WiFi/Bluetooth restrictions, offline override PIN, Settings PIN-gate, pause-all-restrictions kill-switch, mandatory 2FA admin login, scheduled backups + external-drive support, self-update, and the new bottom-tab/PWA admin UI.

**`v0.1.0` has been tagged and released** via GitHub Actions (the aarch64 binary is attached to the GitHub Release). **Deployment to the real physical Pi was in progress as of this writing** - `deploy/install.sh` steps were handed to the user for a Pi separate from the one running `board-game-tracker`, reachable via `tailscale serve` (not `funnel` - stays tailnet-only). Confirm on resuming whether that deployment actually completed, and if so, whether the dev-server SQLite DB on the Windows dev machine (all of today's test configuration) or a fresh database is what's live there - the user chose "start fresh" rather than migrating the dev DB over.

**Not started** (explicitly deferred, not scope-creep):
- Real server-to-device push (most likely UnifiedPush, not FCM - this project avoids Google/Play Services by design) - 2-minute polling is the accepted interim tradeoff.
- Notification listener / message monitoring and DNS-level browsing restriction (Pi-hole/AdGuard) - see the root `PROJECT_CONTEXT.md`'s staged messaging-monitoring plan, still fully on the roadmap, not started on either client or server.
- Tamper-resistant/launcher-watchdog persistence (auto-restart on crash) - not built on either the old or new client.
