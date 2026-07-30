# Kid Phone Server — Project Context for Claude Code

## What this is

A lightweight, purpose-built parental-control server for the Kid Phone project, replacing Headwind MDM + a custom `kidmode-plugin` (Java/Tomcat/Postgres/AngularJS). The old stack proved the underlying Device-Owner Android approach works, but its admin side was never actually usable by a non-technical parent — every policy change needed a raw `psql` insert. This rewrite exists to give a parent a genuinely simple web UI for managing their kids' phones, while staying lightweight enough to run on a Raspberry Pi Zero 2 W.

The client is a separate repo: `kids-launcher-mdm` (a custom Kotlin Android launcher that's also the Device-Owner MDM agent, package `com.kidslauncher.mdm`, networking code in `headwind/`). As of this server's initial build, the client still speaks the *old* Headwind-style protocol - a follow-up session/plan is needed to rewrite the client's `headwind/` package to speak this server's API instead. Don't assume the client already matches this contract.

## Tech stack

Deliberately mirrors `board-game-tracker` (another self-hosted Pi app by the same developer) since it already solved the boring-but-essential infrastructure for this exact hardware target:

- **Language:** Rust, **Web framework:** Axum, **Database:** SQLite via `sqlx` (WAL mode)
- **Templating:** Askama (compile-time-checked server-rendered HTML, no JS build step, no frontend framework)
- **Sessions/auth:** `tower-sessions` + `tower-sessions-sqlx-store`, `argon2` for the admin password
- **Hosting target:** Raspberry Pi Zero 2 W running DietPi, `aarch64-unknown-linux-musl` cross-compiled via GitHub Actions (same target board-game-tracker already validated)

## About the developer

No prior programming experience - build features directly rather than explaining Rust concepts, but loop them in on real architecture/schema/UX decisions and explain the *why* in plain language.

## Architecture

- **Two completely separate auth systems**: admin sessions (`tower-sessions`, cookie-based, for the parent-facing web UI) and device bearer tokens (`Authorization: Bearer <token>`, for the phone's API calls). A device is never a session; an admin never touches the device API.
- **Enrollment is a one-shot code, not a device-number+URL pair.** The admin generates a short human-typeable code from a device's page; the phone POSTs it once to `/api/devices/enroll` and gets back a bearer token in return. The code is cleared from the DB the moment it's used - it can never be replayed. This replaces the old flow of typing a raw server URL and a made-up device number.
- **`kiosk_desired` is server-authoritative**, unlike the client's current (pre-rewrite) design where a local on-device switch was the source of truth. That local-switch design had a real gap: the toggle lived in the *kid's own* Settings screen (never suspended, since it's the launcher's own package), so a kid could just switch it back off. The new model: the admin UI sets `kiosk_desired` in `device_policy`, the device applies it automatically on its next sync - no on-device confirmation. (The client hasn't been updated to actually do this yet - see "not yet built" below.)
- **Friendlier allowlist**: the device reports its installed apps (`{package_name, label}` pairs) in every status heartbeat; the admin UI renders checkboxes from that real, current list rather than asking a parent to hand-type Android package names. See `device_status.installed_apps_json` and `handlers::devices::view_device`.
- **Schedule fields are minutes-since-midnight** (`weekday_start_minutes` etc.), matching the client's already-built, already-unit-tested `KidModeEnforcer.kt` decision logic (including its overnight-wraparound handling for bedtime windows that cross midnight) - the server just stores/serves this data, it doesn't evaluate the lock decision itself. The admin UI converts to/from HTML `<input type="time">` values (`HH:MM`) at the handler boundary (`devices::minutes_to_time_input`/`time_input_to_minutes`).

## Non-obvious gotcha hit during the initial build

**axum's built-in `Form` extractor cannot deserialize repeated same-named form fields (e.g. multiple checked checkboxes named `allowed_packages`) into a `Vec<String>`** - it errors with `invalid type: string "...", expected a sequence`. This is a real limitation of the underlying deserializer, not a bug in this app's code. Fixed in `handlers::devices::update_policy` by taking the raw `axum::body::Bytes` and parsing manually with the `form_urlencoded` crate instead of using `Form<T>`. If any future form needs a repeated-checkbox-group field, use this same pattern rather than `Form<T>` with a `Vec` field.

## Data model (SQLite, see `migrations/0001_init.sql`)

- `admin_users` - parent login accounts (single or a small handful)
- `devices` - one row per kid's phone: name, enrollment code (+ expiry, cleared on use), hashed bearer token, enrolled/last-seen timestamps
- `device_policy` - one row per device: allowlist JSON, schedule windows, `kiosk_desired`, and a reserved-but-unused `lock_task_features` column for later per-device configurability of which OS chrome features (notifications, recents, keyguard, etc.) stay available in kiosk mode
- `device_status` - append-only heartbeat log: lock reason, kiosk-engaged (device-reported, may lag `kiosk_desired` briefly), installed-app snapshot, app version, timestamp

## Device-facing API (plain JSON, no envelope)

- `POST /api/devices/enroll` - `{enrollment_code}` → `{device_id, device_token}`
- `GET /api/devices/policy` (bearer) → allowlist, schedule, `kiosk_desired`
- `POST /api/devices/status` (bearer) - `{lock_reason, kiosk_engaged, installed_apps, app_version}` → 204

## Current status / what's built

- **Phase 0-3 complete and verified end-to-end** (browser-tested UI + curl-tested API, 2026-07-30): admin login with forced first-password-change, device list, add-device (enrollment code generation + regeneration), full enroll → policy fetch → status report loop via curl, per-device page with real allowlist checkboxes populated from a curl-simulated status report, schedule time-picker round-trip, kiosk toggle persisting to `kiosk_desired`.
- **Not yet built**: Phase 4 (actual deploy to the physical Pi Zero 2 W / DietPi - `deploy/install.sh` etc. are written but untested against real hardware), and the separate client-rewrite plan (kids-launcher-mdm's `headwind/` package still speaks the old Headwind protocol and still uses the local kiosk-mode switch, not `kiosk_desired`).
- **Explicitly deferred** (not scope-creep, just not this round): TOTP/2FA on admin login (board-game-tracker has a ready-to-port implementation if this ever gets exposed beyond LAN/tailnet), scheduled backups + external-drive support + self-update-from-the-web-UI (all proven patterns in board-game-tracker's `deploy/install.sh`/`security_events`-style hardening, worth porting once the core is stable), the `lock_task_features` bitmask UI, notification listener, DNS/network restriction.
