# Kid Phone Server

A self-hosted parental-control admin server for Android phones running in [Device Owner mode](https://developer.android.com/work/dpc/build-dpc). Built to pair with [`kids-launcher-mdm`](https://github.com/siesta5787/kids-launcher-mdm), a custom Android launcher that doubles as the on-device management agent - this repo is the parent-facing web app that controls it.

Designed to run on very light hardware (a Raspberry Pi Zero 2 W is the reference target) and to actually be usable by a non-technical parent: every setting is a real web form, there's no database console involved.

## Features

- **Device enrollment** via a short, one-shot, human-typeable code - no QR scanning or manually typing server URLs/tokens on the phone.
- **App allowlist**, built from the phone's own self-reported installed-app list (real checkboxes, not hand-typed Android package names).
- **Kiosk (lock-task) mode** with per-device control over which system chrome stays available while pinned - status bar, notifications, home button, recents, power menu, lock screen.
- **Bedtime / screen-time schedule**, separate weekday and weekend windows.
- **WiFi / Bluetooth restriction levels** (open / restricted / disabled).
- **Offline override PIN** - a parent-set failsafe that works with zero network connectivity, for when a policy or update ever leaves a phone unreachable.
- **Launcher app updates**, pushed and installed silently via Device Owner APIs - upload a new build here, phones pick it up on their next sync.
- Mandatory 2FA admin login, account lockout / IP-ban security log, scheduled backups, and self-update, all built in.
- Installable as a PWA; bottom-tab mobile-first UI with light/dark theming that follows your device.

## Tech stack

Rust + [Axum](https://github.com/tokio-rs/axum) + SQLite (via `sqlx`, WAL mode) + [Askama](https://github.com/askama-rs/askama) for compile-time-checked server-rendered HTML - no JS framework, no frontend build step. Sessions via `tower-sessions`, admin passwords hashed with `argon2`.

## Deploying

See [DEPLOY.md](DEPLOY.md) for the full walkthrough. Short version, on a 64-bit Raspberry Pi (or any aarch64 Linux box):

```bash
curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash
```

This installs a systemd service listening on `127.0.0.1:3100` only - put it behind [Tailscale](https://tailscale.com/) (or your own reverse proxy/VPN) to reach it remotely. It prints a one-time admin password on first install; you'll be forced to change it and set up two-factor login before anything else works.

## Development

```bash
cp .env.example .env   # fill in an admin username/password
cargo run
```

See [CLAUDE.md](CLAUDE.md) for architecture notes and the device-facing API contract.

## License

[GNU General Public License v3.0](LICENSE) or later.
