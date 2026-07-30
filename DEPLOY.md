# Deploying to a Raspberry Pi / DietPi

These steps get Kid Phone Server running on a Raspberry Pi Zero 2 W. Only 64-bit (aarch64) is supported.

## 1. Install

SSH into the Pi, then run:

```
curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash
```

This downloads the latest release binary, sets it up as a background service that starts on boot, and prints an admin username/password at the end — **save that password**, you'll need it to log in the first time (and you'll be asked to change it immediately after).

The app only listens on the Pi itself (`127.0.0.1:3100`) by default — that's intentional for security.

## 2. Make it reachable

If you're already running Tailscale on this Pi (e.g. alongside board-game-tracker), just visit `http://<pi-tailscale-ip>:3100` from your tailnet, or add a reachable hostname/port however you already expose other services on this box. A public Funnel URL is optional and not required for this app to work over your own tailnet.

## Updating

```
curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/update.sh | sudo bash
```

Downloads the latest release and swaps the binary in place. Doesn't touch your `.env` or database.

## Useful commands on the Pi

- Check it's running: `systemctl status kid-phone-server`
- View logs: `journalctl -u kid-phone-server -f`
- Restart it: `sudo systemctl restart kid-phone-server`

## Backups

Not yet built — the database lives at `/opt/kid-phone-server/data/kidphone.db`. Copy that file somewhere safe periodically until scheduled backups (same pattern as board-game-tracker's) get ported over.
