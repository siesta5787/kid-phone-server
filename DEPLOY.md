# Deploying to a Raspberry Pi / DietPi

These steps get Kids Device MDM running on a Raspberry Pi Zero 2 W. Only 64-bit (aarch64) is supported.

## 1. Install

SSH into the Pi, then run:

```
curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash
```

This downloads the latest release binary, sets it up as a background service that starts on boot, and prints an admin username/password at the end — **save that password**, you'll need it to log in the first time (and you'll be asked to change it immediately after).

The app only listens on the Pi itself (`127.0.0.1:3100`) by default — that's intentional for security.

## 2. Make it reachable

For plain tailnet access, visit `http://<pi-tailscale-ip>:3100` from any device on your tailnet - no further setup needed.

For an HTTPS URL (required if you want the admin site to be installable as a PWA - plain HTTP doesn't qualify), use `tailscale serve`, **not** `tailscale funnel` (funnel makes it public on the internet, which you don't want for a parental-control panel):

```
sudo tailscale serve --bg --https=443 http://127.0.0.1:3100
```

This gives you `https://<hostname>.<tailnet>.ts.net`, reachable only from your own tailnet. If this Pi already serves something else on port 443 (e.g. `board-game-tracker`), use a different port instead, e.g. `--https=8443`.

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

Built in - see the **Backups** page under Settings in the admin UI. Create a backup on demand, set a schedule for automatic ones, and optionally mirror them live to an external drive plugged into the Pi. The database itself lives at `/opt/kid-phone-server/data/kidphone.db` if you ever need it directly.
