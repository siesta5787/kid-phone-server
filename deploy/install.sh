#!/usr/bin/env bash
# Kid Phone Server — installer for a Raspberry Pi / DietPi (or any Linux/
# systemd box).
#
# Usage (as root, e.g. via sudo):
#   curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash
#
# Safe to re-run: it won't overwrite an existing .env or database, it just
# re-installs the binary/service/watcher scripts (useful for re-running
# after a failure, or to pick up a newer privileged action).

set -euo pipefail

REPO="siesta5787/kid-phone-server"
INSTALL_DIR="/opt/kid-phone-server"
SERVICE_USER="kidphone"

# Bumped only when the privileged scripts below (actions.sh/watcher.sh/
# scheduler.sh/backup_sync.sh) actually gain or change a privileged action -
# independent of the app's own release version, which changes on every
# release including ones that touch nothing here. The app compares this
# against its own required minimum (security::REQUIRED_WATCHER_SCHEMA) to
# decide whether re-running this installer is actually necessary, rather
# than just checking whether the release version strings happen to match.
WATCHER_SCHEMA_VERSION="2"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this as root (e.g. 'sudo bash install.sh')." >&2
    exit 1
fi

case "$(uname -m)" in
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        echo "This installer supports 64-bit (aarch64) Pi OS / DietPi only." >&2
        exit 1
        ;;
esac
echo "Detected architecture: $(uname -m) -> $TARGET"

echo "Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq curl tar unzip iptables >/dev/null

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "Creating service user '$SERVICE_USER'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR"
TARBALL_URL="https://github.com/$REPO/releases/latest/download/kid-phone-server-$TARGET.tar.gz"
echo "Downloading latest release from $TARBALL_URL ..."
curl -sSL "$TARBALL_URL" -o /tmp/kid-phone-server.tar.gz
tar -xzf /tmp/kid-phone-server.tar.gz -C "$INSTALL_DIR"
rm /tmp/kid-phone-server.tar.gz
chmod +x "$INSTALL_DIR/kid_phone_server"

# "latest/download/..." redirects to "download/vX.Y.Z/...", which is the only
# place the actual version tag shows up in this whole download flow. Recorded
# so the app can tell you when the root-side watcher/scheduler scripts (only
# ever refreshed by re-running this installer, never by the in-app update
# button) have fallen behind the app version, instead of silently no-op'ing
# on features the installed watcher doesn't know about yet.
INSTALLED_VERSION="$(curl -sI "$TARBALL_URL" | grep -i '^location:' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"

mkdir -p "$INSTALL_DIR/data"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    echo "No existing .env found — generating one with a fresh admin password."
    # `head -c 24` exiting early sends tr a SIGPIPE, which pipefail treats as
    # a pipeline failure and would abort the whole script under set -e — the
    # password itself is still captured correctly, so just swallow that.
    ADMIN_PASSWORD="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)"
    cat >"$INSTALL_DIR/.env" <<EOF
DATABASE_URL=sqlite://data/kidphone.db
BIND_ADDR=127.0.0.1:3100
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
    PRINT_CREDENTIALS=1
else
    echo "Existing .env found — leaving it untouched."
    PRINT_CREDENTIALS=0
fi

if [ -n "$INSTALLED_VERSION" ]; then
    echo -n "$INSTALLED_VERSION" >"$INSTALL_DIR/data/watcher_version"
fi
echo -n "$WATCHER_SCHEMA_VERSION" >"$INSTALL_DIR/data/watcher_schema_version"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"

echo "Installing systemd service..."
cat >/etc/systemd/system/kid-phone-server.service <<EOF
[Unit]
Description=Kid Phone Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/kid_phone_server
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/data

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kid-phone-server
# `enable --now` only *starts* the unit, which is a no-op if it's already
# running - meaning re-running this installer to pick up a new release
# would silently keep the old binary running forever. Restart explicitly so
# this works the same whether this is a fresh install or a re-run.
systemctl restart kid-phone-server

echo "Installing the update watcher and scheduler..."
# A separate, root-owned component that does the actual privileged work -
# updating the app itself, apt packages, Tailscale, and rebooting.
# kid_phone_server itself runs unprivileged and can only ever drop a flag
# file in its own data/ folder asking for one of a small fixed set of
# actions - it can never reach or modify anything in this directory, even if
# fully compromised, since it lives outside $INSTALL_DIR entirely and
# nothing here is kidphone-writable.
UPDATER_DIR="/opt/kid-phone-server-updater"
mkdir -p "$UPDATER_DIR"

# Placeholder mount point for an optional external backup drive. Doesn't do
# anything by itself - mount a drive here (e.g. via /etc/fstab) and enable
# "copy backups to external drive" on the Backups page to use it.
mkdir -p /mnt/kid-phone-server-backup

# Shared privileged actions, used both by the manual (flag-file-triggered)
# watcher and the automatic (time-triggered) scheduler, so the actual
# commands only need to be reviewed/maintained in one place.
cat >"$UPDATER_DIR/actions.sh" <<'ACTIONS_EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO="siesta5787/kid-phone-server"
DATA_DIR="/opt/kid-phone-server/data"
BACKUP_DIR="$DATA_DIR/backups"

action_app_update() {
    curl -sSL "https://raw.githubusercontent.com/$REPO/master/deploy/update.sh" | bash
}

action_app_restart() {
    systemctl restart kid-phone-server
}

action_os_check() {
    apt-get update -qq
}

action_os_upgrade() {
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
}

action_tailscale_update() {
    tailscale update --yes
}

action_reboot() {
    systemctl reboot
}

# Redirects port-53 DNS traffic arriving over the tailnet interface to the
# app's own in-process DNS filter (see src/dns_engine.rs), which listens on
# a plain unprivileged port (5300) - this rule is the only privileged part
# of that feature. Scoped to tailscale0 specifically, so only traffic from a
# device that's chosen this Pi as its Tailscale exit node is ever affected;
# nothing else on the Pi's network stack is touched. Idempotent - checking
# before adding (rather than just appending) means re-toggling the feature
# on/off repeatedly, or re-running this installer, never leaves duplicate
# rules behind.
action_dns_filter_enable() {
    for proto in udp tcp; do
        iptables -t nat -C PREROUTING -i tailscale0 -p "$proto" --dport 53 \
            -j DNAT --to-destination 127.0.0.1:5300 2>/dev/null || \
        iptables -t nat -A PREROUTING -i tailscale0 -p "$proto" --dport 53 \
            -j DNAT --to-destination 127.0.0.1:5300
    done
}

action_dns_filter_disable() {
    for proto in udp tcp; do
        iptables -t nat -D PREROUTING -i tailscale0 -p "$proto" --dport 53 \
            -j DNAT --to-destination 127.0.0.1:5300 2>/dev/null || true
    done
}

# Formats a removable drive as ext4 and mounts it at the external backup
# path. Defense in depth: independently re-validates the device from
# scratch - matches the expected /dev/sd[a-z] pattern, is actually marked
# removable by the kernel, and is definitely not whatever backs / or /boot
# - regardless of what the (unprivileged, internet-facing) app already
# checked before requesting this, since that process is exactly the one
# component that must never be trusted to have gotten this right on its own.
action_format_drive() {
    local device="$1"

    if [ -z "$device" ]; then
        echo "format_drive: no device specified" >&2
        return 1
    fi
    if ! echo "$device" | grep -qE '^/dev/sd[a-z]$'; then
        echo "format_drive: refusing to format '$device' — doesn't match the expected /dev/sd[a-z] pattern" >&2
        return 1
    fi

    local devname
    devname="$(basename "$device")"
    if [ ! -f "/sys/block/$devname/removable" ] || [ "$(cat "/sys/block/$devname/removable")" != "1" ]; then
        echo "format_drive: refusing to format '$device' — not marked removable by the kernel" >&2
        return 1
    fi

    local root_device boot_device
    root_device="$(findmnt -no SOURCE / | sed -E 's/p?[0-9]+$//')"
    if [ "$device" = "$root_device" ]; then
        echo "format_drive: refusing to format '$device' — this is the root filesystem's device" >&2
        return 1
    fi
    boot_device="$(findmnt -no SOURCE /boot 2>/dev/null | sed -E 's/p?[0-9]+$//' || true)"
    if [ -n "$boot_device" ] && [ "$device" = "$boot_device" ]; then
        echo "format_drive: refusing to format '$device' — this is the boot device" >&2
        return 1
    fi

    echo "Formatting $device as ext4..."
    umount "${device}"* 2>/dev/null || true
    mkfs.ext4 -F -q "$device"

    mkdir -p /mnt/kid-phone-server-backup
    local uuid
    uuid="$(blkid -s UUID -o value "$device")"

    # Replace any existing fstab entry for this mount point first, so
    # re-formatting a previously-configured drive doesn't leave stale
    # duplicate entries behind.
    sed -i '\#/mnt/kid-phone-server-backup#d' /etc/fstab
    echo "UUID=$uuid /mnt/kid-phone-server-backup ext4 defaults,nofail 0 2" >>/etc/fstab

    mount /mnt/kid-phone-server-backup
    echo "Drive formatted and mounted at /mnt/kid-phone-server-backup."
}

# Restores a named backup zip: stops the app, swaps in the backup's
# database, and restarts. Everything that can be validated up front
# (filename shape, the file actually existing, the zip actually containing a
# kidphone.db) happens *before* the app is stopped, so a bad request never
# takes the app down for nothing. Once stopped, an EXIT trap guarantees the
# app gets restarted no matter how the rest of this function finishes -
# success, or an unexpected failure partway through the file swap - since
# this is the last thing watcher.sh does before the script itself exits.
action_restore_backup() {
    local filename="$1"

    if [ -z "$filename" ]; then
        echo "restore_backup: no filename specified" >&2
        return 1
    fi
    case "$filename" in
        backup-*.zip) ;;
        *)
            echo "restore_backup: refusing to restore '$filename' — doesn't match the expected backup-*.zip pattern" >&2
            return 1
            ;;
    esac
    if echo "$filename" | grep -qE '/|\.\.'; then
        echo "restore_backup: refusing to restore '$filename' — invalid characters" >&2
        return 1
    fi

    local backup_path="$BACKUP_DIR/$filename"
    if [ ! -f "$backup_path" ]; then
        echo "restore_backup: '$backup_path' not found" >&2
        return 1
    fi

    local restore_tmp
    restore_tmp="$(mktemp -d)"
    if ! unzip -q -o "$backup_path" -d "$restore_tmp"; then
        echo "restore_backup: couldn't unzip '$backup_path'" >&2
        rm -rf "$restore_tmp"
        return 1
    fi
    if [ ! -f "$restore_tmp/kidphone.db" ]; then
        echo "restore_backup: backup zip didn't contain kidphone.db, aborting" >&2
        rm -rf "$restore_tmp"
        return 1
    fi

    echo "Stopping the app for restore..."
    systemctl stop kid-phone-server
    trap 'systemctl start kid-phone-server' EXIT

    # Safety copy of whatever's live right now, in case the wrong backup
    # gets restored - a raw file rather than a zip, so this doesn't depend
    # on any extra tooling being present.
    local prerestore_dir
    prerestore_dir="$BACKUP_DIR/prerestore-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$prerestore_dir"
    cp "$DATA_DIR/kidphone.db" "$prerestore_dir/kidphone.db" 2>/dev/null || true

    cp "$restore_tmp/kidphone.db" "$DATA_DIR/kidphone.db"
    rm -f "$DATA_DIR/kidphone.db-wal" "$DATA_DIR/kidphone.db-shm"
    rm -rf "$restore_tmp"
    chown -R kidphone:kidphone "$DATA_DIR"

    echo "Restore complete."
}
ACTIONS_EOF

cat >"$UPDATER_DIR/watcher.sh" <<'WATCHER_EOF'
#!/usr/bin/env bash
# Runs as root, triggered only when kid-phone-server (unprivileged) drops
# a flag file asking for one of a fixed set of actions.
set -euo pipefail
source /opt/kid-phone-server-updater/actions.sh

FLAG_FILE="/opt/kid-phone-server/data/update_requested"
FLAG_CONTENT="$(cat "$FLAG_FILE" 2>/dev/null || true)"
rm -f "$FLAG_FILE"

# Most actions are a single word; format_drive/restore_backup additionally
# carry a second, space-separated argument.
ACTION="${FLAG_CONTENT%% *}"
if [ "$ACTION" != "$FLAG_CONTENT" ]; then
    ARG="${FLAG_CONTENT#* }"
else
    ARG=""
fi

case "$ACTION" in
    update) action_app_update ;;
    restart) action_app_restart ;;
    os_check) action_os_check ;;
    os_upgrade) action_os_upgrade ;;
    tailscale_update) action_tailscale_update ;;
    reboot) action_reboot ;;
    dns_filter_enable) action_dns_filter_enable ;;
    dns_filter_disable) action_dns_filter_disable ;;
    format_drive) action_format_drive "$ARG" ;;
    restore_backup) action_restore_backup "$ARG" ;;
    *)
        echo "Unknown or empty update-request action: '$ACTION'" >&2
        exit 1
        ;;
esac
WATCHER_EOF

# Runs on a timer (not flag-triggered) to apply the admin-configured
# schedule from the Software updates page. This script is already root, so
# unlike the manual path above it just acts directly rather than going
# through the flag-file indirection - that indirection exists only to let
# the *unprivileged, internet-facing* app request privileged actions, which
# doesn't apply to this trusted, non-network-facing component.
cat >"$UPDATER_DIR/scheduler.sh" <<'SCHEDULER_EOF'
#!/usr/bin/env bash
set -euo pipefail
source /opt/kid-phone-server-updater/actions.sh

CONFIG_FILE="/opt/kid-phone-server/data/schedule.conf"
LAST_RUN_FILE="/opt/kid-phone-server-updater/last_run_date"

[ -f "$CONFIG_FILE" ] || exit 0

FREQUENCY="daily"
DAY_OF_WEEK="0"
DAY_OF_MONTH="1"
CHECK_TIME="03:00"
AUTO_APPLY_OS="false"
AUTO_APPLY_TAILSCALE="false"
AUTO_REBOOT="false"
# shellcheck disable=SC1090
source "$CONFIG_FILE"

TODAY="$(date +%F)"
LAST_RUN="$(cat "$LAST_RUN_FILE" 2>/dev/null || true)"
[ "$LAST_RUN" != "$TODAY" ] || exit 0

case "$FREQUENCY" in
    weekly)
        [ "$(date +%w)" = "$DAY_OF_WEEK" ] || exit 0
        ;;
    monthly)
        [ "$(date +%-d)" = "$DAY_OF_MONTH" ] || exit 0
        ;;
esac

NOW_MINUTES=$(( 10#$(date +%H) * 60 + 10#$(date +%M) ))
TARGET_MINUTES=$(( 10#${CHECK_TIME%%:*} * 60 + 10#${CHECK_TIME##*:} ))
DIFF=$(( NOW_MINUTES - TARGET_MINUTES ))
# Only fire in the 10-minute window right after the scheduled time (this
# runs on a 10-minute timer, so this is the precision that's actually
# achievable - good enough for background maintenance).
[ "$DIFF" -ge 0 ] && [ "$DIFF" -lt 10 ] || exit 0

echo "$TODAY" >"$LAST_RUN_FILE"

action_os_check
if [ "$AUTO_APPLY_OS" = "true" ]; then
    action_os_upgrade
fi
if [ "$AUTO_APPLY_TAILSCALE" = "true" ]; then
    action_tailscale_update
fi
if [ "$AUTO_REBOOT" = "true" ] && [ -f /var/run/reboot-required ]; then
    action_reboot
fi
SCHEDULER_EOF

# Mirrors backups (both the named point-in-time snapshots and the
# continuously-refreshed live-mirror file) to the external drive, if
# enabled and the drive is currently mounted. Runs on its own much faster
# timer than the OS-update scheduler above, since a stale offsite copy
# defeats the point of having one. Reads just the settings it needs via
# grep rather than sourcing backup_schedule.conf, since that file and
# schedule.conf (above) share variable names (FREQUENCY, DAY_OF_WEEK, ...)
# and sourcing both in the same script would let one silently clobber the
# other.
cat >"$UPDATER_DIR/backup_sync.sh" <<'BACKUP_SYNC_EOF'
#!/usr/bin/env bash
set -euo pipefail

BACKUP_CONFIG_FILE="/opt/kid-phone-server/data/backup_schedule.conf"
EXTERNAL_MOUNT="/mnt/kid-phone-server-backup"
DATA_DIR="/opt/kid-phone-server/data"

[ -f "$BACKUP_CONFIG_FILE" ] || exit 0
mountpoint -q "$EXTERNAL_MOUNT" || exit 0

EXTERNAL_COPY_ENABLED="$(grep -m1 '^EXTERNAL_COPY_ENABLED=' "$BACKUP_CONFIG_FILE" | cut -d= -f2 || true)"
CONTINUOUS_MIRROR_ENABLED="$(grep -m1 '^CONTINUOUS_MIRROR_ENABLED=' "$BACKUP_CONFIG_FILE" | cut -d= -f2 || true)"

if [ "$EXTERNAL_COPY_ENABLED" = "true" ] && [ -d "$DATA_DIR/backups" ]; then
    mkdir -p "$EXTERNAL_MOUNT/snapshots"
    cp -au "$DATA_DIR/backups/." "$EXTERNAL_MOUNT/snapshots/" 2>/dev/null || true
fi

if [ "$CONTINUOUS_MIRROR_ENABLED" = "true" ] && [ -f "$DATA_DIR/live_mirror.db" ]; then
    mkdir -p "$EXTERNAL_MOUNT/live"
    cp -au "$DATA_DIR/live_mirror.db" "$EXTERNAL_MOUNT/live/kidphone.db" 2>/dev/null || true
fi
BACKUP_SYNC_EOF

chown -R root:root "$UPDATER_DIR"
chmod 700 "$UPDATER_DIR" "$UPDATER_DIR/actions.sh" "$UPDATER_DIR/watcher.sh" "$UPDATER_DIR/scheduler.sh" "$UPDATER_DIR/backup_sync.sh"

cat >/etc/systemd/system/kid-phone-server-updater.path <<'PATH_EOF'
[Unit]
Description=Watch for Kid Phone Server update/restart requests

[Path]
PathExists=/opt/kid-phone-server/data/update_requested

[Install]
WantedBy=multi-user.target
PATH_EOF

cat >/etc/systemd/system/kid-phone-server-updater.service <<'SERVICE_EOF'
[Unit]
Description=Handle a pending Kid Phone Server update/restart request

[Service]
Type=oneshot
ExecStart=/opt/kid-phone-server-updater/watcher.sh
SERVICE_EOF

cat >/etc/systemd/system/kid-phone-server-scheduler.timer <<'TIMER_EOF'
[Unit]
Description=Check the Kid Phone Server update/reboot schedule every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
TIMER_EOF

cat >/etc/systemd/system/kid-phone-server-scheduler.service <<'SCHED_SERVICE_EOF'
[Unit]
Description=Apply the Kid Phone Server scheduled update/reboot, if due

[Service]
Type=oneshot
ExecStart=/opt/kid-phone-server-updater/scheduler.sh
SCHED_SERVICE_EOF

cat >/etc/systemd/system/kid-phone-server-backup-sync.timer <<'BACKUP_TIMER_EOF'
[Unit]
Description=Sync Kid Phone Server backups to the external drive every 90 seconds

[Timer]
OnBootSec=1min
OnUnitActiveSec=90sec

[Install]
WantedBy=timers.target
BACKUP_TIMER_EOF

cat >/etc/systemd/system/kid-phone-server-backup-sync.service <<'BACKUP_SERVICE_EOF'
[Unit]
Description=Mirror Kid Phone Server backups to the external drive, if enabled

[Service]
Type=oneshot
ExecStart=/opt/kid-phone-server-updater/backup_sync.sh
BACKUP_SERVICE_EOF

systemctl daemon-reload
systemctl enable --now kid-phone-server-updater.path
systemctl enable --now kid-phone-server-scheduler.timer
systemctl enable --now kid-phone-server-backup-sync.timer

echo ""
echo "=========================================="
echo " Kid Phone Server is installed and running."
echo "=========================================="
echo ""
echo "Locally on the Pi: http://127.0.0.1:3100"
echo ""
if [ "$PRINT_CREDENTIALS" -eq 1 ]; then
    echo "First-time admin login:"
    echo "  Username: admin"
    echo "  Password: $ADMIN_PASSWORD"
    echo ""
    echo "Save this password now — it won't be shown again. You'll be forced"
    echo "to change it and set up two-factor login the first time you sign in."
    echo ""
fi
echo "This only listens on the Pi itself (127.0.0.1) for security. To reach it"
echo "from your phone or other devices, set up Tailscale (or Tailscale Funnel"
echo "for a public URL) next - see DEPLOY.md."
echo ""
echo "Future updates, backups, and restarts can all be done from the app's"
echo "Backups / Software updates pages once logged in - you shouldn't need to"
echo "SSH back in for routine maintenance after this."
echo ""
echo "Check status any time with: systemctl status kid-phone-server"
