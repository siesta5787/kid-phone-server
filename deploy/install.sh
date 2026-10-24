#!/usr/bin/env bash
# Kid Phone Server — installer for a plain Raspberry Pi OS / DietPi (or any
# Linux/systemd box).
#
# The recommended way to run this app is a Box (github.com/siesta5787/
# pi2zeroserver): it installs the app, keeps it, its system and Tailscale
# updated, and is what the app's Software updates page works with. Don't run
# this installer on a Box.
#
# Usage (as root, e.g. via sudo):
#   curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install.sh | sudo bash
#
# Safe to re-run: it won't overwrite an existing .env or database, it just
# re-installs the latest release and the service/helper scripts. Re-running
# it is also how a plain-Pi install updates the app (the in-app updater and
# OS/Tailscale scheduling were removed; on a plain Pi, keep the OS updated
# with the usual apt tools).

set -euo pipefail

REPO="siesta5787/kid-phone-server"
INSTALL_DIR="/opt/kid-phone-server"
SERVICE_USER="kidphone"

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
apt-get install -y -qq curl tar unzip iptables jq >/dev/null

# Cleanup for any Pi that ran an installer from before the on-device-filtering
# migration (see this repo's CLAUDE.md): this server no longer runs a live DNS
# listener at all (filtering happens entirely on-device now, via the
# launcher's own KidVpnService), so the old port-53/853 DNAT redirect rules
# and the route_localnet sysctl they depended on are both dead weight. Removal
# is best-effort/idempotent (`|| true`) since a fresh install has none of this
# to clean up in the first place.
for proto in udp tcp; do
    iptables -t nat -D PREROUTING -i tailscale0 -p "$proto" --dport 53 \
        -j DNAT --to-destination 127.0.0.1:5300 2>/dev/null || true
done
iptables -t nat -D PREROUTING -i tailscale0 -p tcp --dport 853 \
    -j DNAT --to-destination 127.0.0.1:8853 2>/dev/null || true
rm -f /etc/sysctl.d/99-kid-phone-server.conf
systemctl disable --now kid-phone-server-tls-cert.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/kid-phone-server-tls-cert.timer /etc/systemd/system/kid-phone-server-tls-cert.service
rm -f /opt/kid-phone-server-updater/tls_cert_renew.sh

# Cleanup for a Pi set up before the app stopped updating itself and the OS
# (updates are the Box's job now): the OS/Tailscale scheduler, and the state
# files the old Software updates page kept.
systemctl disable --now kid-phone-server-scheduler.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/kid-phone-server-scheduler.timer /etc/systemd/system/kid-phone-server-scheduler.service
rm -f /opt/kid-phone-server-updater/scheduler.sh /opt/kid-phone-server-updater/last_run_date
rm -f /opt/kid-phone-server/data/schedule.conf /opt/kid-phone-server/data/app_update_schedule.conf \
    /opt/kid-phone-server/data/app_update_last_check /opt/kid-phone-server/data/watcher_version \
    /opt/kid-phone-server/data/watcher_schema_version

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

echo "Installing the backup helper..."
# A separate, root-owned component that does the privileged backup work -
# formatting an external backup drive, restoring a backup (the app has to be
# stopped for that), and mirroring backups to the drive. kid_phone_server
# itself runs unprivileged and can only ever drop a flag file in its own
# data/ folder asking for one of a small fixed set of actions - it can never
# reach or modify anything in this directory, even if fully compromised,
# since it lives outside $INSTALL_DIR entirely and nothing here is
# kidphone-writable.
UPDATER_DIR="/opt/kid-phone-server-updater"
mkdir -p "$UPDATER_DIR"

# Placeholder mount point for an optional external backup drive. Doesn't do
# anything by itself - mount a drive here (e.g. via /etc/fstab) and enable
# "copy backups to external drive" on the Backups page to use it.
mkdir -p /mnt/kid-phone-server-backup

# The privileged actions the flag-file watcher below can run.
cat >"$UPDATER_DIR/actions.sh" <<'ACTIONS_EOF'
#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="/opt/kid-phone-server/data"
BACKUP_DIR="$DATA_DIR/backups"

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

# An action word plus one space-separated argument.
ACTION="${FLAG_CONTENT%% *}"
if [ "$ACTION" != "$FLAG_CONTENT" ]; then
    ARG="${FLAG_CONTENT#* }"
else
    ARG=""
fi

case "$ACTION" in
    format_drive) action_format_drive "$ARG" ;;
    restore_backup) action_restore_backup "$ARG" ;;
    *)
        echo "Unknown or empty update-request action: '$ACTION'" >&2
        exit 1
        ;;
esac
WATCHER_EOF

# Mirrors backups (both the named point-in-time snapshots and the
# continuously-refreshed live-mirror file) to the external drive, if
# enabled and the drive is currently mounted, on a fast timer, since a stale
# offsite copy defeats the point of having one. Reads just the settings it
# needs via grep rather than sourcing backup_schedule.conf.
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
chmod 700 "$UPDATER_DIR" "$UPDATER_DIR/actions.sh" "$UPDATER_DIR/watcher.sh" "$UPDATER_DIR/backup_sync.sh"

cat >/etc/systemd/system/kid-phone-server-updater.path <<'PATH_EOF'
[Unit]
Description=Watch for Kid Phone Server backup requests (format drive, restore)

[Path]
PathExists=/opt/kid-phone-server/data/update_requested

[Install]
WantedBy=multi-user.target
PATH_EOF

cat >/etc/systemd/system/kid-phone-server-updater.service <<'SERVICE_EOF'
[Unit]
Description=Handle a pending Kid Phone Server backup request

[Service]
Type=oneshot
ExecStart=/opt/kid-phone-server-updater/watcher.sh
SERVICE_EOF

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
echo "Backups can be made and restored from the app's Backups page. To update"
echo "the app, re-run this installer. (For hands-off updates of the app, the"
echo "system and Tailscale, run it on a Box instead: github.com/siesta5787/pi2zeroserver)"
echo ""
echo "Check status any time with: systemctl status kid-phone-server"
