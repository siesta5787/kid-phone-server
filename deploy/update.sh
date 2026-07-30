#!/usr/bin/env bash
# Kid Phone Server — updater. Downloads the latest release and replaces the
# running app, without touching your .env or database. Migrations run
# automatically on the next startup.
#
# Usage (as root, e.g. via sudo):
#   curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/update.sh | sudo bash

set -euo pipefail

REPO="siesta5787/kid-phone-server"
INSTALL_DIR="/opt/kid-phone-server"
SERVICE_USER="kidphone"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this as root (e.g. 'sudo bash update.sh')." >&2
    exit 1
fi

if [ ! -f "$INSTALL_DIR/.env" ]; then
    echo "$INSTALL_DIR doesn't look like an existing install (no .env found)." >&2
    echo "Run install.sh first." >&2
    exit 1
fi

case "$(uname -m)" in
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

TARBALL_URL="https://github.com/$REPO/releases/latest/download/kid-phone-server-$TARGET.tar.gz"
echo "Downloading latest release from $TARBALL_URL ..."
curl -sSL "$TARBALL_URL" -o /tmp/kid-phone-server.tar.gz

echo "Stopping service..."
systemctl stop kid-phone-server

echo "Installing update..."
TMP_EXTRACT="$(mktemp -d)"
tar -xzf /tmp/kid-phone-server.tar.gz -C "$TMP_EXTRACT"
rm /tmp/kid-phone-server.tar.gz

cp "$TMP_EXTRACT/kid_phone_server" "$INSTALL_DIR/kid_phone_server"
chmod +x "$INSTALL_DIR/kid_phone_server"

rm -rf "$INSTALL_DIR/static"
cp -r "$TMP_EXTRACT/static" "$INSTALL_DIR/static"
rm -rf "$TMP_EXTRACT"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/kid_phone_server" "$INSTALL_DIR/static"

echo "Starting service..."
systemctl start kid-phone-server

sleep 2
if systemctl is-active --quiet kid-phone-server; then
    echo ""
    echo "Update complete and running."
else
    echo ""
    echo "The service didn't start cleanly — check 'systemctl status kid-phone-server'" >&2
    echo "and 'journalctl -u kid-phone-server -n 50' for details." >&2
    exit 1
fi
