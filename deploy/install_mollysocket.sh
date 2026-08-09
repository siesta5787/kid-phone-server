#!/usr/bin/env bash
# MollySocket — optional sibling service for Molly (Signal) push
# notifications via UnifiedPush. Not part of Kid Phone Server itself: this
# just installs the upstream mollyim/mollysocket binary as its own systemd
# service, alongside kid-phone-server on the same Pi. See DEPLOY.md.
#
# Usage (as root, e.g. via sudo):
#   curl -sSL https://raw.githubusercontent.com/siesta5787/kid-phone-server/master/deploy/install_mollysocket.sh | sudo bash
#
# Safe to re-run: re-downloads the latest binary and restarts the service,
# but never touches an existing conf.toml (so your VAPID key and any Molly
# registrations already on file survive an update).

set -euo pipefail

REPO="mollyim/mollysocket"
INSTALL_DIR="/opt/mollysocket"
SERVICE_USER="mollysocket"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this as root (e.g. 'sudo bash install_mollysocket.sh')." >&2
    exit 1
fi

case "$(uname -m)" in
    # musl build, same reasoning as kid-phone-server's own target: no glibc
    # version dependency on a minimal Pi OS / DietPi image.
    aarch64) ASSET="mollysocket-musl-linux_arm64" ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        echo "This installer supports 64-bit (aarch64) Pi OS / DietPi only." >&2
        exit 1
        ;;
esac
echo "Detected architecture: $(uname -m) -> $ASSET"

echo "Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq curl >/dev/null

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "Creating service user '$SERVICE_USER'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR/data"

BINARY_URL="https://github.com/$REPO/releases/latest/download/$ASSET"
echo "Downloading latest MollySocket release from $BINARY_URL ..."
curl -sSL "$BINARY_URL" -o "$INSTALL_DIR/mollysocket"
chmod +x "$INSTALL_DIR/mollysocket"

if [ ! -f "$INSTALL_DIR/conf.toml" ]; then
    echo "No existing conf.toml found — generating a VAPID key and a fresh config."
    VAPID_KEY="$("$INSTALL_DIR/mollysocket" vapid gen)"
    cat >"$INSTALL_DIR/conf.toml" <<EOF
host = "127.0.0.1"
port = 8020
webserver = true
# This server is only reachable over your own tailnet (same trust model as
# kid-phone-server itself - see DEPLOY.md), so a wildcard here is no wider
# in practice than kid-phone-server's own single-admin-account model. Narrow
# these to your specific account ID / push endpoint later if you want
# defense in depth - see mollysocket's own README for the exact syntax.
allowed_endpoints = ["*"]
allowed_uuids = ["*"]
db = "$INSTALL_DIR/data/db.sqlite"
vapid_privkey = "$VAPID_KEY"
EOF
else
    echo "Existing conf.toml found — leaving it untouched."
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/conf.toml"

echo "Installing systemd service..."
cat >/etc/systemd/system/mollysocket.service <<EOF
[Unit]
Description=MollySocket (push relay for Molly/Signal)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=MOLLY_CONF=$INSTALL_DIR/conf.toml
ExecStart=$INSTALL_DIR/mollysocket server
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
systemctl enable mollysocket
# Same reasoning as kid-phone-server.service: `enable --now` is a no-op if
# already running, which would leave a re-run's freshly downloaded binary
# unused until the next unrelated restart.
systemctl restart mollysocket

echo ""
echo "=========================================="
echo " MollySocket is installed and running."
echo "=========================================="
echo ""
echo "Locally on the Pi: http://127.0.0.1:8020"
echo ""
echo "This only listens on the Pi itself (127.0.0.1), same as kid-phone-server."
echo "To reach it from Molly's setup screen, expose it over your tailnet on its"
echo "own HTTPS port (kid-phone-server already uses 443, so pick another, e.g."
echo "8443):"
echo ""
echo "  sudo tailscale serve --bg --https=8443 http://127.0.0.1:8020"
echo ""
echo "See DEPLOY.md for the full Molly setup steps."
echo ""
echo "Check status any time with: systemctl status mollysocket"
