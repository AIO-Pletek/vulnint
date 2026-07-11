#!/usr/bin/env bash
# VulnInt Linux Agent installer.
#
# Usage:
#   sudo bash install.sh https://vulnint.example.com <AGENT_TOKEN>
#
# Installs to /opt/vulnint, drops a systemd unit, and starts the agent.

set -euo pipefail

API_URL="${1:-${VULNINT_API_URL:-}}"
TOKEN="${2:-${VULNINT_AGENT_TOKEN:-}}"

if [[ -z "$API_URL" || -z "$TOKEN" ]]; then
    echo "usage: $0 <api_url> <agent_token>" >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

INSTALL_DIR="/opt/vulnint"
CONFIG_DIR="/etc/vulnint"
QUEUE_DIR="/var/spool/vulnint"
SCRIPT_PATH="$INSTALL_DIR/vulnint-agent.py"
SERVICE_PATH="/etc/systemd/system/vulnint-agent.service"
TIMER_PATH="/etc/systemd/system/vulnint-agent.timer"

# Detect a usable python3
if ! command -v python3 >/dev/null; then
    echo "python3 is required" >&2
    exit 2
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$QUEUE_DIR"
chown root:root "$INSTALL_DIR" "$CONFIG_DIR"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
chmod 700 "$QUEUE_DIR"

# Copy agent script (assumes it lives next to this installer)
HERE="$(dirname "$(readlink -f "$0")")"
install -m 0755 "$HERE/vulnint-agent.py" "$SCRIPT_PATH"

# Write config
umask 077
cat > "$CONFIG_DIR/agent.yaml" <<EOF
# VulnInt agent config
api_url: "$API_URL"
agent_token: "$TOKEN"
interval: 21600
verify_tls: true
queue_dir: "$QUEUE_DIR"
EOF
chmod 600 "$CONFIG_DIR/agent.yaml"

# systemd unit + timer (timer for periodic; service for one-shot)
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=VulnInt Vulnerability Inventory Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$(command -v python3) $SCRIPT_PATH --once --config $CONFIG_DIR/agent.yaml
User=root
Nice=10
ProtectSystem=strict
ReadWritePaths=$QUEUE_DIR
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
RestrictSUIDSGID=true
LockPersonality=true
EOF

cat > "$TIMER_PATH" <<EOF
[Unit]
Description=Run VulnInt agent on schedule

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now vulnint-agent.timer

# Run once immediately
systemctl start vulnint-agent.service || true

echo "✓ VulnInt agent installed."
echo "  Config:  $CONFIG_DIR/agent.yaml"
echo "  Status:  systemctl status vulnint-agent.timer"
echo "  Logs:    journalctl -u vulnint-agent.service"
