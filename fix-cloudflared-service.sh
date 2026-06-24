#!/bin/bash
set -euo pipefail

# One-off fix: harden cloudflared-tunnel.service on existing servers.
# Changes:
#   - Restart=on-failure → Restart=always (survives clean exits too)
#   - Remove WatchdogSec if present (cloudflared doesn't support sd_notify)
#
# Run as root on the tower:
#   bash fix-cloudflared-service.sh

SERVICE_FILE="/etc/systemd/system/cloudflared-tunnel.service"

if [[ ! -f "$SERVICE_FILE" ]]; then
    echo "❌ $SERVICE_FILE not found. Is cloudflared installed?"
    exit 1
fi

echo "Current service config:"
grep -E "Restart=|WatchdogSec=" "$SERVICE_FILE" || echo "  (no matching lines)"
echo

# Apply fixes
sed -i 's/^Restart=on-failure/Restart=always/' "$SERVICE_FILE"

# Remove WatchdogSec — cloudflared doesn't support sd_notify WATCHDOG=1,
# so systemd kills it every WatchdogSec interval thinking it's stuck.
sed -i '/^WatchdogSec=/d' "$SERVICE_FILE"

echo "Updated service config:"
grep -E "Restart=|WatchdogSec=" "$SERVICE_FILE" || echo "  (no WatchdogSec — correct)"
echo

systemctl daemon-reload
systemctl restart cloudflared-tunnel
sleep 3

if systemctl is-active --quiet cloudflared-tunnel; then
    echo "✅ cloudflared-tunnel restarted and healthy"
else
    echo "⚠️  cloudflared-tunnel not active — check: journalctl -u cloudflared-tunnel -f"
fi
