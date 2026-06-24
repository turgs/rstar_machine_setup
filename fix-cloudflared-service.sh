#!/bin/bash
set -euo pipefail

# One-off fix: harden cloudflared-tunnel.service on existing servers.
# Changes:
#   - Restart=on-failure → Restart=always (survives clean exits too)
#   - Add WatchdogSec=60 (restarts if cloudflared gets stuck without crashing)
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

if ! grep -q "WatchdogSec" "$SERVICE_FILE"; then
    sed -i '/^LimitNOFILE=/a WatchdogSec=60' "$SERVICE_FILE"
fi

echo "Updated service config:"
grep -E "Restart=|WatchdogSec=" "$SERVICE_FILE"
echo

systemctl daemon-reload
systemctl restart cloudflared-tunnel
sleep 3

if systemctl is-active --quiet cloudflared-tunnel; then
    echo "✅ cloudflared-tunnel restarted and healthy"
else
    echo "⚠️  cloudflared-tunnel not active — check: journalctl -u cloudflared-tunnel -f"
fi
