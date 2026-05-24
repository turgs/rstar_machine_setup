#!/bin/bash
# fan_debug.sh — fix BMC assertions and set fans quiet, with diagnostics
set -euo pipefail
echo "=== FAN FIX + DEBUG $(date) ==="
echo ""
echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true
echo "2. Setting FULL mode + clearing assertions..."
ipmitool raw 0x30 0x45 0x01 0x01
ipmitool sel clear
sleep 2
echo "3. Lowering thresholds (connected fans only)..."
for fan in FAN1 FANA FANB; do
    ipmitool sensor thresh "$fan" lower 0 50 100 2>/dev/null || true
done
echo "4. Setting zones to 35%..."
ipmitool raw 0x30 0x70 0x66 0x01 0x00 0x23
ipmitool raw 0x30 0x70 0x66 0x01 0x01 0x23
echo "5. Waiting 15s..."
sleep 15
echo "6. Results:"
ipmitool sensor | grep FAN
echo ""
echo -n "   Zone 0: "; ipmitool raw 0x30 0x70 0x66 0x00 0x00
echo -n "   Zone 1: "; ipmitool raw 0x30 0x70 0x66 0x00 0x01
echo -n "   Fan mode: "; ipmitool raw 0x30 0x45 0x00
echo ""
echo "7. Event log:"
ipmitool sel list 2>/dev/null | tail -3 || echo "   (empty)"
echo ""
echo "8. Starting smfc..."
systemctl start smfc 2>/dev/null || true
sleep 10
echo "9. Post-smfc (10s):"
ipmitool sensor | grep FAN
echo -n "   Fan mode: "; ipmitool raw 0x30 0x45 0x00
systemctl is-active smfc && echo "   smfc: RUNNING" || echo "   smfc: NOT RUNNING"
echo "=== DONE ==="
