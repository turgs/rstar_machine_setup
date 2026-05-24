#!/bin/bash
# fan_fix.sh — clear BMC assertions and set fans to 15%
set -euo pipefail
echo "=== FAN FIX ==="
echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true
echo "2. Setting FULL mode..."
ipmitool raw 0x30 0x45 0x01 0x01
echo "3. Clearing event log (BMC assertions)..."
ipmitool sel clear
sleep 2
echo "4. Lowering thresholds..."
for fan in FAN1 FAN2 FAN3 FAN4 FAN5 FANA FANB; do
    ipmitool sensor thresh "$fan" lower 0 100 200 2>/dev/null || true
done
echo "5. Setting both zones to 15%..."
ipmitool raw 0x30 0x70 0x66 0x01 0x00 0x0F
ipmitool raw 0x30 0x70 0x66 0x01 0x01 0x0F
echo "6. Waiting 15s to check if BMC overrides..."
sleep 15
echo "7. Results:"
ipmitool sensor | grep FAN
echo ""
echo -n "Zone 0: "; ipmitool raw 0x30 0x70 0x66 0x00 0x00
echo -n "Zone 1: "; ipmitool raw 0x30 0x70 0x66 0x00 0x01
echo ""
echo "8. Starting smfc..."
systemctl start smfc 2>/dev/null || true
sleep 5
echo "9. Final check:"
ipmitool sensor | grep FAN
echo ""
systemctl is-active smfc && echo "smfc: RUNNING" || echo "smfc: NOT RUNNING"
echo "=== DONE ==="
