#!/bin/bash
# fan_debug.sh — diagnose and fix Supermicro fan control issues
# Run as root: bash <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/fan_debug.sh)
set -euo pipefail

echo "=== SMFC FAN DEBUG $(date) ==="

echo ""
echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true
sleep 2

echo "2. Setting FULL mode..."
ipmitool raw 0x30 0x45 0x01 0x01
sleep 2

echo "3. Setting both zones to 15%..."
ipmitool raw 0x30 0x70 0x66 0x01 0x00 0x0F
ipmitool raw 0x30 0x70 0x66 0x01 0x01 0x0F
sleep 5

echo "4. Fan RPMs after manual 15%:"
ipmitool sensor | grep FAN
echo ""

echo "5. Reading zone levels:"
echo -n "   Zone 0: "; ipmitool raw 0x30 0x70 0x66 0x00 0x00
echo -n "   Zone 1: "; ipmitool raw 0x30 0x70 0x66 0x00 0x01
echo ""

echo "6. Waiting 10s for BMC override..."
sleep 10
echo "7. Fan RPMs after 10s wait:"
ipmitool sensor | grep FAN
echo ""

echo "8. Zone levels after wait:"
echo -n "   Zone 0: "; ipmitool raw 0x30 0x70 0x66 0x00 0x00
echo -n "   Zone 1: "; ipmitool raw 0x30 0x70 0x66 0x00 0x01
echo ""

echo "9. CPU temp:"
ipmitool sensor | grep -i "cpu\|temp" | head -5
echo ""

echo "10. Fan mode:"
echo -n "   Mode: "; ipmitool raw 0x30 0x45 0x00
echo ""

echo "11. IPMI event log (last 5):"
ipmitool sel list 2>/dev/null | tail -5 || echo "   (empty)"
echo ""

echo "=== DONE ==="
echo "Screenshot this and share it."
