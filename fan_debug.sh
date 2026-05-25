#!/bin/bash
# fan_debug.sh — find the lowest stable fan speed
set -euo pipefail
echo "=== FAN LEVEL SWEEP $(date) ==="
echo ""

systemctl stop smfc 2>/dev/null || true
ipmitool raw 0x30 0x45 0x01 0x01
ipmitool sel clear
sleep 2

for level in 35 30 25 20 15; do
    hex=$(printf '0x%02x' $level)
    echo "--- Testing ${level}% (${hex}) ---"
    ipmitool raw 0x30 0x70 0x66 0x01 0x00 $hex
    ipmitool raw 0x30 0x70 0x66 0x01 0x01 $hex
    sleep 8
    
    # Check if BMC overrode
    mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ BMC OVERRIDE at ${level}% (mode=$mode z0=$z0 z1=$z1)"
        echo "  RPMs: $rpms"
        echo "  Lowest safe level: $((level + 5))%"
        # Restore
        ipmitool raw 0x30 0x45 0x01 0x01
        ipmitool sel clear
        sleep 2
        safe=$((level + 5))
        safehex=$(printf '0x%02x' $safe)
        ipmitool raw 0x30 0x70 0x66 0x01 0x00 $safehex
        ipmitool raw 0x30 0x70 0x66 0x01 0x01 $safehex
        echo ""
        echo "=== RESULT: Lowest safe level = ${safe}% ==="
        echo "To apply: edit /etc/smfc/smfc.conf"
        echo "  [CPU] min_level=${safe}"
        echo "  [CONST] level=${safe}"
        systemctl start smfc 2>/dev/null || true
        exit 0
    fi
    
    echo "  ✅ HELD at ${level}% (RPMs: $rpms)"
    echo ""
done

echo "=== RESULT: All levels stable down to 15%! ==="
echo "To apply: edit /etc/smfc/smfc.conf"
echo "  [CPU] min_level=15"
echo "  [CONST] level=15"
systemctl start smfc 2>/dev/null || true
