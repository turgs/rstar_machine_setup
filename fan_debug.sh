#!/bin/bash
# fan_debug.sh — test if fans hold at 15% without and with smfc
set -euo pipefail
echo "=== FAN HOLD TEST $(date) ==="
echo ""

echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true
sleep 2

echo "2. FULL mode + clear assertions + thresholds..."
ipmitool raw 0x30 0x45 0x01 0x01
ipmitool sel clear
for fan in FAN1 FANA FANB; do
    ipmitool sensor thresh "$fan" lower 0 50 100 2>/dev/null || true
done
sleep 2

echo "3. Setting both zones to 15%..."
ipmitool raw 0x30 0x70 0x66 0x01 0x00 0x0F
ipmitool raw 0x30 0x70 0x66 0x01 0x01 0x0F
echo ""

check_fans() {
    local mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    local z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    local z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    local rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    local temp=$(ipmitool sensor 2>/dev/null | grep -i "cpu temp\|CPU Temp" | head -1 | awk '{print $4}')
    
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ BMC OVERRIDE (mode=$mode z0=$z0 z1=$z1 cpu=${temp}C)"
        echo "  RPMs: $rpms"
        ipmitool sel list 2>/dev/null | tail -3 || true
        return 1
    fi
    echo "  ✅ HELD (z0=$z0 z1=$z1 cpu=${temp}C RPMs: $rpms)"
    return 0
}

echo "=== PHASE 1: Without smfc ==="
for s in 10 20 30 45 60; do
    echo "--- ${s}s ---"
    sleep 10
    if ! check_fans; then
        echo ""
        echo "=== RESULT: BMC overrides at ~${s}s WITHOUT smfc ==="
        exit 1
    fi
done

echo ""
echo "=== PHASE 2: Starting smfc ==="
ipmitool sel clear 2>/dev/null || true
systemctl start smfc 2>/dev/null || true
sleep 3
echo "smfc config:"
grep -E "min_level|^level|ipmi_zone" /etc/smfc/smfc.conf 2>/dev/null || echo "  (not found)"
echo ""

for s in 10 20 30 45 60; do
    echo "--- smfc +${s}s ---"
    sleep 10
    if ! check_fans; then
        echo ""
        journalctl -u smfc --no-pager -n 5 2>/dev/null || true
        echo ""
        echo "=== RESULT: SMFC causes override at ~${s}s ==="
        exit 1
    fi
done

echo ""
echo "=== ALL CLEAR — fans quiet 60s with AND without smfc ==="
