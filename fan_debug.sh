#!/bin/bash
# fan_debug.sh — test if fans hold at 15% without smfc interfering
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

for wait in 10 20 30 45 60; do
    echo "--- Checking at ${wait}s (no smfc) ---"
    sleep_remaining=$((wait - ${prev_wait:-0}))
    sleep $sleep_remaining
    prev_wait=$wait
    mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ BMC OVERRIDE at ${wait}s (mode=$mode z0=$z0 z1=$z1)"
        echo "  RPMs: $rpms"
        echo ""
        echo "  Events:"
        ipmitool sel list 2>/dev/null | tail -3 || echo "  (empty)"
        echo ""
        echo "=== BMC overrides after ~${wait}s WITHOUT smfc ==="
        exit 1
    fi
    echo "  ✅ HELD (mode=$mode z0=$z0 z1=$z1 RPMs: $rpms)"
done

echo ""
echo "=== Held for 60s without smfc! Starting smfc now... ==="
systemctl start smfc 2>/dev/null || true

for wait in 10 20 30 45 60; do
    echo "--- smfc running +${wait}s ---"
    sleep_remaining=$((wait - ${prev_wait2:-0}))
    sleep $sleep_remaining
    prev_wait2=$wait
    mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ BMC OVERRIDE at +${wait}s WITH smfc (mode=$mode z0=$z0 z1=$z1)"
        echo "  RPMs: $rpms"
        echo ""
        echo "  Events:"
        ipmitool sel list 2>/dev/null | tail -3 || echo "  (empty)"
        echo ""
        echo "=== SMFC IS THE PROBLEM — overrides after ~${wait}s ==="
        exit 1
    fi
    echo "  ✅ HELD (mode=$mode z0=$z0 z1=$z1 RPMs: $rpms)"
done

echo ""
echo "=== ALL CLEAR — fans quiet for 60s with AND without smfc ==="
