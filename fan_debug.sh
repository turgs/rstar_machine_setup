#!/bin/bash
# fan_debug.sh — find lowest stable fan level after BMC cold reset
set -euo pipefail
echo "=== FAN SWEEP TEST $(date) ==="
echo ""

echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true

echo "2. Setting thresholds..."
ipmitool sensor thresh FAN1 lower 0 100 200 2>/dev/null || true
ipmitool sensor thresh FANA lower 0 100 200 2>/dev/null || true
for fan in FAN2 FAN3 FAN4 FAN5 FANB; do
    ipmitool sensor thresh "$fan" lower 0 0 0 2>/dev/null || true
done

echo "3. BMC cold reset (90s)..."
ipmitool mc reset cold
sleep 90

echo "4. FULL mode + clear events..."
ipmitool raw 0x30 0x45 0x01 0x01
ipmitool sel clear
sleep 3

check_fans() {
    local mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    local z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    local z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    local rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ OVERRIDE (mode=$mode z0=$z0 z1=$z1 RPMs: $rpms)"
        ipmitool sel list 2>/dev/null | tail -2 || true
        return 1
    fi
    echo "  ✅ HELD (z0=$z0 z1=$z1 RPMs: $rpms)"
    return 0
}

echo ""
echo "=== SWEEP: 30s hold per level, no smfc ==="
LOWEST=30
for level in 30 25 20 15; do
    hex=$(printf '0x%02x' $level)
    echo ""
    echo "===== Testing ${level}% ====="
    ipmitool sel clear 2>/dev/null || true
    ipmitool raw 0x30 0x70 0x66 0x01 0x00 $hex
    ipmitool raw 0x30 0x70 0x66 0x01 0x01 $hex
    
    failed=0
    for s in 10 20 30; do
        echo "--- ${level}% @ ${s}s ---"
        sleep 10
        if ! check_fans; then
            echo "  ❌ FAILED at ${level}% after ${s}s"
            failed=1
            # Recover for next test
            ipmitool raw 0x30 0x45 0x01 0x01
            ipmitool sel clear
            sleep 3
            break
        fi
    done
    
    if [ $failed -eq 0 ]; then
        LOWEST=$level
        echo "  ✅ ${level}% PASSED 30s hold"
    else
        echo "  Lowest stable: ${LOWEST}%"
        break
    fi
done

echo ""
echo "=== RESULT: Lowest stable level = ${LOWEST}% ==="
echo ""

echo "=== Verifying ${LOWEST}% with smfc for 60s ==="
hex=$(printf '0x%02x' $LOWEST)
ipmitool sel clear 2>/dev/null || true
ipmitool raw 0x30 0x70 0x66 0x01 0x00 $hex
ipmitool raw 0x30 0x70 0x66 0x01 0x01 $hex

# Update smfc config with the discovered level
sed -i "s/min_level=.*/min_level=${LOWEST}/" /etc/smfc/smfc.conf 2>/dev/null || true
sed -i "s/^level=.*/level=${LOWEST}/" /etc/smfc/smfc.conf 2>/dev/null || true

systemctl start smfc 2>/dev/null || true

for s in 10 20 30 45 60; do
    echo "--- smfc +${s}s ---"
    sleep 10
    if ! check_fans; then
        journalctl -u smfc --no-pager -n 3 2>/dev/null || true
        echo "=== SMFC override at +${s}s — use ${LOWEST}% static instead ==="
        exit 1
    fi
done

echo ""
echo "=== ALL CLEAR — smfc running at ${LOWEST}% ==="
echo "Config updated: /etc/smfc/smfc.conf"
grep -E "min_level|^level" /etc/smfc/smfc.conf 2>/dev/null || true
