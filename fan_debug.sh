#!/bin/bash
# fan_debug.sh — fix fans with BMC cold reset + safe minimum levels
set -euo pipefail
echo "=== FAN FIX $(date) ==="
echo ""

echo "1. Stopping smfc..."
systemctl stop smfc 2>/dev/null || true

echo "2. Setting thresholds on connected fans..."
ipmitool sensor thresh FAN1 lower 0 100 200 2>/dev/null || true
ipmitool sensor thresh FANA lower 0 100 200 2>/dev/null || true
ipmitool sensor thresh FANB lower 0 100 200 2>/dev/null || true

echo "3. Setting disconnected fan thresholds to 0/0/0..."
for n in 2 3 4 5; do
    ipmitool sensor thresh FAN${n} lower 0 0 0 2>/dev/null || true
done

echo "4. BMC cold reset (takes ~90 seconds)..."
ipmitool mc reset cold
echo "   Waiting 90s for BMC to restart..."
sleep 90

echo "5. Setting FULL mode + clearing events..."
ipmitool raw 0x30 0x45 0x01 0x01
ipmitool sel clear
sleep 3

echo "6. Setting zones to 30%..."
ipmitool raw 0x30 0x70 0x66 0x01 0x00 0x1E
ipmitool raw 0x30 0x70 0x66 0x01 0x01 0x1E
echo ""

check_fans() {
    local mode=$(ipmitool raw 0x30 0x45 0x00 2>/dev/null | tr -d ' ')
    local z0=$(ipmitool raw 0x30 0x70 0x66 0x00 0x00 2>/dev/null | tr -d ' ')
    local z1=$(ipmitool raw 0x30 0x70 0x66 0x00 0x01 2>/dev/null | tr -d ' ')
    local rpms=$(ipmitool sensor 2>/dev/null | grep FAN | grep -v na | awk '{printf "%s:%s ", $1, $4}')
    if [ "$mode" != "01" ] || [ "$z0" = "64" ] || [ "$z1" = "64" ]; then
        echo "  ❌ OVERRIDE (mode=$mode z0=$z0 z1=$z1)"
        echo "  RPMs: $rpms"
        ipmitool sel list 2>/dev/null | tail -3 || true
        return 1
    fi
    echo "  ✅ HELD (z0=$z0 z1=$z1 RPMs: $rpms)"
    return 0
}

echo "=== Testing 30% for 60s (no smfc) ==="
for s in 10 20 30 45 60; do
    echo "--- ${s}s ---"
    sleep 10
    if ! check_fans; then
        echo "=== FAILED at ${s}s even after BMC reset ==="
        exit 1
    fi
done

echo ""
echo "=== 30% held! Starting smfc... ==="
ipmitool sel clear 2>/dev/null || true
systemctl start smfc 2>/dev/null || true

for s in 10 20 30 45 60; do
    echo "--- smfc +${s}s ---"
    sleep 10
    if ! check_fans; then
        journalctl -u smfc --no-pager -n 3 2>/dev/null || true
        echo "=== SMFC caused override at +${s}s ==="
        exit 1
    fi
done

echo ""
echo "=== ALL CLEAR — fans quiet at 30% ==="
