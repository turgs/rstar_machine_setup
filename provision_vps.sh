#!/bin/bash
#
# provision_vps.sh - Ubuntu VPS Provisioning Script for Kamal 2
# Designed for Binary Lane VPS running Ubuntu 22.04/24.04 LTS
#
# Usage:
#   bash provision_vps.sh --ssh-key="ssh-ed25519 AAAA..."
#
# See README.md for full documentation
#

set -euo pipefail

# Set TERM if not set (for non-interactive SSH sessions)
export TERM="${TERM:-dumb}"
export DEBIAN_FRONTEND=noninteractive

# Error handler
error_handler() {
    local line_no=$1
    local exit_code=$?
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ SCRIPT FAILED at line $line_no (exit code: $exit_code)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    [[ -f "$STATE_FILE" ]] && echo "Last completed steps are in: $STATE_FILE"
    echo "Check logs: journalctl -xe"
    echo ""
    echo "For support, provide:"
    echo "  1. This error output"
    echo "  2. Contents of $STATE_FILE"
    echo "  3. Output of: journalctl -xe | tail -50"
    echo ""
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# Cleanup temporary files on exit
cleanup() {
    rm -f /tmp/get-docker.sh 2>/dev/null || true
}
trap cleanup EXIT

#==============================================================================
# CONFIGURATION DEFAULTS
#==============================================================================

# User Configuration
DEPLOY_USER="${DEPLOY_USER:-deploy}"
DEPLOY_UID="${DEPLOY_UID:-1000}"
DEPLOY_PASSWORD=""  # Auto-generated if empty

# SSH Configuration
SSH_PORT="${SSH_PORT:-33003}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"

# Security - fail2ban
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-true}"
FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-86400}"  # 24 hours in seconds
FAIL2BAN_MAXRETRY="${FAIL2BAN_MAXRETRY:-5}"
FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-600}"  # 10 minutes in seconds
FAIL2BAN_WHITELIST_URL="${FAIL2BAN_WHITELIST_URL:-https://gist.githubusercontent.com/turgs/6d471a01fa901146c0ed9e2138f7c902/raw/}"

# System Configuration
TIMEZONE="${TIMEZONE:-UTC}"
SWAP_SIZE="${SWAP_SIZE:-2G}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-true}"
ALLOW_AUTO_REBOOT="${ALLOW_AUTO_REBOOT:-false}"
AUTO_REBOOT="${AUTO_REBOOT:-true}"

# Optional Features
ENABLE_CANARY_TOKEN="${ENABLE_CANARY_TOKEN:-false}"
CANARYTOKEN_URL="${CANARYTOKEN_URL:-}"
UBUNTU_LIVEPATCH_TOKEN="${UBUNTU_LIVEPATCH_TOKEN:-}"
LAN_IP="${LAN_IP:-}"

# Docker
DOCKER_VERSION="${DOCKER_VERSION:-latest}"

#==============================================================================
# PARSE COMMAND LINE ARGUMENTS (overrides environment variables)
#==============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ssh-key=*)
                SSH_PUBLIC_KEY="${1#*=}"
                shift
                ;;
            --ssh-port=*)
                SSH_PORT="${1#*=}"
                shift
                ;;
            --deploy-user=*)
                DEPLOY_USER="${1#*=}"
                shift
                ;;
            --swap-size=*)
                SWAP_SIZE="${1#*=}"
                shift
                ;;
            --fail2ban-whitelist-url=*)
                FAIL2BAN_WHITELIST_URL="${1#*=}"
                shift
                ;;
            --canary-url=*)
                CANARYTOKEN_URL="${1#*=}"
                ENABLE_CANARY_TOKEN="true"
                shift
                ;;
            --livepatch-token=*)
                UBUNTU_LIVEPATCH_TOKEN="${1#*=}"
                shift
                ;;
            --lan-ip=*)
                LAN_IP="${1#*=}"
                shift
                ;;
            --no-fail2ban)
                ENABLE_FAIL2BAN="false"
                shift
                ;;
            --no-reboot)
                AUTO_REBOOT="false"
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

show_usage() {
    cat << 'EOF'
Usage: provision_vps.sh [OPTIONS]

Required:
  None - All parameters are optional!

Optional:
  --ssh-key=KEY              SSH public key for deploy user
                             (checks Gist or uses provider key if omitted)
  --ssh-port=PORT           SSH port (default: 33003)
  --deploy-user=USER        Deploy username (default: deploy)
  --swap-size=SIZE          Swap size, e.g., 2G, 4G (default: 2G)
  --fail2ban-whitelist-url=URL  Gist URL for IP whitelist (default: turgs gist)
  --canary-url=URL          CanaryTokens URL for reboot alerts
  --livepatch-token=TOKEN   Ubuntu Livepatch token
  --lan-ip=IP               Binary Lane private network IP
  --no-fail2ban             Disable fail2ban installation
  --no-reboot               Skip automatic reboot after provisioning
  --help, -h                Show this help message

Examples:
  # Minimal (provider adds SSH key, uses all defaults)
  bash provision_vps.sh

  # With custom SSH key
  bash provision_vps.sh --ssh-key="ssh-ed25519 AAAA..."

  # SSH key from Gist (first ssh-* line)
  bash provision_vps.sh --fail2ban-whitelist-url="https://gist.../raw/"

  # Full options
  bash provision_vps.sh \
    --ssh-key="ssh-ed25519 AAAA..." \
    --ssh-port=33003 \
    --swap-size=4G \
    --canary-url="https://canarytokens.com/..."

Environment Variables (CLI args take priority):
  SSH_PUBLIC_KEY, SSH_PORT, DEPLOY_USER, SWAP_SIZE,
  FAIL2BAN_WHITELIST_URL, CANARYTOKEN_URL, etc.

EOF
}

#==============================================================================
# HELPER FUNCTIONS
#==============================================================================

STATE_FILE="/root/.provision_state"

mark_complete() {
    echo "$1" >> "$STATE_FILE"
}

is_complete() {
    grep -q "^$1$" "$STATE_FILE" 2>/dev/null
}

log() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
    echo ""
}

error() {
    echo "ERROR: $1" >&2
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        error "This script is designed for Ubuntu"
    fi
}

check_service() {
    local service=$1
    systemctl is-active --quiet "$service" 2>/dev/null
}

validate_ip() {
    local ip=$1
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    # Validate each octet is 0-255
    local IFS='./'
    local parts=($ip)
    for part in "${parts[@]:0:4}"; do
        [[ $part =~ ^[0-9]+$ ]] && [[ $part -le 255 ]] || return 1
    done
    return 0
}

fetch_from_gist() {
    local url=$1
    local pattern=$2
    if [[ -n "$url" ]]; then
        curl -fsSL --max-time 10 "$url" 2>/dev/null | grep -E "$pattern" | head -1 || true
    fi
}

generate_password() {
    # Generate a strong 32-character password
    if command -v openssl &>/dev/null; then
        openssl rand -base64 24 | head -c 32
    elif [[ -e /dev/urandom ]]; then
        tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 32
    else
        # Fallback to timestamp + random (less secure but functional)
        echo "${RANDOM}${RANDOM}$(date +%s%N)" | sha256sum | cut -d' ' -f1 | head -c 32
    fi
}

#==============================================================================
# MAIN PROVISIONING FUNCTIONS
#==============================================================================

preflight_checks() {
    log "Running Pre-flight Checks"
    
    # Check disk space (need at least 2GB free for swap + Docker)
    local AVAILABLE_GB
    AVAILABLE_GB=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
    if [[ $AVAILABLE_GB -lt 2 ]]; then
        error "Insufficient disk space: ${AVAILABLE_GB}GB available, need at least 2GB"
    fi
    echo "✓ Disk space: ${AVAILABLE_GB}GB available"
    
    # Check network connectivity and DNS in parallel
    local NET_OK=0 DNS_OK=0
    
    # Run network check in background and capture result
    ping -c 1 -W 3 8.8.8.8 &>/dev/null &
    local PID_NET=$!
    
    # Run DNS check in background and capture result
    (host github.com &>/dev/null || nslookup github.com &>/dev/null) &
    local PID_DNS=$!
    
    # Wait for results and capture exit codes
    wait $PID_NET && NET_OK=1 || NET_OK=0
    wait $PID_DNS && DNS_OK=1 || DNS_OK=0
    
    [[ $NET_OK -eq 0 ]] && error "No network connectivity detected"
    echo "✓ Network connectivity verified"
    
    [[ $DNS_OK -eq 0 ]] && error "DNS resolution not working"
    echo "✓ DNS resolution working"
    
    # Check if apt is locked (common on fresh VPS instances)
    local APT_WAIT=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $APT_WAIT -ge 300 ]]; then
            error "apt/dpkg locked for >5 minutes. Kill blocking process or wait longer."
        fi
        [[ $APT_WAIT -eq 0 ]] && echo "⚠ Waiting for apt/dpkg lock (unattended-upgrades may be running)..."
        sleep 10
        APT_WAIT=$((APT_WAIT + 10))
    done
    echo "✓ Package manager available"
    
    # Check if running in a container (not supported)
    if grep -q docker /proc/1/cgroup 2>/dev/null || [[ -f /.dockerenv ]]; then
        error "Cannot run inside a Docker container"
    fi
    echo "✓ Not running in container"
}

validate_inputs() {
    log "Validating Inputs"
    
    # Validate SSH port (1-65535, not privileged unless necessary)
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ $SSH_PORT -lt 1 ]] || [[ $SSH_PORT -gt 65535 ]]; then
        error "Invalid SSH port: $SSH_PORT (must be 1-65535)"
    fi
    [[ $SSH_PORT -eq 22 ]] && echo "⚠ Warning: Using default SSH port 22 (consider custom port for security)"
    
    # Warn about common service ports
    case $SSH_PORT in
        80|443|8080|3000|3306|5432) echo "⚠ Warning: Port $SSH_PORT commonly used by other services" ;;
    esac
    
    # Check if port already in use by another service
    if ss -tlnp | grep -q ":$SSH_PORT " && ! ss -tlnp | grep -q ":$SSH_PORT .*sshd"; then
        error "Port $SSH_PORT already in use by another service"
    fi
    echo "✓ SSH port: $SSH_PORT (available)"
    
    # Validate deploy user
    if ! [[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        error "Invalid username: $DEPLOY_USER (must start with letter/underscore, contain only lowercase, digits, hyphens)"
    fi
    echo "✓ Deploy user: $DEPLOY_USER"
    
    # Validate UID not in use (unless by existing deploy user)
    if getent passwd "$DEPLOY_UID" &>/dev/null; then
        local EXISTING_USER
        EXISTING_USER=$(getent passwd "$DEPLOY_UID" | cut -d: -f1)
        if [[ "$EXISTING_USER" != "$DEPLOY_USER" ]]; then
            error "UID $DEPLOY_UID already in use by user: $EXISTING_USER"
        fi
    fi
    echo "✓ Deploy UID: $DEPLOY_UID (available)"
    
    # Validate swap size format and disk space
    if [[ ! "$SWAP_SIZE" =~ ^[0-9]+[GM]$ ]]; then
        error "Invalid swap size format: $SWAP_SIZE (use: 2G or 2048M)"
    fi
    echo "✓ Swap size: $SWAP_SIZE"
    
    # Validate timezone
    if ! timedatectl list-timezones | grep -qx "$TIMEZONE"; then
        error "Invalid timezone: $TIMEZONE (use: timedatectl list-timezones)"
    fi
    echo "✓ Timezone: $TIMEZONE"
    
    # Validate SSH key format if provided
    if [[ -n "$SSH_PUBLIC_KEY" ]]; then
        if ! echo "$SSH_PUBLIC_KEY" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-)'; then
            error "Invalid SSH public key format"
        fi
        # Validate key has 3 parts (type, key, optional comment)
        local KEY_PARTS
        KEY_PARTS=$(echo "$SSH_PUBLIC_KEY" | awk '{print NF}')
        if [[ $KEY_PARTS -lt 2 ]]; then
            error "Malformed SSH key (missing components)"
        fi
        echo "✓ SSH public key validated"
    else
        echo "⚠ No SSH key provided - will check Gist or use provider key"
    fi
    
    # Validate LAN IP format if provided
    if [[ -n "$LAN_IP" ]]; then
        if ! validate_ip "$LAN_IP"; then
            error "Invalid LAN IP format: $LAN_IP"
        fi
    fi
    
    # Test Gist URL accessibility if provided
    if [[ -n "$FAIL2BAN_WHITELIST_URL" ]]; then
        if ! curl -fsSL --max-time 5 "$FAIL2BAN_WHITELIST_URL" &>/dev/null; then
            echo "⚠ Warning: Cannot reach whitelist Gist URL (will use localhost only)"
        else
            echo "✓ IP whitelist Gist: accessible"
        fi
    fi
    
    echo "✓ fail2ban: $ENABLE_FAIL2BAN"
    [[ -n "$CANARYTOKEN_URL" ]] && echo "✓ CanaryTokens: enabled"
    [[ -n "$UBUNTU_LIVEPATCH_TOKEN" ]] && echo "✓ Livepatch: enabled"
}

update_system() {
    if is_complete "update_system"; then
        echo "⚠ System already updated, skipping"
        return
    fi
    
    log "Updating System Packages"
    
    echo "Running apt-get update..."
    apt-get -yq update > /dev/null
    
    echo "Running apt-get upgrade..."
    apt-get -yq --with-new-pkgs upgrade > /dev/null
    
    echo "Running apt-get autoremove..."
    apt-get -yq autoremove > /dev/null
    
    # Install essential tools
    echo "Installing essential tools..."
    apt-get -yq install curl wget git vim ufw fail2ban logrotate ca-certificates gnupg lsb-release
    
    mark_complete "update_system"
    echo "✓ System updated"
}

setup_timezone() {
    if is_complete "setup_timezone"; then
        echo "⚠ Timezone already configured, skipping"
        return
    fi
    
    log "Setting Timezone to $TIMEZONE"
    
    timedatectl set-timezone "$TIMEZONE"
    echo "✓ Timezone set to $(timedatectl | grep 'Time zone' | awk '{print $3}')"
    
    mark_complete "setup_timezone"
}

create_deploy_user() {
    if is_complete "create_deploy_user"; then
        echo "⚠ Deploy user already configured, skipping"
        return
    fi
    
    log "Creating Deploy User: $DEPLOY_USER"
    
    # Check if user already exists
    if id "$DEPLOY_USER" &>/dev/null; then
        echo "⚠ User $DEPLOY_USER already exists, skipping creation"
    else
        useradd -m -u "$DEPLOY_UID" -s /bin/bash "$DEPLOY_USER"
        echo "✓ User $DEPLOY_USER created"
    fi
    
    # Generate password if not set
    if [[ -z "$DEPLOY_PASSWORD" ]]; then
        DEPLOY_PASSWORD=$(generate_password)
        echo "✓ Generated strong password for $DEPLOY_USER"
    fi
    
    # Set password (user won't use it due to SSH config, but good to have)
    echo "$DEPLOY_USER:$DEPLOY_PASSWORD" | chpasswd
    
    # Add to sudo group
    if ! usermod -aG sudo "$DEPLOY_USER"; then
        error "Failed to add $DEPLOY_USER to sudo group"
    fi
    
    # Verify user is in sudo group
    if ! groups "$DEPLOY_USER" | grep -q sudo; then
        error "User $DEPLOY_USER not in sudo group after usermod"
    fi
    
    # Save password securely for reference
    echo "$DEPLOY_PASSWORD" > /root/.${DEPLOY_USER}_password
    chmod 600 /root/.${DEPLOY_USER}_password
    
    echo "✓ Deploy user configured"
    echo "  Password: $DEPLOY_PASSWORD (save this for emergency sudo access)"
    echo "  Password also saved to: /root/.${DEPLOY_USER}_password"
    
    mark_complete "create_deploy_user"
}

setup_ssh_keys() {
    if is_complete "setup_ssh_keys"; then
        echo "⚠ SSH keys already configured, skipping"
        return
    fi
    
    log "Setting Up SSH Keys"
    
    # If no key provided, try fetching from Gist
    if [[ -z "$SSH_PUBLIC_KEY" ]] && [[ -n "$FAIL2BAN_WHITELIST_URL" ]]; then
        echo "  No SSH key provided, checking Gist..."
        SSH_PUBLIC_KEY=$(fetch_from_gist "$FAIL2BAN_WHITELIST_URL" '^ssh-(rsa|ed25519|ecdsa)')
        
        if [[ -n "$SSH_PUBLIC_KEY" ]]; then
            # Validate the fetched key has proper format
            local KEY_PARTS=$(echo "$SSH_PUBLIC_KEY" | awk '{print NF}')
            if [[ $KEY_PARTS -ge 2 ]]; then
                echo "  ✓ Found and validated SSH key in Gist"
            else
                echo "  ⚠ Found SSH key in Gist but format invalid, ignoring"
                SSH_PUBLIC_KEY=""
            fi
        else
            echo "  ⚠ No SSH key found in Gist"
        fi
    fi
    
    # If still no key, check if one already exists (provider auto-added)
    if [[ -z "$SSH_PUBLIC_KEY" ]]; then
        if [[ -f "/home/$DEPLOY_USER/.ssh/authorized_keys" ]] && [[ -s "/home/$DEPLOY_USER/.ssh/authorized_keys" ]]; then
            echo "  ⚠ No SSH key provided, but deploy user already has keys"
            echo "  ✓ Using existing SSH key configuration"
            mark_complete "setup_ssh_keys"
            return
        elif [[ -f "/root/.ssh/authorized_keys" ]] && [[ -s "/root/.ssh/authorized_keys" ]]; then
            echo "  ⚠ No SSH key provided, copying from root (provider added)"
            mkdir -p "/home/$DEPLOY_USER/.ssh"
            cp /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
            chmod 700 "/home/$DEPLOY_USER/.ssh"
            chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
            chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
            echo "  ✓ Copied SSH keys from root to $DEPLOY_USER"
            mark_complete "setup_ssh_keys"
            return
        else
            echo "  ⚠ WARNING: No SSH key found!"
            echo "  ⚠ You may lose access after reboot if provider didn't add keys"
            echo "  ⚠ Consider using --no-reboot and adding keys manually"
            mark_complete "setup_ssh_keys"
            return
        fi
    fi
    
    # Setup SSH directories
    mkdir -p /root/.ssh "/home/$DEPLOY_USER/.ssh"
    chmod 700 /root/.ssh "/home/$DEPLOY_USER/.ssh"
    
    # Add SSH key to both root and deploy user
    for AUTH_FILE in "/root/.ssh/authorized_keys" "/home/$DEPLOY_USER/.ssh/authorized_keys"; do
        if ! grep -qF "$SSH_PUBLIC_KEY" "$AUTH_FILE" 2>/dev/null; then
            echo "$SSH_PUBLIC_KEY" >> "$AUTH_FILE"
            echo "✓ Added SSH key to $(basename $(dirname $(dirname "$AUTH_FILE")))"
        fi
        chmod 600 "$AUTH_FILE"
        
        # Verify format immediately after adding
        local INVALID_KEYS=$(grep -v '^#' "$AUTH_FILE" | grep -v '^$' | grep -vE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-)' || true)
        [[ -n "$INVALID_KEYS" ]] && error "Invalid SSH key format in $AUTH_FILE"
    done
    
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    
    echo "✓ SSH keys configured"
    mark_complete "setup_ssh_keys"
}

configure_ssh() {
    if is_complete "configure_ssh"; then
        echo "⚠ SSH already configured, skipping"
        return
    fi
    
    log "Configuring SSH (Hybrid Security: Root Password + Deploy Keys-Only)"
    
    # Backup original config if not already backed up
    if [[ ! -f /etc/ssh/sshd_config.backup-provision ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup-provision
    fi
    
    # Create custom SSH config
    cat > /etc/ssh/sshd_config.d/99-custom.conf << EOF
# Custom SSH Configuration for Kamal 2 Deployment
# Port configuration
Port $SSH_PORT

# Global settings
PubkeyAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 30

# Forwarding (disabled for security, safe for Kamal)
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no

# Banner settings
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes

# Modern cryptography only
PubkeyAcceptedKeyTypes ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Deploy user: Keys only (secure)
Match User $DEPLOY_USER
    PasswordAuthentication no
    AuthenticationMethods publickey

# Root user: Password auth enabled (emergency access)
Match User root
    PasswordAuthentication yes
    PermitRootLogin yes
    
# Keep connections alive
Match All
    ClientAliveInterval 240
    ClientAliveCountMax 2
EOF
    
    # Test SSH config
    if ! sshd -t; then
        error "SSH configuration test failed"
    fi
    
    echo "✓ SSH configured on port $SSH_PORT"
    echo "  - Root: Password auth enabled (emergency access)"
    echo "  - $DEPLOY_USER: Keys only (production secure)"
    
    # Restart SSH
    systemctl restart sshd
    
    # Verify SSH restarted successfully
    sleep 2
    if ! systemctl is-active --quiet sshd; then
        error "SSH failed to restart! Restoring backup config..."
    fi
    
    echo "✓ SSH service restarted"
    mark_complete "configure_ssh"
}

configure_firewall() {
    if is_complete "configure_firewall"; then
        echo "⚠ Firewall already configured, skipping"
        return
    fi
    
    log "Configuring UFW Firewall"
    
    # Set defaults FIRST before adding rules
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # CRITICAL: Add SSH rule BEFORE enabling firewall to prevent lockout
    echo "  Adding SSH rule for port $SSH_PORT..."
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Allow HTTP/HTTPS for Kamal
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Show rules before enabling
    echo "  Rules to be enabled:"
    ufw show added | grep -v '^#' || true
    
    # Enable firewall
    ufw --force enable
    
    # Verify SSH port is allowed (critical to prevent lockout)
    if ! ufw status | grep -q "$SSH_PORT/tcp.*ALLOW"; then
        error "SSH port $SSH_PORT not allowed in firewall! This would cause lockout."
    fi
    
    # Configure UFW logging (medium to avoid log spam)
    ufw logging medium
    
    echo "✓ Firewall configured"
    echo "  - Port $SSH_PORT: SSH"
    echo "  - Port 80: HTTP"
    echo "  - Port 443: HTTPS"
    
    mark_complete "configure_firewall"
}

create_whitelist_updater() {
    log "Creating Dynamic IP Whitelist Updater"
    
    mkdir -p /etc/fail2ban/scripts
    
    cat > /etc/fail2ban/scripts/update_whitelist.sh << 'SCRIPT_EOF'
#!/bin/bash
set -euo pipefail

GIST_URL="${FAIL2BAN_WHITELIST_URL:-https://gist.githubusercontent.com/turgs/6d471a01fa901146c0ed9e2138f7c902/raw/}"
WHITELIST_FILE="/etc/fail2ban/ip_whitelist.conf"
TEMP_FILE="${WHITELIST_FILE}.tmp"

# Always start with localhost
echo "127.0.0.1/8" > "$TEMP_FILE"

# Fetch from Gist if URL provided
if [[ -n "$GIST_URL" ]]; then
    if curl -fsSL --max-time 10 "$GIST_URL" 2>/dev/null | \
        grep -v '^#' | \
        grep -v '^[[:space:]]*$' | \
        awk '{print $1}' | \
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' >> "$TEMP_FILE" 2>/dev/null; then
        
        # Success - atomic update
        mv "$TEMP_FILE" "$WHITELIST_FILE"
        
        # Reload fail2ban if running
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            if systemctl reload fail2ban 2>/dev/null; then
                logger -t fail2ban-whitelist "Updated whitelist from Gist: $(wc -l < "$WHITELIST_FILE") IPs"
            else
                logger -t fail2ban-whitelist "WARNING: Whitelist updated but fail2ban reload failed"
            fi
        fi
    else
        # Fetch failed - keep existing file or create localhost-only
        if [[ ! -f "$WHITELIST_FILE" ]]; then
            mv "$TEMP_FILE" "$WHITELIST_FILE"
            logger -t fail2ban-whitelist "Created localhost-only whitelist (Gist fetch failed)"
        else
            rm -f "$TEMP_FILE"
            logger -t fail2ban-whitelist "Failed to fetch Gist, keeping existing whitelist"
        fi
    fi
else
    # No URL, just localhost
    mv "$TEMP_FILE" "$WHITELIST_FILE"
fi
SCRIPT_EOF
    
    chmod +x /etc/fail2ban/scripts/update_whitelist.sh
    
    # Set environment variable for the script
    cat > /etc/default/fail2ban-whitelist << EOF
FAIL2BAN_WHITELIST_URL="$FAIL2BAN_WHITELIST_URL"
EOF
    
    # Update the script to source this file
    if ! sed -i '2a source /etc/default/fail2ban-whitelist 2>/dev/null || true' /etc/fail2ban/scripts/update_whitelist.sh; then
        error "Failed to update whitelist updater script"
    fi
    
    # Verify the source line was added
    if ! grep -q 'source /etc/default/fail2ban-whitelist' /etc/fail2ban/scripts/update_whitelist.sh; then
        error "Whitelist updater script modification failed"
    fi
    
    echo "✓ Whitelist updater created (will run after fail2ban starts)"
}

configure_fail2ban() {
    if is_complete "configure_fail2ban"; then
        echo "⚠ fail2ban already configured, skipping"
        return
    fi
    
    log "Configuring fail2ban"
    
    [[ "$ENABLE_FAIL2BAN" != "true" ]] && { echo "⚠ fail2ban disabled, skipping"; mark_complete "configure_fail2ban"; return; }
    
    # Create dynamic whitelist updater first (but don't run yet)
    create_whitelist_updater
    
    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban settings
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME
maxretry = $FAIL2BAN_MAXRETRY

# Progressive ban (repeat offenders get longer bans)
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 4w

# Whitelist from dynamic file
ignoreip = 127.0.0.1/8
ignorecommand = cat /etc/fail2ban/ip_whitelist.conf

# Action (ban only, no email by default)
action = %(action_)s

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
maxretry = $FAIL2BAN_MAXRETRY

[sshd-ddos]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
maxretry = 10

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 3
EOF
    
    # Setup hourly cron to update whitelist
    cat > /etc/cron.d/fail2ban_whitelist << EOF
# Update fail2ban IP whitelist hourly from Gist
0 * * * * root /etc/fail2ban/scripts/update_whitelist.sh > /dev/null 2>&1

# Also update on reboot
@reboot root sleep 60 && /etc/fail2ban/scripts/update_whitelist.sh > /dev/null 2>&1
EOF
    
    chmod +x /etc/cron.d/fail2ban_whitelist
    
    # Restart fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    # Wait for fail2ban to start and verify with retry logic
    local RETRY=0
    while ! systemctl is-active --quiet fail2ban && [[ $RETRY -lt 10 ]]; do
        sleep 1
        RETRY=$((RETRY + 1))
    done
    
    if ! systemctl is-active --quiet fail2ban; then
        error "fail2ban failed to start after 10 seconds! Check: journalctl -u fail2ban -n 50"
    fi
    
    # Wait for jails to initialize before running whitelist updater
    sleep 2
    RETRY=0
    while ! fail2ban-client status &>/dev/null && [[ $RETRY -lt 5 ]]; do
        sleep 1
        RETRY=$((RETRY + 1))
    done
    
    # Now run whitelist updater (fail2ban is ready)
    /etc/fail2ban/scripts/update_whitelist.sh
    
    # Verify SSH jail is active
    if ! fail2ban-client status sshd &>/dev/null; then
        echo "⚠ Warning: fail2ban sshd jail not active yet (may need more time)"
    fi
    
    echo "✓ fail2ban configured"
    echo "  - Ban time: $(($FAIL2BAN_BANTIME / 3600)) hours"
    echo "  - Max retries: $FAIL2BAN_MAXRETRY"
    echo "  - Find time: $(($FAIL2BAN_FINDTIME / 60)) minutes"
    echo "  - Progressive bans: enabled"
    echo "  - Dynamic whitelist: enabled"
    
    mark_complete "configure_fail2ban"
}

configure_unattended_upgrades() {
    if is_complete "configure_unattended_upgrades"; then
        echo "⚠ Unattended upgrades already configured, skipping"
        return
    fi
    
    log "Configuring Unattended Upgrades"
    
    [[ "$ENABLE_UNATTENDED_UPGRADES" != "true" ]] && { echo "⚠ Unattended upgrades disabled, skipping"; mark_complete "configure_unattended_upgrades"; return; }
    
    apt-get -yq install unattended-upgrades
    
    # Configure automatic updates
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};

Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$ALLOW_AUTO_REBOOT";
EOF
    
    if [[ "$ALLOW_AUTO_REBOOT" == "true" ]]; then
        echo 'Unattended-Upgrade::Automatic-Reboot-Time "16:00";  // 2am Brisbane' >> /etc/apt/apt.conf.d/50unattended-upgrades
    fi
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    echo "✓ Unattended upgrades configured"
    echo "  - Auto-reboot: $ALLOW_AUTO_REBOOT"
    
    mark_complete "configure_unattended_upgrades"
}

create_swap() {
    if is_complete "create_swap"; then
        echo "⚠ Swap already configured, skipping"
        return
    fi
    
    # Early check before acquiring lock to prevent unnecessary waiting
    if swapon --show | grep -q '/swapfile'; then
        echo "⚠ Swap already exists, skipping"
        mark_complete "create_swap"
        return
    fi
    
    log "Creating Swap: $SWAP_SIZE"
    
    # Use flock to prevent concurrent swap creation
    (
        flock -n 200 || { echo "⚠ Another swap creation in progress, waiting..."; flock 200; }
        
        # Double-check inside lock
        if swapon --show | grep -q '/swapfile'; then
            echo "⚠ Swap already exists, skipping"
            mark_complete "create_swap"
            return
        fi
    
    # Parse swap size to MB (validation already done in validate_inputs)
    local SIZE_MB=${SWAP_SIZE%[GM]}
    [[ "$SWAP_SIZE" == *G ]] && SIZE_MB=$((SIZE_MB * 1024))
    
    # Create swap file - try fallocate first (faster), fallback to dd
    if ! fallocate -l "${SIZE_MB}M" /swapfile 2>/dev/null; then
        echo "⚠ fallocate not supported, using dd (slower)..."
        dd if=/dev/zero of=/swapfile bs=1M count="$SIZE_MB" status=progress
    fi
    
    # Verify swap file was created
    if [[ ! -f /swapfile ]]; then
        error "Failed to create /swapfile"
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Make permanent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    fi
    
    # Verify swap is active
    if ! swapon --show | grep -q '/swapfile'; then
        error "Swap creation failed - swap not active"
    fi
    
    echo "✓ Swap created: $SWAP_SIZE"
    mark_complete "create_swap"
    
    ) 200>/var/lock/provision_swap.lock
}

install_docker() {
    if is_complete "install_docker"; then
        echo "⚠ Docker already installed and configured, skipping"
        return
    fi
    
    log "Installing Docker"
    
    # Ensure jq is available for Docker daemon.json validation later
    if ! command -v jq &>/dev/null; then
        echo "Installing jq for JSON validation..."
        apt-get -yq install jq > /dev/null
    fi
    
    # Check disk space (Docker needs ~500MB minimum)
    local AVAILABLE_MB=$(df / | awk 'NR==2 {print int($4/1024)}')
    if [[ $AVAILABLE_MB -lt 500 ]]; then
        error "Insufficient disk space for Docker: ${AVAILABLE_MB}MB available, need at least 500MB"
    fi
    
    # Check if Docker already installed
    if command -v docker &> /dev/null; then
        echo "⚠ Docker already installed: $(docker --version)"
        echo "  Ensuring $DEPLOY_USER in docker group..."
        if ! usermod -aG docker "$DEPLOY_USER"; then
            error "Failed to add $DEPLOY_USER to docker group"
        fi
        # Verify user is in docker group
        if ! groups "$DEPLOY_USER" | grep -q docker; then
            error "User $DEPLOY_USER not in docker group after usermod"
        fi
        mark_complete "install_docker"
        return
    fi
    
    # Install Docker using official script with error handling
    echo "Downloading Docker installation script..."
    if ! curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        error "Failed to download Docker installation script"
    fi
    
    echo "Installing Docker (this may take a few minutes)..."
    if ! sh /tmp/get-docker.sh > /dev/null 2>&1; then
        error "Docker installation failed"
    fi
    
    rm -f /tmp/get-docker.sh
    
    # Add deploy user to docker group
    if ! usermod -aG docker "$DEPLOY_USER"; then
        error "Failed to add $DEPLOY_USER to docker group"
    fi
    
    # Verify user is in docker group
    if ! groups "$DEPLOY_USER" | grep -q docker; then
        error "User $DEPLOY_USER not in docker group after usermod"
    fi
    
    # Enable Docker service
    systemctl enable docker
    systemctl start docker
    
    # Configure Docker daemon with security and performance settings
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
EOF
    
    # Validate JSON syntax before applying
    if command -v python3 &>/dev/null; then
        if ! python3 -m json.tool /etc/docker/daemon.json >/dev/null 2>&1; then
            error "Invalid JSON in Docker daemon.json configuration"
        fi
    elif command -v jq &>/dev/null; then
        if ! jq empty /etc/docker/daemon.json >/dev/null 2>&1; then
            error "Invalid JSON in Docker daemon.json configuration"
        fi
    fi
    echo "✓ Docker configuration validated"
    
    # Reload Docker daemon to apply configuration (safer than restart on fresh install)
    systemctl daemon-reload
    systemctl restart docker
    
    # Wait for Docker to be ready
    local RETRY=0
    while ! docker info &>/dev/null && [[ $RETRY -lt 10 ]]; do
        sleep 1
        RETRY=$((RETRY + 1))
    done
    
    [[ $RETRY -eq 10 ]] && error "Docker daemon not responding after configuration"
    
    echo "✓ Docker installed: $(docker --version)"
    echo "  - User $DEPLOY_USER added to docker group"
    echo "  - Docker group will activate after reboot"
    echo "  - Log rotation configured"
    echo "  - Daemon verified functional"
    
    mark_complete "install_docker"
}

configure_sysctl() {
    if is_complete "configure_sysctl"; then
        echo "⚠ System parameters already configured, skipping"
        return
    fi
    
    log "Configuring System Parameters"
    
    cat > /etc/sysctl.d/99-custom.conf << EOF
# File system - Docker/Kamal optimization
fs.inotify.max_user_watches=524288

# Memory management - Container optimization
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.overcommit_memory=1

# Network security hardening
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1

# Connection tracking for Docker
net.netfilter.nf_conntrack_max=262144
net.ipv4.ip_local_port_range=1024 65535
EOF
    
    sysctl -p /etc/sysctl.d/99-custom.conf
    
    echo "✓ System parameters configured"
    mark_complete "configure_sysctl"
}

setup_ubuntu_livepatch() {
    if is_complete "setup_ubuntu_livepatch"; then
        echo "⚠ Ubuntu Livepatch already configured, skipping"
        return
    fi
    
    log "Setting Up Ubuntu Livepatch"
    
    [[ -z "$UBUNTU_LIVEPATCH_TOKEN" ]] && { echo "⚠ No Livepatch token provided, skipping"; mark_complete "setup_ubuntu_livepatch"; return; }
    
    apt-get -yq install snapd > /dev/null
    snap install canonical-livepatch
    canonical-livepatch enable "$UBUNTU_LIVEPATCH_TOKEN"
    
    echo "✓ Ubuntu Livepatch enabled"
    mark_complete "setup_ubuntu_livepatch"
}

setup_canary_token() {
    if is_complete "setup_canary_token"; then
        echo "⚠ CanaryTokens already configured, skipping"
        return
    fi
    
    log "Setting Up CanaryTokens Reboot Alert"
    
    [[ "$ENABLE_CANARY_TOKEN" != "true" || -z "$CANARYTOKEN_URL" ]] && { echo "⚠ CanaryTokens not configured, skipping"; mark_complete "setup_canary_token"; return; }
    
    cat > /etc/cron.d/reboot_canary << EOF
@reboot $DEPLOY_USER curl -fsS --retry 3 --max-time 10 "$CANARYTOKEN_URL" > /dev/null 2>&1 || true
EOF
    
    chmod 600 /etc/cron.d/reboot_canary
    
    echo "✓ CanaryTokens reboot alert configured (secure permissions)"
    mark_complete "setup_canary_token"
}

setup_log_rotation() {
    if is_complete "setup_log_rotation"; then
        echo "⚠ Log rotation already configured, skipping"
        return
    fi
    
    log "Configuring Log Rotation"
    
    cat > /etc/logrotate.d/custom-security << EOF
/var/log/ufw.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}

/var/log/fail2ban.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
EOF
    
    echo "✓ Log rotation configured"
    mark_complete "setup_log_rotation"
}

configure_lan_ip() {
    if is_complete "configure_lan_ip"; then
        echo "⚠ LAN IP already configured, skipping"
        return
    fi
    
    log "Configuring Binary Lane Private Network IP"
    
    [[ -z "$LAN_IP" ]] && { echo "⚠ No LAN IP provided, skipping"; mark_complete "configure_lan_ip"; return; }
    
    # Detect primary network interface
    local IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    IFACE=${IFACE:-eth0}
    [[ -z "${IFACE// /}" ]] && IFACE="eth0"
    
    # Verify interface exists
    if ! ip link show "$IFACE" &>/dev/null; then
        error "Network interface $IFACE does not exist"
    fi
    
    echo "  Using interface: $IFACE"
    
    # Use netplan for modern Ubuntu
    cat > /etc/netplan/60-private-network.yaml << EOF
network:
  version: 2
  ethernets:
    $IFACE:
      addresses:
        - $LAN_IP/16
EOF
    
    chmod 600 /etc/netplan/60-private-network.yaml
    
    # Backup existing netplan configs before making changes
    mkdir -p /etc/netplan/backup
    
    # Save list of original config files for precise rollback
    local ORIGINAL_CONFIGS=()
    mapfile -t ORIGINAL_CONFIGS < <(find /etc/netplan -maxdepth 1 -name '*.yaml' -type f 2>/dev/null || true)
    
    # Create backup copies
    for config in "${ORIGINAL_CONFIGS[@]}"; do
        [[ -f "$config" ]] && cp "$config" /etc/netplan/backup/ 2>/dev/null || true
    done
    
    # Test netplan config before applying
    if ! netplan generate; then
        error "Invalid netplan configuration generated"
    fi
    
    # Apply with timeout and verification
    if ! timeout 10 netplan apply 2>/dev/null; then
        echo "⚠ WARNING: netplan apply timed out or failed, attempting rollback"
        # Remove our new config
        rm -f /etc/netplan/60-private-network.yaml
        # Restore ONLY the original configs (not all backup files)
        for orig_config in "${ORIGINAL_CONFIGS[@]}"; do
            local basename_file=$(basename "$orig_config")
            [[ -f "/etc/netplan/backup/$basename_file" ]] && cp "/etc/netplan/backup/$basename_file" "$orig_config" 2>/dev/null || true
        done
        netplan apply 2>/dev/null || true
        error "Failed to apply netplan configuration (rolled back)"
    fi
    
    # Verify network still works after netplan changes (test multiple endpoints)
    sleep 3
    local CONNECTIVITY_OK=false
    for test_ip in 8.8.8.8 1.1.1.1 208.67.222.222; do
        if ping -c 2 -W 3 "$test_ip" &>/dev/null; then
            CONNECTIVITY_OK=true
            break
        fi
    done
    
    if [[ "$CONNECTIVITY_OK" != "true" ]]; then
        echo "⚠ WARNING: Network connectivity affected, rolling back netplan changes"
        # Remove our new config
        rm -f /etc/netplan/60-private-network.yaml
        # Restore ONLY the original configs
        for orig_config in "${ORIGINAL_CONFIGS[@]}"; do
            local basename_file=$(basename "$orig_config")
            [[ -f "/etc/netplan/backup/$basename_file" ]] && cp "/etc/netplan/backup/$basename_file" "$orig_config" 2>/dev/null || true
        done
        netplan apply 2>/dev/null || true
        error "Network connectivity lost after netplan changes (rolled back)"
    fi
    
    echo "✓ Private network IP configured: $LAN_IP on $IFACE"
    mark_complete "configure_lan_ip"
}

verify_ssh_connectivity() {
    log "Verifying SSH Configuration"
    
    # Test SSHD config
    if ! sshd -t 2>&1; then
        echo "  ✗ SSH configuration test failed!"
        error "SSH configuration invalid! NOT rebooting to prevent lockout."
    fi
    echo "  ✓ SSH config valid"
    
    # Verify SSH service is running
    if ! check_service sshd; then
        error "SSH service not running!"
    fi
    echo "  ✓ SSH service active"
    
    # Verify SSH is listening on the correct port
    local MAX_WAIT=10
    local WAIT=0
    while ! ss -tlnp | grep -q ":$SSH_PORT " && [[ $WAIT -lt $MAX_WAIT ]]; do
        echo "  ⚠ Waiting for SSH to listen on port $SSH_PORT..."
        sleep 1
        WAIT=$((WAIT + 1))
    done
    
    if ss -tlnp | grep -q ":$SSH_PORT "; then
        echo "  ✓ SSH listening on port $SSH_PORT"
    else
        error "SSH not listening on port $SSH_PORT! Check configuration."
    fi
    
    # Verify firewall allows SSH port
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "$SSH_PORT.*ALLOW"; then
            error "Firewall not allowing SSH port $SSH_PORT!"
        fi
        echo "  ✓ Firewall allows SSH port"
    fi
    
    # Verify authorized_keys exists and has correct permissions
    local KEY_FILE="/home/$DEPLOY_USER/.ssh/authorized_keys"
    if [[ -f "$KEY_FILE" ]]; then
        local PERMS
        PERMS=$(stat -c %a "$KEY_FILE")
        if [[ "$PERMS" != "600" ]]; then
            error "Incorrect permissions on $KEY_FILE (found: $PERMS, need: 600)"
        fi
        echo "  ✓ SSH keys have correct permissions"
        
        # Verify key content if we explicitly added one
        if [[ -n "$SSH_PUBLIC_KEY" ]]; then
            if ! grep -qF "$(echo "$SSH_PUBLIC_KEY" | awk '{print $2}')" "$KEY_FILE"; then
                error "SSH public key not found in $KEY_FILE"
            fi
            echo "  ✓ SSH public key installed correctly"
        else
            local KEY_COUNT
            KEY_COUNT=$(grep -c '^ssh-' "$KEY_FILE" 2>/dev/null || echo 0)
            echo "  ✓ SSH authorized_keys exists ($KEY_COUNT key(s) found)"
        fi
    else
        echo "  ⚠ WARNING: No authorized_keys file found!"
        echo "  ⚠ You may lose SSH access after reboot"
        if [[ "$AUTO_REBOOT" == "true" ]]; then
            error "Cannot safely reboot without SSH keys. Use --no-reboot to continue anyway."
        fi
    fi
    
    echo ""
    echo "✓ SSH connectivity verified - safe to reboot"
}

verify_setup() {
    log "Verifying Setup"
    
    echo "Checking services..."
    
    # Check SSH
    if check_service sshd; then
        echo "  ✓ SSH running on port $SSH_PORT"
    else
        echo "  ✗ SSH not running"
    fi
    
    # Check UFW
    if ufw status | grep -q "Status: active"; then
        echo "  ✓ Firewall active"
    else
        echo "  ✗ Firewall not active"
    fi
    
    # Check fail2ban
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        if check_service fail2ban; then
            echo "  ✓ fail2ban running"
        else
            echo "  ✗ fail2ban not running"
        fi
    fi
    
    # Check Docker
    if command -v docker &> /dev/null && check_service docker; then
        echo "  ✓ Docker installed and running"
        groups "$DEPLOY_USER" | grep -q docker && echo "  ✓ $DEPLOY_USER in docker group"
    fi
    
    # Check swap
    swapon --show | grep -q '/swapfile' && echo "  ✓ Swap active"
    
    echo ""
    echo "Setup verification complete!"
}

show_summary() {
    log "Provisioning Complete!"
    
    cat << EOF
Server is now configured for Kamal 2 deployment.

IMPORTANT INFORMATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSH ACCESS:
  Port: $SSH_PORT
  Deploy user: $DEPLOY_USER (keys-only)
  Root user: root (password + keys - emergency access)
  
  Connect as deploy: ssh -p $SSH_PORT $DEPLOY_USER@<server-ip>
  Connect as root:   ssh -p $SSH_PORT root@<server-ip>

DEPLOY USER PASSWORD (for sudo):
  $DEPLOY_PASSWORD

SECURITY:
  - fail2ban: $(if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then echo "enabled (24h bans)"; else echo "disabled"; fi)
  - Firewall: ports $SSH_PORT, 80, 443 open
  - Unattended upgrades: $ENABLE_UNATTENDED_UPGRADES
  - Dynamic IP whitelist: $(if [[ -n "$FAIL2BAN_WHITELIST_URL" ]]; then echo "enabled"; else echo "disabled"; fi)

KAMAL 2 CONFIGURATION:
  Add to your .kamal/deploy.yml:
  
  ssh:
    port: $SSH_PORT
    user: $DEPLOY_USER

NEXT STEPS:
  1. Reboot the server to apply all changes $(if [[ "$AUTO_REBOOT" == "true" ]]; then echo "(automatic)"; else echo "(manual: sudo reboot)"; fi)
  2. Wait 2 minutes for server to stabilize
  3. Test SSH connection: ssh -p $SSH_PORT $DEPLOY_USER@<server-ip>
  4. Test Docker: docker ps (should work without sudo)
  5. Configure Kamal and deploy!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
}

#==============================================================================
# MAIN EXECUTION
#==============================================================================

main() {
    # Parse arguments
    parse_args "$@"
    
    # Pre-flight checks
    check_root
    check_ubuntu
    
    # Show banner
    clear 2>/dev/null || true
    cat << 'EOF'
╔════════════════════════════════════════════════╗
║                                                ║
║   Ubuntu VPS Provisioning Script for Kamal 2   ║
║                                                ║
╚════════════════════════════════════════════════╝
EOF
    
    # Run comprehensive pre-flight checks
    preflight_checks
    
    # Validate inputs
    validate_inputs
    
    # Execute provisioning steps
    update_system
    setup_timezone
    create_deploy_user
    setup_ssh_keys
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_unattended_upgrades
    create_swap
    install_docker
    configure_sysctl
    setup_log_rotation
    setup_ubuntu_livepatch
    setup_canary_token
    configure_lan_ip
    
    # Verify everything worked
    verify_setup
    
    # Critical: Verify SSH before rebooting
    verify_ssh_connectivity
    
    # Show summary
    show_summary
    
    # Reboot (optional)
    if [[ "$AUTO_REBOOT" == "true" ]]; then
        log "Rebooting in 10 seconds..."
        echo "Press Ctrl+C to cancel"
        sleep 10
        reboot
    else
        log "Provisioning Complete"
        echo "⚠ Automatic reboot disabled. Please reboot manually to apply all changes:"
        echo "  sudo reboot"
    fi
}

# Run main function
main "$@"
