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

generate_password() {
    # Generate a strong 32-character password
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 32
}

#==============================================================================
# MAIN PROVISIONING FUNCTIONS
#==============================================================================

validate_inputs() {
    log "Validating Inputs"
    
    # Validate SSH key format if provided
    if [[ -n "$SSH_PUBLIC_KEY" ]]; then
        if ! echo "$SSH_PUBLIC_KEY" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-)'; then
            error "Invalid SSH public key format"
        fi
        echo "✓ SSH public key validated"
    else
        echo "⚠ No SSH key provided - will check Gist or use provider key"
    fi
    
    echo "✓ SSH port: $SSH_PORT"
    echo "✓ Deploy user: $DEPLOY_USER"
    echo "✓ Swap size: $SWAP_SIZE"
    echo "✓ fail2ban: $ENABLE_FAIL2BAN"
    [[ -n "$FAIL2BAN_WHITELIST_URL" ]] && echo "✓ IP whitelist: enabled (Gist)"
    [[ -n "$CANARYTOKEN_URL" ]] && echo "✓ CanaryTokens: enabled"
    [[ -n "$UBUNTU_LIVEPATCH_TOKEN" ]] && echo "✓ Livepatch: enabled"
}

update_system() {
    if is_complete "update_system"; then
        echo "⚠ System already updated, skipping"
        return
    fi
    
    log "Updating System Packages"
    
    apt-get -yq update
    apt-get -yq --with-new-pkgs upgrade
    apt-get -yq autoremove
    
    # Install essential tools
    apt-get -yq install curl wget git vim ufw fail2ban logrotate ca-certificates gnupg lsb-release
    
    mark_complete "update_system"
    echo "✓ System updated"
}

setup_timezone() {
    log "Setting Timezone to $TIMEZONE"
    
    timedatectl set-timezone "$TIMEZONE"
    echo "✓ Timezone set to $(timedatectl | grep 'Time zone' | awk '{print $3}')"
}

create_deploy_user() {
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
    usermod -aG sudo "$DEPLOY_USER"
    
    echo "✓ Deploy user configured"
    echo "  Password: $DEPLOY_PASSWORD (save this for emergency sudo access)"
}

setup_ssh_keys() {
    log "Setting Up SSH Keys"
    
    # If no key provided, try fetching from Gist
    if [[ -z "$SSH_PUBLIC_KEY" ]] && [[ -n "$FAIL2BAN_WHITELIST_URL" ]]; then
        echo "  No SSH key provided, checking Gist..."
        local GIST_CONTENT
        GIST_CONTENT=$(curl -fsSL "$FAIL2BAN_WHITELIST_URL" 2>/dev/null || true)
        
        # Look for SSH key in Gist (lines starting with ssh-)
        SSH_PUBLIC_KEY=$(echo "$GIST_CONTENT" | grep -E '^ssh-(rsa|ed25519|ecdsa)' | head -1 || true)
        
        if [[ -n "$SSH_PUBLIC_KEY" ]]; then
            echo "  ✓ Found SSH key in Gist"
        fi
    fi
    
    # If still no key, check if one already exists (provider auto-added)
    if [[ -z "$SSH_PUBLIC_KEY" ]]; then
        if [[ -f "/home/$DEPLOY_USER/.ssh/authorized_keys" ]] && [[ -s "/home/$DEPLOY_USER/.ssh/authorized_keys" ]]; then
            echo "  ⚠ No SSH key provided, but deploy user already has keys"
            echo "  ✓ Using existing SSH key configuration"
            return
        elif [[ -f "/root/.ssh/authorized_keys" ]] && [[ -s "/root/.ssh/authorized_keys" ]]; then
            echo "  ⚠ No SSH key provided, copying from root (provider added)"
            mkdir -p "/home/$DEPLOY_USER/.ssh"
            cp /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
            chmod 700 "/home/$DEPLOY_USER/.ssh"
            chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
            chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
            echo "  ✓ Copied SSH keys from root to $DEPLOY_USER"
            return
        else
            echo "  ⚠ WARNING: No SSH key found!"
            echo "  ⚠ You may lose access after reboot if provider didn't add keys"
            echo "  ⚠ Consider using --no-reboot and adding keys manually"
            return
        fi
    fi
    
    # Setup for root
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # Add SSH key to root if not already present
    if ! grep -qF "$SSH_PUBLIC_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
        echo "✓ Added SSH key to root"
    else
        echo "⚠ SSH key already in root authorized_keys"
    fi
    
    chmod 600 /root/.ssh/authorized_keys
    
    # Setup for deploy user
    mkdir -p "/home/$DEPLOY_USER/.ssh"
    
    # Copy SSH key to deploy user
    if ! grep -qF "$SSH_PUBLIC_KEY" "/home/$DEPLOY_USER/.ssh/authorized_keys" 2>/dev/null; then
        echo "$SSH_PUBLIC_KEY" >> "/home/$DEPLOY_USER/.ssh/authorized_keys"
        echo "✓ Added SSH key to $DEPLOY_USER"
    else
        echo "⚠ SSH key already in $DEPLOY_USER authorized_keys"
    fi
    
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    chmod 700 "/home/$DEPLOY_USER/.ssh"
    chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
    
    echo "✓ SSH keys configured"
}

configure_ssh() {
    log "Configuring SSH (Hybrid Security: Root Password + Deploy Keys-Only)"
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
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
    echo "✓ SSH service restarted"
}

configure_firewall() {
    log "Configuring UFW Firewall"
    
    # Set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH on custom port
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Allow HTTP/HTTPS for Kamal
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable firewall
    ufw --force enable
    
    # Configure UFW logging to separate file
    ufw logging on
    
    echo "✓ Firewall configured"
    echo "  - Port $SSH_PORT: SSH"
    echo "  - Port 80: HTTP"
    echo "  - Port 443: HTTPS"
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
        grep -E '^[0-9]+\.' >> "$TEMP_FILE" 2>/dev/null; then
        
        # Success - atomic update
        mv "$TEMP_FILE" "$WHITELIST_FILE"
        
        # Reload fail2ban if running
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            systemctl reload fail2ban 2>/dev/null || true
        fi
        
        logger -t fail2ban-whitelist "Updated whitelist from Gist: $(wc -l < "$WHITELIST_FILE") IPs"
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
    sed -i '2a source /etc/default/fail2ban-whitelist 2>/dev/null || true' /etc/fail2ban/scripts/update_whitelist.sh
    
    # Run immediately to create initial whitelist
    /etc/fail2ban/scripts/update_whitelist.sh
    
    echo "✓ Whitelist updater created"
    [[ -f /etc/fail2ban/ip_whitelist.conf ]] && echo "  Whitelisted IPs: $(wc -l < /etc/fail2ban/ip_whitelist.conf)"
}

configure_fail2ban() {
    log "Configuring fail2ban"
    
    if [[ "$ENABLE_FAIL2BAN" != "true" ]]; then
        echo "⚠ fail2ban disabled, skipping"
        return
    fi
    
    # Create dynamic whitelist updater first
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
    
    echo "✓ fail2ban configured"
    echo "  - Ban time: $(($FAIL2BAN_BANTIME / 3600)) hours"
    echo "  - Max retries: $FAIL2BAN_MAXRETRY"
    echo "  - Find time: $(($FAIL2BAN_FINDTIME / 60)) minutes"
    echo "  - Progressive bans: enabled"
    echo "  - Dynamic whitelist: enabled"
}

configure_unattended_upgrades() {
    log "Configuring Unattended Upgrades"
    
    if [[ "$ENABLE_UNATTENDED_UPGRADES" != "true" ]]; then
        echo "⚠ Unattended upgrades disabled, skipping"
        return
    fi
    
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
}

create_swap() {
    log "Creating Swap: $SWAP_SIZE"
    
    # Check if swap already exists
    if swapon --show | grep -q '/swapfile'; then
        echo "⚠ Swap already exists, skipping"
        return
    fi
    
    # Parse swap size to MB
    local SIZE_MB
    if [[ "$SWAP_SIZE" =~ ^([0-9]+)G$ ]]; then
        SIZE_MB=$((${BASH_REMATCH[1]} * 1024))
    elif [[ "$SWAP_SIZE" =~ ^([0-9]+)M$ ]]; then
        SIZE_MB=${BASH_REMATCH[1]}
    else
        error "Invalid swap size format. Use: 2G or 2048M"
    fi
    
    # Create swap file - try fallocate first (faster), fallback to dd
    if ! fallocate -l "${SIZE_MB}M" /swapfile 2>/dev/null; then
        echo "⚠ fallocate not supported, using dd (slower)..."
        dd if=/dev/zero of=/swapfile bs=1M count="$SIZE_MB" status=progress
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Make permanent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    fi
    
    echo "✓ Swap created: $SWAP_SIZE"
}

install_docker() {
    log "Installing Docker"
    
    # Check if Docker already installed
    if command -v docker &> /dev/null; then
        echo "⚠ Docker already installed: $(docker --version)"
        echo "  Ensuring $DEPLOY_USER in docker group..."
        usermod -aG docker "$DEPLOY_USER"
        return
    fi
    
    # Install Docker using official script
    curl -fsSL https://get.docker.com | sh
    
    # Add deploy user to docker group
    usermod -aG docker "$DEPLOY_USER"
    
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
    
    systemctl restart docker
    
    echo "✓ Docker installed: $(docker --version)"
    echo "  - User $DEPLOY_USER added to docker group"
    echo "  - Log rotation configured"
}

configure_sysctl() {
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
}

setup_ubuntu_livepatch() {
    log "Setting Up Ubuntu Livepatch"
    
    if [[ -z "$UBUNTU_LIVEPATCH_TOKEN" ]]; then
        echo "⚠ No Livepatch token provided, skipping"
        return
    fi
    
    apt-get -yq install snapd
    snap install canonical-livepatch
    canonical-livepatch enable "$UBUNTU_LIVEPATCH_TOKEN"
    
    echo "✓ Ubuntu Livepatch enabled"
}

setup_canary_token() {
    log "Setting Up CanaryTokens Reboot Alert"
    
    if [[ "$ENABLE_CANARY_TOKEN" != "true" ]] || [[ -z "$CANARYTOKEN_URL" ]]; then
        echo "⚠ CanaryTokens not configured, skipping"
        return
    fi
    
    cat > /etc/cron.d/reboot_canary << EOF
@reboot $DEPLOY_USER curl -fsS --retry 3 --max-time 10 "$CANARYTOKEN_URL" > /dev/null 2>&1 || true
EOF
    
    chmod +x /etc/cron.d/reboot_canary
    
    echo "✓ CanaryTokens reboot alert configured"
}

setup_log_rotation() {
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
}

configure_lan_ip() {
    log "Configuring Binary Lane Private Network IP"
    
    if [[ -z "$LAN_IP" ]]; then
        echo "⚠ No LAN IP provided, skipping"
        return
    fi
    
    # Detect primary network interface
    local IFACE
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [[ -z "$IFACE" ]]; then
        echo "⚠ Could not detect network interface, using eth0"
        IFACE="eth0"
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
    netplan apply
    
    echo "✓ Private network IP configured: $LAN_IP on $IFACE"
}

verify_ssh_connectivity() {
    log "Verifying SSH Configuration"
    
    # Test SSHD config
    if ! sshd -t 2>/dev/null; then
        error "SSH configuration test failed! NOT rebooting to prevent lockout."
    fi
    echo "  ✓ SSH config valid"
    
    # Verify SSH is listening on the correct port
    if ss -tlnp | grep -q ":$SSH_PORT "; then
        echo "  ✓ SSH listening on port $SSH_PORT"
    else
        error "SSH not listening on port $SSH_PORT! Check configuration."
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
    if systemctl is-active --quiet sshd; then
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
        if systemctl is-active --quiet fail2ban; then
            echo "  ✓ fail2ban running"
        else
            echo "  ✗ fail2ban not running"
        fi
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        echo "  ✓ Docker installed"
        if groups "$DEPLOY_USER" | grep -q docker; then
            echo "  ✓ $DEPLOY_USER in docker group"
        fi
    fi
    
    # Check swap
    if swapon --show | grep -q '/swapfile'; then
        echo "  ✓ Swap active"
    fi
    
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
    clear
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Ubuntu VPS Provisioning Script for Kamal 2             ║
║   Optimized for Binary Lane VPS                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    
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
