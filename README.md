# rstar_machine_setup

**Ubuntu VPS Provisioning for Kamal 2 Deployments**

Automated, non-interactive script to provision Binary Lane (or any) Ubuntu VPS for production Ruby on Rails deployments using Kamal 2.

---

## 🚀 Quick Start

### One-Liner Deployment (Binary Lane auto-adds SSH key)

```bash
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh)
```

### Or with explicit SSH key

```bash
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh) \
  --ssh-key="$(cat ~/.ssh/id_ed25519.pub)"
```

### Or use SSH key from your Gist

Add your SSH public key to your fail2ban whitelist Gist (any line starting with `ssh-`), then:

```bash
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh) \
  --fail2ban-whitelist-url="https://gist.githubusercontent.com/YOUR_USER/YOUR_GIST_ID/raw/"
```

That's it! Your server will be fully configured and reboot automatically.

---

## 📋 What Gets Configured

### Security
- ✅ **SSH Hardening**
  - Custom port 33003 (configurable)
  - Root: Password auth enabled (emergency access)
  - Deploy user: Keys-only authentication
  - Connection keep-alive configured

- ✅ **fail2ban Protection**
  - 24-hour bans (progressive for repeat offenders)
  - 5 retry attempts allowed
  - Dynamic IP whitelist via GitHub Gist
  - Auto-updates hourly

- ✅ **UFW Firewall**
  - Ports 33003 (SSH), 80 (HTTP), 443 (HTTPS)
  - Default deny incoming
  - Default allow outgoing

- ✅ **Automatic Security Updates**
  - Unattended upgrades enabled
  - Auto-reboot disabled (Kamal-friendly)

### System
- ✅ **Deploy User**
  - Created with docker group access
  - SSH key-based authentication
  - Sudo access (password protected)

- ✅ **Docker**
  - Latest version installed
  - Deploy user can run docker without sudo
  - Log rotation configured (10MB max, 3 files)

- ✅ **Swap**
  - 2GB by default (configurable)
  - Optimized for containers (swappiness=10)

- ✅ **System Tuning**
  - Timezone set to UTC
  - File watches increased for Docker
  - sysctl optimized for containerized apps

---

## 📖 Usage

### Method 1: Zero Config (Provider SSH Key)

```bash
# Binary Lane auto-adds your SSH key, so just run:
ssh root@YOUR_SERVER_IP
curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh > provision_vps.sh
bash provision_vps.sh
```

### Method 2: Custom SSH Key

```bash
bash provision_vps.sh \
  --ssh-key="ssh-ed25519 AAAA..." \
  --ssh-port=33003 \
  --swap-size=4G
```

### Method 3: SSH Key from Gist

```bash
# Add SSH key to your Gist (line starting with ssh-), then:
bash provision_vps.sh \
  --fail2ban-whitelist-url="https://gist.githubusercontent.com/turgs/.../raw/"
```

### Method 4: Environment Variables

```bash
export SSH_PUBLIC_KEY="ssh-ed25519 AAAA..."
export SSH_PORT=33003
export SWAP_SIZE=4G

bash provision_vps.sh
```

### Method 5: Remote Execution (One-Liner - See Full Output Locally!)

```bash
# Zero config (uses provider key)
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh)

# With custom key
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh) \
  --ssh-key="$(cat ~/.ssh/id_ed25519.pub)"

# Full output streams to your local terminal in real-time!
```

---

## 🔧 Configuration Options

### All Options Are Optional!

The script works with zero arguments (uses provider SSH keys).

### Common Options
- `--ssh-key=KEY` - SSH public key for deploy user
  - **If omitted:** Checks Gist (first `ssh-*` line) → Uses provider key (Binary Lane) → Copies from root
- `--ssh-port=PORT` - SSH port (default: `33003`)
- `--deploy-user=USER` - Deploy username (default: `deploy`)
- `--swap-size=SIZE` - Swap size: 2G, 4G, 8G (default: `2G`)
- `--fail2ban-whitelist-url=URL` - Gist URL for IP whitelist (default: turgs' Gist)
- `--canary-url=URL` - CanaryTokens URL for reboot alerts
- `--livepatch-token=TOKEN` - Ubuntu Livepatch token
- `--lan-ip=IP` - Binary Lane private network IP
- `--no-fail2ban` - Disable fail2ban installation
- `--no-reboot` - Skip automatic reboot (manual reboot required)
- `--help`, `-h` - Show help message

### Environment Variables (CLI args take priority)

All options can be set via environment variables:
```bash
SSH_PUBLIC_KEY           # Optional - see SSH key sources above
SSH_PORT
DEPLOY_USER
SWAP_SIZE
FAIL2BAN_WHITELIST_URL
CANARYTOKEN_URL
UBUNTU_LIVEPATCH_TOKEN
LAN_IP
ENABLE_FAIL2BAN
AUTO_REBOOT              # Set to "false" to skip auto-reboot
```

---

## 🔐 Dynamic IP Whitelist

The script uses a **private GitHub Gist** to maintain a dynamic IP whitelist that updates hourly on all servers.

### Your Gist
https://gist.github.com/turgs/6d471a01fa901146c0ed9e2138f7c902

**Current Content:**
```txt
167.179.190.211 # Tim's AussieBB dynamic IP. Nov 23, 2025
```

### Format
One IP per line (optional: add SSH key on any line starting with `ssh-`):
```txt
167.179.190.200                          # Tim's home dynamic IP
101.234.56.89                            # Office - Static IP
192.168.1.0/24                           # Office LAN
172.22.108.48                            # waiter-shallow.bnr.la
150.107.75.244                           # Production server
ssh-ed25519 AAAAC3Nza...your-key-here   # Optional: SSH key for deploy user
```

**Pro Tip:** Add your SSH public key to the Gist! The script will automatically use it if you don't pass `--ssh-key` flag.

### How It Works
1. Script fetches Gist every hour via cron
2. Updates `/etc/fail2ban/ip_whitelist.conf`
3. Reloads fail2ban automatically
4. No server restart needed

### Updating IPs
1. **Edit your Gist** on GitHub
2. **Save** - Changes propagate within 1 hour
3. **Emergency update:** SSH to server and run:
   ```bash
   sudo /etc/fail2ban/scripts/update_whitelist.sh
   ```

### Testing
```bash
# View current whitelist
cat /etc/fail2ban/ip_whitelist.conf

# Check fail2ban status
sudo fail2ban-client status sshd

# View ban log
sudo journalctl -u fail2ban -f
```

---

## 🎯 Kamal 2 Integration

### Configure Kamal for Custom SSH Port

Edit `.kamal/deploy.yml`:

```yaml
ssh:
  port: 33003
  user: deploy

servers:
  web:
    - YOUR_SERVER_IP
```

### Test Connection

```bash
# SSH as deploy user (production)
ssh -p 33003 deploy@YOUR_SERVER_IP

# Test Docker (should work without sudo)
docker ps

# Test sudo (will prompt for password)
sudo ufw status
```

### Deploy with Kamal

```bash
# Setup (first time)
kamal setup

# Deploy
kamal deploy

# Check status
kamal app logs
```

---

## 📊 After Provisioning

### What You'll Get

1. **SSH Access Updated**
   - Port changed to 33003
   - Root: Password + keys (emergency)
   - Deploy: Keys only (production)

2. **Credentials Output**
   - Deploy user password (save for sudo)
   - Connection details

3. **Server Reboots**
   - Automatic reboot after provisioning
   - Wait 2 minutes before reconnecting

### Verification Checklist

```bash
# Connect to server
ssh -p 33003 deploy@YOUR_SERVER_IP

# ✓ Check Docker works without sudo
docker ps

# ✓ Check firewall
sudo ufw status

# ✓ Check fail2ban
sudo fail2ban-client status

# ✓ Check whitelist
cat /etc/fail2ban/ip_whitelist.conf

# ✓ Check swap
swapon --show

# ✓ View provisioning log
sudo journalctl -xe
```

---

## ��️ Security Features

### Hybrid SSH Authentication
- **Root user:** Password + key auth enabled
  - Binary Lane provides 8-char random password
  - Emergency access if SSH keys lost
  - Still protected by fail2ban

- **Deploy user:** Keys-only
  - No password authentication
  - Production-secure
  - Used for Kamal deployments

### fail2ban Configuration
- **Ban time:** 24 hours (not 1h or 30d)
  - Long enough to stop persistent bots
  - Short enough for legitimate recovery
- **Max retries:** 5 (allows typos)
- **Progressive bans:** Repeat offenders get longer bans
- **Dynamic whitelist:** Your IPs never banned

### Firewall Rules
- **Port 33003:** SSH (custom port reduces bot noise by ~95%)
- **Port 80:** HTTP (for Kamal proxy)
- **Port 443:** HTTPS (for Kamal proxy)
- **Default:** Deny all other incoming

---

## 🔧 Maintenance

### Update Your IP Whitelist
Edit Gist: https://gist.github.com/turgs/6d471a01fa901146c0ed9e2138f7c902

### Force Whitelist Update
```bash
sudo /etc/fail2ban/scripts/update_whitelist.sh
```

### Check fail2ban Bans
```bash
# View banned IPs
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client set sshd unbanip 1.2.3.4
```

### View Logs
```bash
# fail2ban activity
sudo tail -f /var/log/fail2ban.log

# Whitelist updates
sudo journalctl -t fail2ban-whitelist

# SSH authentication attempts
sudo tail -f /var/log/auth.log

# UFW firewall blocks
sudo tail -f /var/log/ufw.log
```

### Manual Security Updates
```bash
sudo apt update && sudo apt upgrade -y
```

---

## 🐛 Troubleshooting

### Can't SSH After Provisioning

**Problem:** Connection refused or timeout

**Solutions:**
1. **Wait 2 minutes** - Server is rebooting
2. **Check port:** Use `-p 33003` not default port 22
3. **Emergency access:** Use Binary Lane console as root with password

```bash
# Correct command
ssh -p 33003 deploy@YOUR_SERVER_IP

# Not this
ssh deploy@YOUR_SERVER_IP  # ❌ Wrong port
```

### Locked Out of Server

**Solution:** Use Binary Lane web console
1. Login to Binary Lane dashboard
2. Open VPS console (browser-based)
3. Login as `root` with Binary Lane password
4. Check `/var/log/auth.log` for SSH issues
5. Temporarily disable fail2ban: `systemctl stop fail2ban`

### fail2ban Banned My IP

**Immediate Fix:**
```bash
# Via Binary Lane console (login as root)
fail2ban-client set sshd unbanip YOUR_IP

# Or disable temporarily
systemctl stop fail2ban
```

**Permanent Fix:**
Add your IP to Gist: https://gist.github.com/turgs/6d471a01fa901146c0ed9e2138f7c902

### Docker Permission Denied

**Problem:** `docker ps` says permission denied

**Solution:** Deploy user needs to logout/login for group changes to take effect
```bash
# Logout and login again
exit
ssh -p 33003 deploy@YOUR_SERVER_IP

# Or reboot server
sudo reboot

# Or temporarily
newgrp docker
```

### Whitelist Not Updating

**Check:**
```bash
# Is cron running?
sudo systemctl status cron

# Test manual update
sudo /etc/fail2ban/scripts/update_whitelist.sh

# Check logs
sudo journalctl -t fail2ban-whitelist

# Verify Gist URL accessible
curl -fsSL https://gist.githubusercontent.com/turgs/6d471a01fa901146c0ed9e2138f7c902/raw/
```

---

## 📂 Files Created

```
/etc/ssh/sshd_config.d/99-custom.conf          # SSH configuration
/etc/fail2ban/jail.local                       # fail2ban config
/etc/fail2ban/ip_whitelist.conf               # Dynamic IP whitelist
/etc/fail2ban/scripts/update_whitelist.sh     # Whitelist updater
/etc/default/fail2ban-whitelist                # Whitelist env vars
/etc/cron.d/fail2ban_whitelist                 # Hourly update cron
/etc/cron.d/reboot_canary                      # CanaryTokens alert (optional)
/etc/apt/apt.conf.d/50unattended-upgrades     # Auto-updates config
/etc/docker/daemon.json                        # Docker log rotation
/swapfile                                      # Swap file
```

---

## 🔄 Comparison with Old Scripts

### Old Setup (01_user_firewall_etc.sh + 02_docker_setup.sh)
- ❌ Interactive prompts (blocks automation)
- ❌ Required manual variable setting
- ❌ Two separate scripts
- ❌ Docker Swarm focused
- ❌ 30-day fail2ban bans
- ❌ Static IP whitelist in config
- ❌ Non-idempotent (can't re-run)

### New Setup (provision_vps.sh)
- ✅ Fully non-interactive
- ✅ CLI arguments + environment variables
- ✅ Single comprehensive script
- ✅ Kamal 2 optimized
- ✅ 24-hour fail2ban bans (progressive)
- ✅ Dynamic IP whitelist via Gist
- ✅ Idempotent (safe to re-run)
- ✅ Error handling and verification
- ✅ Detailed logging and output

---

## 🎓 Best Practices

### Before Provisioning
1. ✅ (Optional) Have your SSH public key ready or add to Gist
2. ✅ Update your IP in the Gist
3. ✅ Note the server IP address
4. ✅ Have Binary Lane console access ready (emergency)

### After Provisioning
1. ✅ Save the deploy user password (output at end)
2. ✅ Test SSH connection immediately
3. ✅ Test Docker: `docker ps`
4. ✅ Configure Kamal with port 33003
5. ✅ Add server IP to Gist whitelist (prevent self-ban)

### Ongoing Maintenance
1. ✅ Keep Gist updated with current IPs
2. ✅ Monitor fail2ban bans occasionally
3. ✅ Review security updates monthly
4. ✅ Test emergency root access periodically

---

## 📝 Notes

- **Port 33003** chosen to reduce automated bot attacks (~95% reduction in noise)
- **Root password auth** kept for Binary Lane emergency access (defense in depth)
- **24h fail2ban bans** are sweet spot between security and usability
- **Dynamic whitelist** means you can update IPs without SSH access
- **Kamal 2** fully supports custom SSH ports via config
- **Output streaming** - Full real-time output whether running locally or via SSH pipe
- **SSH key sources** - Script tries: CLI flag → Gist → Provider key → Root's key → Warns if none

---

## 🆘 Support

### Log Files
- SSH: `/var/log/auth.log`
- fail2ban: `/var/log/fail2ban.log`
- UFW: `/var/log/ufw.log`
- System: `journalctl -xe`

### Useful Commands
```bash
# Service status
systemctl status sshd fail2ban docker ufw

# Check ports
ss -tulpn | grep LISTEN

# Test SSH config
sshd -t

# View active firewall rules
ufw status verbose

# Check Docker
docker info
docker ps
```

---

## 📜 License

MIT License - Use freely for your projects

---

## 🙏 Credits

Built for Ruby on Rails deployments with Kamal 2 on Binary Lane VPS infrastructure.

**Author:** Tim Burgan (@turgs)  
**Date:** November 2025  
**Version:** 1.0
