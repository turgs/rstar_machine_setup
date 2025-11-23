# Example Script Output

This shows what you'll see when running the script (same output whether on server or via SSH pipe).

## Running via SSH Pipe (Remote Execution)

```bash
$ ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/provision_vps.sh)

==========================================
Validating Inputs
==========================================

⚠ No SSH key provided - will check Gist or use provider key
✓ SSH port: 33003
✓ Deploy user: deploy

==========================================
Updating System Packages
==========================================

Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]
...
✓ System updated

==========================================
Configuring Timezone
==========================================

✓ Timezone set to UTC

==========================================
Creating Deploy User: deploy
==========================================

✓ User deploy created
✓ Generated strong password for deploy
✓ Deploy user configured
  Password: X9mK2pLq4rT8 (save this for emergency sudo access)

==========================================
Setting Up SSH Keys
==========================================

  No SSH key provided, checking Gist...
  ✓ Found SSH key in Gist
✓ Added SSH key to root
✓ Added SSH key to deploy
✓ SSH keys configured

==========================================
Configuring SSH
==========================================

✓ SSH configured
  Port: 33003
  Root: Password + keys enabled
  Deploy: Keys-only

==========================================
Configuring UFW Firewall
==========================================

✓ UFW configured
  SSH (33003), HTTP (80), HTTPS (443) allowed

==========================================
Configuring fail2ban
==========================================

  Creating dynamic IP whitelist updater...
  Whitelisted IPs: 3
✓ fail2ban configured
  Bantime: 24 hours
  Max retries: 5

==========================================
Configuring Unattended Upgrades
==========================================

✓ Unattended upgrades enabled
  Auto-reboot: disabled (Kamal-friendly)

==========================================
Creating Swap: 2G
==========================================

✓ Swap created: 2G

==========================================
Installing Docker
==========================================

✓ Docker installed
  User deploy added to docker group

==========================================
Configuring System Parameters
==========================================

✓ System parameters configured

==========================================
Configuring Log Rotation
==========================================

✓ Log rotation configured

==========================================
Verifying Setup
==========================================

✓ Docker service running
✓ UFW firewall active
✓ fail2ban service running
✓ Swap active: 2G

==========================================
Verifying SSH Configuration
==========================================

  ✓ SSH config valid
  ✓ SSH listening on port 33003
  ✓ SSH keys have correct permissions
  ✓ SSH authorized_keys exists (1 key(s) found)

✓ SSH connectivity verified - safe to reboot

==========================================
                  SUMMARY
==========================================

✅ VPS PROVISIONING COMPLETE!

═══════════════════════════════════════════════════════════

SERVER DETAILS:
  Hostname: your-server
  OS: Ubuntu 24.04 LTS
  Timezone: UTC
  Swap: 2G

USERS:
  Root:
    - Password: <Binary Lane provided>
    - SSH Auth: Password + Keys
    - SSH Port: 33003

  Deploy (deploy):
    - Password: X9mK2pLq4rT8
    - SSH Auth: Keys only
    - Docker: Enabled (no sudo needed)

SECURITY:
  ✓ UFW Firewall: Active (SSH: 33003, HTTP: 80, HTTPS: 443)
  ✓ fail2ban: Active (24h bans, 5 retries, dynamic whitelist)
  ✓ Unattended Upgrades: Enabled (no auto-reboot)
  ✓ SSH Hardening: Custom port, modern crypto only

DOCKER:
  ✓ Version: 24.0.7
  ✓ User deploy can run docker without sudo
  ✓ Log rotation: 10MB max, 3 files

OPTIONAL FEATURES:
  ⚠ Ubuntu Livepatch: Not configured
  ⚠ CanaryTokens: Not configured
  ⚠ LAN IP: Not configured

NEXT STEPS:
  1. Reboot the server to apply all changes (automatic)
  2. Wait 2 minutes for server to stabilize
  3. Test SSH connection: ssh -p 33003 deploy@<server-ip>
  4. Test Docker: docker ps (should work without sudo)
  5. Configure Kamal and deploy!

══════════════════════════════════════════════════════════

==========================================
Rebooting in 10 seconds...
==========================================

Press Ctrl+C to cancel
Connection to YOUR_SERVER_IP closed by remote host.
```

## Key Points

### ✅ Full Output Streaming
- **Every step** shows progress in real-time
- **Same output** whether running on server or via SSH pipe
- **Color-coded** messages (✓ ✅ ⚠ ❌)

### 🔐 SSH Key Priority
The script tries these in order:

1. **CLI flag:** `--ssh-key="ssh-ed25519 AAAA..."`
2. **Gist:** First line starting with `ssh-`
3. **Provider key:** Copies from root (Binary Lane auto-adds)
4. **Warning:** If none found, warns about lockout risk

### 📊 Summary Output
- Comprehensive at the end
- **SAVE THE DEPLOY PASSWORD** - shown clearly
- Connection details for Kamal
- Clear next steps

### 🚫 No Reboot Flag
Use `--no-reboot` to skip automatic reboot:

```bash
ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL ...) --no-reboot

# Output ends with:
⚠ Automatic reboot disabled. Please reboot manually to apply all changes:
  sudo reboot
```

## Example: SSH Key from Gist

Your Gist content:
```
167.179.190.211     # Tim's IP
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbC...xyz tim@laptop
```

Script output:
```
==========================================
Setting Up SSH Keys
==========================================

  No SSH key provided, checking Gist...
  ✓ Found SSH key in Gist
✓ Added SSH key to root
✓ Added SSH key to deploy
✓ SSH keys configured
```

## Example: Provider Key (Zero Config)

Binary Lane adds your key before you run script:

```bash
$ ssh root@YOUR_SERVER_IP 'bash -s' < <(curl -fsSL ...)

# Output shows:
==========================================
Setting Up SSH Keys
==========================================

  ⚠ No SSH key provided, copying from root (provider added)
  ✓ Copied SSH keys from root to deploy
```

## Example: No Key Found (Warning)

```
==========================================
Setting Up SSH Keys
==========================================

  ⚠ WARNING: No SSH key found!
  ⚠ You may lose access after reboot if provider didn't add keys
  ⚠ Consider using --no-reboot and adding keys manually

# Then at verification:
==========================================
Verifying SSH Configuration
==========================================

  ✓ SSH config valid
  ✓ SSH listening on port 33003
  ⚠ WARNING: No authorized_keys file found!
  ⚠ You may lose SSH access after reboot
ERROR: Cannot safely reboot without SSH keys. Use --no-reboot to continue anyway.
```

This prevents lockout! ✅
