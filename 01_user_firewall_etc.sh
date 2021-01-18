#! /bin/bash
# 01_server_setup.sh

#
# 
# INSTRUCTIONS
#
# - get this file on your machine:
#   curl https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/01_user_firewall_etc.sh > 01_user_firewall_etc.sh
#
# - On server, paste this into a new nano file. 
# - Save as 01_user_firewall_etc.sh
# Set variables:
#   USER_PASSWORD=changeme
#   CANARYTOKEN_URL=changeme
#   SWAP_SIZE=2G
#   SSH_PORT=22
#   ENCRYPTED_PRIVATE=N
#   LAN_IP=192.168.0.1
# Run it: /bin/bash ./01_user_firewall_etc.sh

echo 'Checking variables...'

# What PASSWORD for new 'deploy' user?
echo " * USER_PASSWORD... ${USER_PASSWORD}"
if [[ -z "${USER_PASSWORD}" ]]; then
  echo -e "      Exiting.\n\n"
  exit
else
  echo "      Good. ( $USER_PASSWORD )"
fi

# Enter new CanaryTokens.com image URL to be triggered on server reboot:
echo ' * CANARYTOKEN_URL'
if [[ -z "${CANARYTOKEN_URL}" ]]; then
  echo -e "      Exiting.\n\n"
  exit
else
  echo "      Good. ( $CANARYTOKEN_URL )"
fi

# Ubuntu Livepatch: ubuntu.com/advantage
# To attach a machine:  sudo ua attach [TOKEN]
# To check status:      sudo ua status
echo ' * UBUNTU_LIVEPATCH_TOKEN (Leave blank to skip)'
if [[ -z "${UBUNTU_LIVEPATCH_TOKEN}" ]]; then
  echo -e "      Skipped.\n\n"
else
  echo "      Good. ( $UBUNTU_LIVEPATCH_TOKEN )"
fi


# What SWAP size (default 2G)?:
echo ' * SWAP_SIZE (default 2G)'
if [[ -z "${SWAP_SIZE}" ]]; then
  SWAP_SIZE=2G
  echo "      Using default. ( $SWAP_SIZE )"
else
  echo "      Good. ( $SWAP_SIZE )"
fi

# What SSH port (default 33003)?:
echo ' * SSH_PORT (default 33003)'
if [[ -z "${SSH_PORT}" ]]; then
  SSH_PORT=33003
  echo "      Using default. ( $SSH_PORT )"
else
  echo "      Good. ( $SSH_PORT )"
fi

# Create encrypted private directory
echo ' * ENCRYPTED_PRIVATE (default N)'
if [[ -z "${ENCRYPTED_PRIVATE}" ]]; then
  ENCRYPTED_PRIVATE=N
  echo "      Using default. ( $ENCRYPTED_PRIVATE )"
else
  echo "      Good. ( $ENCRYPTED_PRIVATE )"
fi
echo ""
echo "---------------------------------------------------"

echo ' * Set LAN_IP (default NO)'
if [[ -z "${LAN_IP}" ]]; then
  echo "      Using default. ( NO )"
else
  echo "      Good. ( $LAN_IP )"
fi
echo ""
echo "---------------------------------------------------"




BACK_TO_CWD=$(pwd)

echo ''
echo ''
echo ''
echo ''
echo ''


echo ""
echo ""
echo "-----------------"
echo "UPDATES AND UPGRADES"
echo ""

# updates
export DEBIAN_FRONTEND=noninteractive
apt-get -yq update
apt-get -yq --with-new-pkgs upgrade
apt-get -yq autoremove


echo ""
echo ""
echo "-----------------"
echo "UBUNTU ADVANTAGE LIVEPATCH"
echo ""

if [[ ! -z "$UBUNTU_LIVEPATCH_TOKEN" ]]; then
  sudo apt-get -y install snapd
  sudo snap install canonical-livepatch
  sudo canonical-livepatch enable $UBUNTU_LIVEPATCH_TOKEN
  sudo ua status
fi



echo ""
echo ""
echo "-----------------"
echo "UNATTENDED UPGRADES"
echo ""


# add unattended upgrades for security patches
# config located at: /etc/apt/apt.conf.d/50unattended-upgrades
apt-get -y install unattended-upgrades

# allow reboot at night
cat << EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "16:00"; // 2am Brisbane.
// Acquire::http::Dl-Limit "70"; // limits the download speed to 70kb/sec
EOF

cat << EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF



echo ""
echo ""
echo "-----------------"
echo "SET TIMEZONE TO UTC"
echo ""


# set timezone of server to be UTC
timedatectl set-timezone UTC


echo ""
echo ""
echo "-----------------"
echo "SET FIREWALL"
echo ""


# set firewall
apt-get -y install ufw
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT
sudo ufw allow 443
sudo ufw allow 80
# log to own file /var/log/ufw.log, not /var/log/syslog, then restart rsyslog
sudo sh -c 'echo "& stop" >> /etc/rsyslog.d/20-ufw.conf'
sudo /etc/init.d/rsyslog restart



echo ""
echo ""
echo "-----------------"
echo "CHANGE SSH PORT TO $SSH_PORT"
echo ""


# change SSH port
sed -i -- "s/Port 22/Port $SSH_PORT/g" /etc/ssh/sshd_config
sed -i -- "s/#Port $SSH_PORT/Port $SSH_PORT/g" /etc/ssh/sshd_config
sudo systemctl restart sshd


cat << EOF > /etc/ssh/ssh_config
Include /etc/ssh/ssh_config.d/*.conf
Host *
  ServerAliveInterval 240
  ServerAliveCountMax 2
  StrictHostKeyChecking no
  UserKnownHostsFile=/dev/null
LogLevel ERROR
EOF



echo ""
echo ""
echo "-----------------"
echo "CREATING SWAP: $SWAP_SIZE"
echo ""

# create swap
fallocate -l $SWAP_SIZE /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
echo "vm.swappiness=5" >> /etc/sysctl.conf
echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
echo "vm.overcommit_memory=1" >> /etc/sysctl.conf # needed for redis



# enabling LAN IP
if [[ ! -z "$LAN_IP" ]]; then
  echo ""
  echo ""
  echo "-----------------"
  echo "ENABLING LAN_IP"
  echo ""

  IFS=. read LAN_IP1 LAN_IP2 LAN_IP3 LAN_IP4 <<< "$LAN_IP"
  cat << EOF >> /etc/network/interfaces

# Enabling LAN IP for Binary Lane: $LAN_IP
auto eth0:0
iface eth0:0 inet static
address $LAN_IP
netmask 255.255.0.0
# gateway $LAN_IP1.$LAN_IP2.$LAN_IP3.1
EOF
  systemctl restart NetworkManager
fi



echo ""
echo ""
echo "-----------------"
echo "CREATING USER 'deploy'"
echo ""


# create 'deploy' user
# ---------------------
useradd -m deploy -s /bin/bash
## >> add a password from grc.com/passwords
#passwd deploy
echo "deploy:$USER_PASSWORD" | chpasswd
# add user to sudoers
usermod -aG sudo deploy




echo ""
echo ""
echo "-----------------"
echo "ADD CANARY-TOKEN TO REBOOT CRON"
echo ""

# edit crontab to ping on restart
# -- get a new one from canarytokens.org
echo "@reboot deploy curl -fsS --retry 3 $CANARYTOKEN_URL > /dev/null" >> /etc/cron.d/reboot_canary
sudo sh -c 'chmod +x /etc/cron.d/reboot_canary'





echo ""
echo ""
echo "-----------------"
echo "FAIL2BAN"
echo ""

# fail2ban
apt-get -yq install fail2ban

# create local config
####################################################################
cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
# ignorecommand =
# ban for 30 days
bantime = 2592000
# if within a 10 minute period
findtime = 600
# if within a 10 minute period
maxretry = 3

[sshd]
enabled = true
port    = $SSH_PORT
logpath = %(sshd_log)s

[sshd-ddos]
enabled = true
port    = $SSH_PORT
logpath = %(sshd_log)s

EOF
####################################################################

service fail2ban restart




if [[ $ENCRYPTED_PRIVATE == 'Y' ]]; then
  clear

  echo ""
  echo ""
  echo "-----------------"
  echo "CREATE ENCRYPTED VOLUME"
  echo ""
  echo "This will asked first for your login password for 'deploy' user, enter your log in password."
  echo ""
  echo 'You will next be asked to "Enter your mount passphrase [leave blank to generate one]",'
  echo "leave this blank (hit the enter key) and a random passphrase will be generated."
  echo ""
  echo "That is all there is to it. "
  echo ''
  read -n1 -r -p "Press any key to continue..." key
  echo ''

  # Create encrypted ecryptfs directory
  # http://bodhizazen.net/Tutorials/Ecryptfs/#Private

  # Alternative with dm-luks
  # # https://www.digitalocean.com/community/tutorials/how-to-use-dm-crypt-to-create-an-encrypted-volume-on-an-ubuntu-vps
  # # https://geekpeek.net/disk-encryption-on-centos-linux/


  # Install ecryptfs:
  sudo apt-get -y install ecryptfs-utils
  clear
  sudo -u deploy -H sh -c 'ecryptfs-setup-private -u deploy'
  # This will asked first for your login password, enter your log in password.
  # You will next be asked to "Enter your mount passphrase [leave blank to generate one]",
  # leave this blank (hit the enter key) and a random passphrase will be generated.
  # That is all there is to it.
  # Any data you place in ~/Private will be encrypted in ~/.Private when you log off.
  # Backup passphrase somewhere In case I ever need to manually mount:
  echo ''
  echo ''
  echo ''
  clear
  echo "Here's your 'backup passphrase' for ecryptfs. You'll need to enter the 'deploy' user's passphrase to see it:"
  echo ''
  sudo -u deploy -H sh -c 'ecryptfs-unwrap-passphrase ~/.ecryptfs/wrapped-passphrase'
  echo ''
  read -n1 -r -p "Copy that to lastpass. Press any key to continue..." key
  echo ''


  # Disable automatic unmounting
  # sudo -u deploy -H sh -c 'rm ~/.ecryptfs/auto-umount'
  cd ~


  # manually mount now
  # sudo mount -t ecryptfs /home/deploy/.Private /home/deploy/Private
fi




echo fs.inotify.max_user_watches=10000000 | sudo tee -a /etc/sysctl.conf
sysctl -p




echo 'user_allow_other' > /etc/fuse.conf



echo ""
echo ""
echo "-----------------"
echo "DONE. TAKE A IMAGE BACKUP NOW."
echo ""

read -n1 -r -p "1. Have you taken a full-disk image backup now?  Press any key to confirm..." key
echo ''
read -n1 -r -p "2. Have you added a script to the control server now?  Press any key to confirm..." key
echo ''


read -p "Ok if we reboot now? (Y or N)"$'\n' REBOOT
if [[ $REBOOT == 'Y' ]]; then
  echo -e "Rebooting.\n\n"
  reboot
else
  echo -e "Finished.\n\n\n\n\n"
fi
