# rstar_machine_setup

Pull the file onto the new server:

```
wget -O 01_user_firewall_etc.sh https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/01_user_firewall_etc.sh
```
Set variables:

```
USER_PASSWORD=changeme
CANARYTOKEN_URL=changeme
LAN_IP=changeme
```

And, optionally:

```
SWAP_SIZE=2G
SSH_PORT=22
ENCRYPTED_PRIVATE=Y
```

Run it:

```
/bin/bash ./01_user_firewall_etc.sh
```
