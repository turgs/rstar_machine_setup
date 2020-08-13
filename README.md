# rstar_machine_setup

Pull the file onto the new server:

```
curl https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/01_user_firewall_etc.sh > 01_user_firewall_etc.sh
```
Set variables:

```
export USER_PASSWORD=changeme
export CANARYTOKEN_URL=changeme
export LAN_IP=changeme
export UBUNTU_LIVEPATCH_TOKEN=changeme
```

And, optionally:

```
export SWAP_SIZE=2G
export SSH_PORT=22
export ENCRYPTED_PRIVATE=Y
```

Run it:

```
/bin/bash ./01_user_firewall_etc.sh
```
