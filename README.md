# rstar_machine_setup

### 01 Initial Setup

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
sudo reboot
```

### 02 Adding to Docker Swarm, or creating new

ull the file onto the new server:

```
curl https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/02_docker_setup.sh > 02_docker_setup.sh
```
Set variables:

```
export JOIN_COMMAND=changeme
```

Run it:

```
/bin/bash ./02_docker_setup.sh
```
