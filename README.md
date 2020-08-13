# rstar_machine_setup

### 01 Initial Setup

Pull the file onto the new server:

```
curl https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/01_user_firewall_etc.sh > /tmp/01_user_firewall_etc.sh
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
bash /tmp/01_user_firewall_etc.sh
sudo reboot
```

### 02 Adding to Docker Swarm, or creating new

Pull the file onto the new server:

```
curl https://raw.githubusercontent.com/turgs/rstar_machine_setup/master/02_docker_setup.sh > /tmp/02_docker_setup.sh
```
optional variable if joining an existing swarm:

```
export JOIN_COMMAND=changeme
```

Run it:

```
sudo bash /tmp/02_docker_setup.sh
```

03 Back on the manager machine

```
ssh ...
docker service ls
docker node ls
```
