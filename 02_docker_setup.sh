#! /bin/bash
# 02_docker_setup.sh

echo 'Checking variables...'


# Join existing swarm
echo ' * Join command (leave blank to create new'
if [[ -z "$JOIN_COMMAND" ]]; then
  echo "      New will be created"
else
  echo "      Good. ( $JOIN_COMMAND )"
fi



echo ""
echo "-----------------"
echo "ADD FIREWALL RULES FOR DOCKER SWARM"
echo ""

sudo ufw allow 2377/tcp # comms from worker nodes to manager in swarm
sudo ufw allow 7946     # comms among nodes for network discovery
sudo ufw allow 4789/udp # overlay network traffic
sudo ufw reload



echo ""
echo "-----------------"
echo "DOCKER"
echo ""

sudo apt-get -y install curl apt-transport-https ca-certificates software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add 
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
sudo apt-get -y update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io
docker --version

# Allow user to not need sudo to run docker commands
sudo usermod -aG docker deploy



if [[ ! -z "$JOIN_COMMAND" ]]; then
    echo ""
    echo "-----------------"
    echo "JOINING SWARM"
    echo ""
    sudo $JOIN_COMMAND
else
    echo ""
    echo "-----------------"
    echo "CREATING SWARM"
    echo ""
    LAN_IP=$(sudo grep '# Enabling LAN IP for Binary Lane: ' /etc/network/interfaces | sed 's/# Enabling LAN IP for Binary Lane: //')
    sudo docker swarm init --advertise-addr $LAN_IP
fi



