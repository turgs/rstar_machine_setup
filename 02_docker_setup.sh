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
echo "DOCKER"
echo ""

sudo apt-get -y install curl apt-transport-https ca-certificates software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add 
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
sudo apt-get -y udpate
sudo apt -get -y install docker-ce docker-ce-cli containerd.io
docker --version

# Allow user to not need sudo to run docker commands
#sudo usermod -aG docker deploy



if [[ ! -z "$JOIN_COMMAND" ]]; then
    echo ""
    echo "-----------------"
    echo "JOINING SWARM"
    echo ""
    $JOIN_COMMAND
else
    echo ""
    echo "-----------------"
    echo "CREATING SWARM"
    echo ""
    LAN_IP=sudo grep '# Enabling LAN IP for Binary Lane: ' /etc/network/interfaces | seb 's/# Enabling LAN IP for Binary Lane: //`
    docker swarm init --advertise-addr $LAN_IP
fi


# contigure docker to work with UFW
# https://github.com/chaifeng/ufw-docker#solving-ufw-and-docker-issues
####################################################################
sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
chmod +x /usr/local/bin/ufw-docker
ufw-docker install

