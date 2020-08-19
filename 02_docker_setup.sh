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
sudo ufw allow from any to any proto esp # Protocol 50 (ESP) if you plan on using overlay network with the encryption option
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



echo ""
echo "-------------"
echo "TRAEFIC_ACME.md"
sudo touch /etc/traefik_acme.json
sudo chmod 600 /etc/traefik_acme.json


echo ""
echo "--------------"
echo "DEPLOY DOCKER SECRETS"

docker secret remove postgres_password
docker secret remove rails_secret_key_base
docker secret remove rails_secret_token
docker secret remove api_key_bugsnag
docker secret remove api_key_postmark
docker secret remove api_key_skylight
docker secret remove api_key_papertrail_host
docker secret remove api_key_papertrail_port
docker secret remove postgres_password.v20200417a
docker secret remove rails_secret_key_base.v20200417a
docker secret remove rails_secret_token.v20200417a
docker secret remove api_key_bugsnag.v20200417a
docker secret remove api_key_postmark.v20200417a
docker secret remove api_key_skylight.v20200417a
docker secret remove api_key_papertrail_host.v20200417a
docker secret remove api_key_papertrail_port.v20200417a
echo "${{ secrets.DEPLOY_POSTGRES_PASSWORD }}"       | docker secret create postgres_password.v20200417a -
echo "${{ secrets.DEPLOY_RAILS_SECRET_KEY_BASE }}"   | docker secret create rails_secret_key_base.v20200417a -
echo "${{ secrets.DEPLOY_RAILS_SECRET_TOKEN }}"      | docker secret create rails_secret_token.v20200417a -
echo "${{ secrets.DEPLOY_API_KEY_BUGSNAG }}"         | docker secret create api_key_bugsnag.v20200417a -
echo "${{ secrets.DEPLOY_API_KEY_POSTMARK }}"        | docker secret create api_key_postmark.v20200417a -
echo "${{ secrets.DEPLOY_API_KEY_SKYLIGHT }}"        | docker secret create api_key_skylight.v20200417a -
echo "${{ secrets.DEPLOY_API_KEY_PAPERTRAIL_HOST }}" | docker secret create api_key_papertrail_host.v20200417a -
echo "${{ secrets.DEPLOY_API_KEY_PAPERTRAIL_PORT }}" | docker secret create api_key_papertrail_port.v20200417a -





echo ""
echo "--------------"
echo "DAILY CRON DOCKER PRUNE"

sudo sh -c 'echo "7 14 * * * root docker docker system prune -f" >> /etc/cron.d/docker_system_prune'
sudo sh -c 'chmod +x /etc/cron.d/docker_system_prune'
