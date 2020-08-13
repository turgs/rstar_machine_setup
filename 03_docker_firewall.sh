#! /bin/bash
# 03_docker_firewall.sh

# contigure docker to work with UFW
# https://github.com/chaifeng/ufw-docker#solving-ufw-and-docker-issues
####################################################################
sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
chmod +x /usr/local/bin/ufw-docker
ufw-docker install
sudo systemctl restart ufw
