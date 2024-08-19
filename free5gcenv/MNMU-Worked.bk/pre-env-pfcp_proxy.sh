#!/bin/bash

sudo apt update
sudo apt install -y python3-pip
pip3 install scapy paho-mqtt

which kubeadm
if [ "$?" -ne "0" ]; then
  echo "你沒有 kubenetes 環境"
  curl https://raw.githubusercontent.com/vincent5753/KAIS/main/legacy/Ubuntu2004-K8s_1_23-dockershim-flannel.sh | bash
else
  cd "${curpath}"
  echo "OK，你有 kubenetes 環境"
  curl https://raw.githubusercontent.com/vincent5753/KAIS/main/nemesis.sh | bash
  curl https://raw.githubusercontent.com/vincent5753/KAIS/main/legacy/Ubuntu2004-K8s_1_23-dockershim-flannel.sh | bash
fi
