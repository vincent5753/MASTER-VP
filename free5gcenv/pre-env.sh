#!/bin/bash

curpath=$(pwd)
sudo apt-get update
sudo apt-get install -y jq clang llvm libbpf-dev libelf-dev libpcap-dev gcc-multilib build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic linux-tools-$(uname -r) libmnl-dev bison flex pkg-config dwarves python3-pip tcpreplay
# getpodveth dependency
#sudo apt install -y jq

# eBPF-related
#sudo apt install -y clang llvm
#sudo apt install -y libbpf-dev libelf-dev libpcap-dev gcc-multilib build-essential
#sudo apt install -y linux-headers-$(uname -r) linux-tools-common linux-tools-generic linux-tools-$(uname -r)
#sudo apt install -y libmnl-dev bison flex pkg-config dwarves

# Packet-related
#sudo apt install -y python3-pip tcpreplay
pip3 install scapy

# Just in case that if we forgot something
echo 0 | sudo tee /proc/sys/net/ipv4/conf/all/rp_filter

# upgrade and compile iproute2 to support BTF
if grep -q "libbpf" <<< $(ip -V)
then
  echo "OK，你有 libbpf"
else
  rm iproute2-5.18.0.tar.xz*
  wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.18.0.tar.xz
  tar xvJf iproute2-5.18.0.tar.xz
  cd iproute2-5.18.0
  ./configure --libbpf_force on --prefix=/usr --color always
  make
  sudo make install
fi

# gtp5g
if [ -e "/etc/modules-load.d/gtp5g.conf" ]
then
  echo "OK，你有 GTP-5G"
else
  git clone https://github.com/free5gc/gtp5g.git
  sudo apt install -y gcc make
  cd gtp5g
  make clean && sudo make
  sudo make install
  cat /etc/modules-load.d/gtp5g.conf
fi

# k8s 1.23
which kubeadm
if [ "$?" -ne "0" ]; then
  echo "你沒有 kubenetes 環境"
  curl https://raw.githubusercontent.com/vincent5753/KAIS/main/legacy/Ubuntu2004-K8s_1_23-dockershim-flannel.sh | bash
else
  cd "${curpath}"
  echo "OK，你有 kubenetes 環境"
  bash nemesis.sh
  bash Ubuntu2004-K8s_1_23-containerd-flannel.sh
fi
