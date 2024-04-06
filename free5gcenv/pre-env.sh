# k8s 1.24
curl https://raw.githubusercontent.com/vincent5753/KAIS/main/legacy/Ubuntu2004-K8s_1_24-containerd-flannel.sh | bash

# eBPF-related
sudo apt install -y clang llvm
sudo apt install -y libbpf-dev libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install -y linux-headers-$(uname -r) linux-tools-common linux-tools-generic linux-tools-$(uname -r)
sudo apt install -y clang libmnl-dev bison flex pkg-config

# upgrade and compile iproute2 to support BTF
wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.18.0.tar.xz
tar xvJf iproute2-5.18.0.tar.xz
cd iproute2-5.18.0
./configure --libbpf_force on --prefix=/usr --color always
make
sudo make install

# gtp5g
git clone https://github.com/free5gc/gtp5g.git
sudo apt install -y gcc make
cd gtp5g
make clean && sudo make
sudo make install
