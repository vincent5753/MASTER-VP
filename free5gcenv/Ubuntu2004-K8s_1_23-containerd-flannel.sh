#!/bin/bash
# Verified by VP@22.04.03 02:45:44(+8) ( also playing Elden Ring :) )

# Install basic packages
#sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

# Add Docker office gpg key
#curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
#echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list

# Install Docker From Docker Official

# Install k8s packages
version=1.23.17-00
echo $version
apt-cache show kubectl | grep "Version: $version"
sudo apt install -y kubelet=$version kubectl=$version kubeadm=$version
sudo apt-mark hold kubelet kubeadm kubectl

# Pull Image
sudo docker pull k8s.gcr.io/kube-apiserver-amd64:v1.23.17
sudo docker pull k8s.gcr.io/kube-controller-manager-amd64:v1.23.17
sudo docker pull k8s.gcr.io/kube-scheduler-amd64:v1.23.17
sudo docker pull k8s.gcr.io/kube-proxy-amd64:v1.23.17
sudo docker pull k8s.gcr.io/pause:3.6
sudo docker pull k8s.gcr.io/etcd:3.5.1-0
sudo docker pull k8s.gcr.io/coredns/coredns:v1.8.6

# Essential Tweaks
cat << EOF | sudo tee /etc/modules-load.d/containerd.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter

# Disable swap
source <(kubectl completion bash)
echo "source <(kubectl completion bash)" >> ~/.bashrc

# Init cluster
## For Master Node

sudo kubeadm init --service-cidr=10.96.0.0/12 --pod-network-cidr=10.244.0.0/16 --v=6
### Copy Config
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

### Flannel CNI
kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml

### Waiting until Ready
kubectl cluster-info
watch -n 1 kubectl get nodes -o wide

### Taint(if needed)
kubectl taint nodes --all node-role.kubernetes.io/master-
