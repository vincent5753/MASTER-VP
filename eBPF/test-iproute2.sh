#!/bin/bash

versionlist="iproute2-versionlist"
sweethome="/home/vp/"
resultfile="/home/vp/iproute2-result"
veth="veth25e7ae2"

while IFS= read -r iproute2file; do
    echo "file: ${iproute2file}"
    iproute2version=$(echo "$iproute2file" | awk -F ".tar" '{print $1}')
    echo "version: ${iproute2version}"
#    wget "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/${iproute2file}"
#    tar xvJf "${iproute2file}"
    cd "${iproute2version}"
    # 啟用 libbpf 的支援
#    ./configure --libbpf_force on
#    make clean
#    make
#    statuscode=$?
#    if [ $statuscode -ne 0 ]; then
#      echo "看來編譯有啥搞砸了？"
#      echo "${iproute2version} MakeStatusCode: ${statuscode}"
#      echo "${iproute2version} MakeStatusCode: ${statuscode}" >> "${resultfile}"
#    fi
#    statuscode=$?
    sudo make install
    installstatuscode=$?
    if [ $installstatuscode -ne 0 ]; then
      echo "看來有東西裝不起來？"
      echo "${iproute2version} MakeInstallStatusCode: ${installstatuscode}"
      echo "${iproute2version} MakeInstallStatusCode: ${installstatuscode}" >> "${resultfile}"
#      continue
    fi
    pwd
    ip -V
#    read -p pause pause
    sleep 5
    sudo tc filter add dev "${veth}" ingress bpf da obj ~/mapfromiproute2.o sec ingress
    tcstatuscode=$?
    if [ $tcstatuscode -ne 0 ]; then
      echo "看來有東西裝不起來？"
      echo "${iproute2version} tcMountStatusCode: ${tcstatuscode}"
      echo "${iproute2version} tcMountStatusCode: ${tcstatuscode} iproute2: $(ip -V)" >> "${resultfile}"
 #     continue
    fi
    sleep 10
    cd "${sweethome}"
    echo "<----- 窩是分隔線 ----->"
done < "$versionlist"

#sudo apt install -y clang libmnl-dev bison flex pkg-config
#wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-6.8.0.tar.xz
#tar xvJf iproute2-6.8.0.tar.xz
#cd iproute2-6.8.0
#./configure --libbpf_force on --prefix=/usr --color always
#make
#sudo make install
