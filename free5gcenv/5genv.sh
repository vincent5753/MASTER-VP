#!/bin/bash

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
end=$'\e[0m'

get_containerid(){
#  echo "[Func] get_containerid"
  echo "PodName: $1"
  ContainerID=$(kubectl describe po "$1" | grep "Container ID" | cut -d '/' -f 3)
  #echo "ContainerID: $ContainerID"
}

get_containerpid(){
#  echo "[Func] get_containerpid"
  ContainerPID=$(docker inspect --format '{{.State.Pid}}' "$ContainerID")
  #echo "ContainerPID: $ContainerPID"
}

get_containerifnum(){
#  echo "[Func] get_containerifnum"
  IfNum=$(sudo nsenter -t "$ContainerPID" -n ip addr | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
  #echo "IfNum: $IfNum"
}

get_vethname(){
#  echo "[Func] get_vethname"
  VethName=$(ip a | grep "${IfNum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
  #echo "VethName: $VethName"
}

printall(){
  echo "ContainerID: \"$ContainerID\""
  echo "ContainerPID: \"$ContainerPID\""
  echo "IfNum: \"$IfNum\""
  echo "VethName: \"$VethName\""
  echo ""
}

getpodinfobyprefix(){
  podstatusall=$(kubectl get po -o wide | grep "$1" )
  podname=$(echo ${podstatusall} | awk -F " " '{print $1}')
  podstatus=$(echo ${podstatusall} | awk -F " " '{print $3}')
  podip=$(echo ${podstatusall} | awk -F " " '{print $6}')
}

waituntilpodready(){
  while true
  do
    sleep 5
    getpodinfobyprefix "$1"
    if [ "${podstatus}" == "Running" ]
    then
     break
    fi
  done
}

read -p "${yel}[Preflightcheck]${end} 請確認運行的 Kubernetes 叢集是全新未部屬的，如果沒有問題請按 ENTER 繼續" pause


echo "${yel}[Cleanup]${end} 移除 mongoDB 先前資料"
sudo rm -rf "/mnt/mongo"
cd free5gc/
echo "${grn}[Deploy][5GC]${end} Deploying mongoDB"
kubectl apply -f 01-free5gc-mongodb.yaml

echo "${grn}[Deploy][Wait]${end} 等待 mongoDB 服務轉為 Running 狀態..."
waituntilpodready "free5gc-mongodb"

echo "${grn}[Deploy][5GC]${end} Deploying UPF"
kubectl apply -f 02-free5gc-upf.yaml
waituntilpodready "free5gc-upf"
get_containerid "${podname}"
get_containerpid
get_containerifnum
get_vethname
printall
echo "${yel}[Debug]${end} 我們先睡 30 秒，如果要監控 UPF 的 GTP-U 和 PFCP 現在快去開 tcpdump 監聽 veth"
echo "${yel}[Debug]${end} 參考指令: sudo tcpdump -v udp port 8805 or udp port 2152 -i ${VethName}"
sleep 30

# 取得 veth，在 smf 起來前要監聽 PFCP Association、Modification
# 之後送到 UPF 的 packet 要 rewrite IP 送到新長出來的 UPF

echo "${grn}[Deploy][5GC]${end} Deploying NRF"
kubectl apply -f 03-free5gc-nrf.yaml
echo "${grn}[Deploy][Wait]${end} 等待 NRF 服務轉為 Running 狀態..."
waituntilpodready "free5gc-nrf"

echo "${grn}[Deploy][5GC]${end} Deploying AMF"
kubectl apply -f 04-free5gc-amf.yaml
waituntilpodready "free5gc-amf"
echo "${grn}[Deploy][Wait]${end} 等待 AMF 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying SMF"
kubectl apply -f 05-free5gc-smf.yaml
waituntilpodready "free5gc-smf"
waituntilpodready "free5gc-smf"
get_containerid "${podname}"
get_containerpid
get_containerifnum
get_vethname
echo "${grn}[Deploy][Wait]${end} 等待 SMF 服務轉為 Running 狀態..."
echo "${red}[預計]${end} 之後 SMF 要 DROP 掉除了第一個 UPF 的 PFCP"
echo "$yel[Debug]${end} SMF Veth: ${VethName}"
# 在收到 Association Response 後要 Drop 掉除了第一個 UPF 的 PFCP

echo "${grn}[Deploy][5GC]${end} Deploying UDR"
kubectl apply -f 06-free5gc-udr.yaml
waituntilpodready "free5gc-udr"
echo "${grn}[Deploy][Wait]${end} 等待 UDR 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying PCF"
kubectl apply -f 07-free5gc-pcf.yaml
waituntilpodready "free5gc-pcf"
echo "${grn}[Deploy][Wait]${end} 等待 PCF 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying UDM"
kubectl apply -f 08-free5gc-udm.yaml
waituntilpodready "free5gc-udm"
echo "${grn}[Deploy][Wait]${end} 等待 UDM 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying NSSF"
kubectl apply -f 09-free5gc-nssf.yaml
waituntilpodready "free5gc-nssf"
echo "${grn}[Deploy][Wait]${end} 等待 NSSF 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying AUSF"
kubectl apply -f 10-free5gc-ausf.yaml
waituntilpodready "free5gc-ausf"
echo "${grn}[Deploy][Wait]${end} 等待 AUSF 服務轉為 Running 狀態..."

echo "${grn}[Deploy][5GC]${end} Deploying WEB-UI"
kubectl apply -f 11-free5gc-webui.yaml
waituntilpodready "free5gc-webui"
echo "${grn}[Deploy][Wait]${end} 等待 webui 服務轉為 Running 狀態..."

echo "${yel}[Debug]${end} 我們先睡 60 秒，快去 WEB-UI 註冊"
echo "${yel}[Debug]${end} 參考網址: $(hostname -I | awk -F " " '{print $1}'):31111"
sleep 60

echo "${grn}[Deploy][UERANSIM]${end} Deploying gnb"
kubectl apply -f ueransim/ueransim-gnb.yaml

echo "${grn}[Deploy][UERANSIM]${end} Deploying ue"
kubectl apply -f ueransim/ueransim-ue.yaml

waituntilpodready "ueransim-ue"
kubectl exec -it ${podname} -- ip a
