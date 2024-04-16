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
  echo "ContainerID: \"${ContainerID}\""
  echo "ContainerPID: \"${ContainerPID}\""
  echo "IfNum: \"${IfNum}\""
  echo "VethName: \"${VethName}\""
#  echo ""
}

getpodinfobyprefix(){
  #echo "[Debug] podprefix \"$1\""
  podstatusall=$(kubectl get pod -o wide | grep "$1" )
  #echo "[Debug] podstatusall \"${podstatusall}\""
  podname=$(echo ${podstatusall} | awk -F " " '{print $1}')
  podstatus=$(echo ${podstatusall} | awk -F " " '{print $3}')
  podip=$(echo ${podstatusall} | awk -F " " '{print $6}')
  #echo "[Debug][getpodinfobyprefix] podname: \"${podname}\" podstatus: \"${podstatus}\" podip: \"${podip}\""
}

# getpodmacaddress "free5gc-mongodb"
getpodmacaddress(){
  #echo "[Debug] in getpodmacaddress"
  getpodinfobyprefix "$1"
  podmac=$(kubectl exec -it ${podname} -- cat /sys/class/net/eth0/address)
}

# getpodinfobyprefixnamespaced ${podname} ${namespace}
# getpodinfobyprefixnamespaced kube-flannel-ds kube-flannel
getpodinfobyprefixnamespaced(){
  #echo "[Debug] getpodinfobyprefixnamespaced: podname: $1 namespace: $2"
  clear
  echo "${grn}[Deploy][Wait]${end} Wait until pod: $1 in NameSpace: $2 is running..."
  podstatusall=$(kubectl get pod -n "$2" -o wide | grep "$1" 2>/dev/null)
  #echo "[Debug] kubectl get pod -n "$2" -o wide | grep "$1""
  #echo "[Debug] ${podstatusall}"
  podname=$(echo ${podstatusall} | awk -F " " '{print $1}')
  podstatus=$(echo ${podstatusall} | awk -F " " '{print $3}')
  podip=$(echo ${podstatusall} | awk -F " " '{print $6}')
  #echo "[Debug][getpodinfobyprefixnamespaced] podname: \"${podname}\" podstatus: \"${podstatus}\" podip: \"${podip}\""
}

waituntilpodready(){
  while true
  do
    sleep 10
    #echo "[Debug] podnameprefix: $1"
    getpodinfobyprefix "$1"
    if [ "${podstatus}" == "Running" ]
    then
     break
    fi
  done
}

waituntilpodreadynamespaced(){
  #echo "[Debug] waituntilpodreadynamespaced name: $1 NS: $2"
  while true
  do
#    sleep 10
    getpodinfobyprefixnamespaced "$1" "$2"
    if [ "${podstatus}" == "Running" ]
    then
     break
    fi
  done
}

getnodeinfo(){
  echo "getnodeinfo"
}

waituntilnodeready(){
  echo "waituntilnodeready"
}

clear
echo "${yel}[Preflightcheck]${end} 請確認運行的 Kubernetes 叢集是全新未部屬"

# 等 flannel ready 再繼續
waituntilpodreadynamespaced "kube-flannel-ds" "kube-flannel"

echo "${yel}[Cleanup]${end} 移除 mongoDB 先前資料 (/mnt/mongo/)"
sudo rm -rf "/mnt/mongo/"
cd free5gc/
echo "${grn}[Deploy][5GC]${end} Deploying mongoDB"
kubectl apply -f 01-free5gc-mongodb.yaml
#echo "[Debug] sleep 60 for mongo"
#sleep 60
echo "${grn}[Deploy][Wait]${end} 等待 mongoDB 服務轉為 Running 狀態..."
waituntilpodready "free5gc-mongodb"
#echo "[Debug] getpodmacaddress"
getpodmacaddress "free5gc-mongodb"
#read -p "pause for debug" pause

echo "${grn}[Deploy][5GC]${end} Deploying UPF"
kubectl apply -f 02-free5gc-upf.yaml
waituntilpodready "free5gc-upf"
get_containerid "${podname}"
get_containerpid
get_containerifnum
get_vethname
printall
#echo "${yel}[Debug]${end} 我們先睡 30 秒，如果要監控 UPF 的 GTP-U 和 PFCP 現在快去開 tcpdump 監聽 veth"
#echo "${yel}[Debug]${end} 抓 PFCP 和 GTP-U 參考指令: sudo tcpdump -v udp port 8805 or udp port 2152 -i ${VethName}"
#echo "${yel}[Debug]${end} 抓 PFCP request 參考指令: sudo tcpdump -v src host 10.244.0.8 and udp port 8805 -i ${VethName}"
#sleep 30
echo "${red}[預計]${end} 之後要自動抓取 PFCP 封包並設定 timeout"

# 取得 veth，在 smf 起來前要監聽 PFCP Association、Modification
# 之後送到 UPF 的 packet 要 rewrite IP 送到新長出來的 UPF

echo "${grn}[Deploy][5GC]${end} Deploying NRF"
kubectl apply -f 03-free5gc-nrf.yaml
echo "${grn}[Deploy][Wait]${end} 等待 NRF 服務轉為 Running 狀態..."
waituntilpodready "free5gc-nrf"

echo "${grn}[Deploy][5GC]${end} Deploying AMF"
kubectl apply -f 04-free5gc-amf.yaml
echo "${grn}[Deploy][Wait]${end} 等待 AMF 服務轉為 Running 狀態..."
waituntilpodready "free5gc-amf"
getpodinfobyprefix "free5gc-amf"
amfip="${podip}"
echo "amfip: ${amfip}"

echo "${grn}[Deploy][5GC]${end} Deploying SMF"
#kubectl apply -f 05-free5gc-smf.yaml
kubectl apply -f 05-free5gc-smf.yaml
waituntilpodready "free5gc-smf"
get_containerid "${podname}"
get_containerpid
get_containerifnum
get_vethname
printall
echo "${grn}[Deploy][Wait]${end} 等待 SMF 服務轉為 Running 狀態..."
# echo "${red}[預計]${end} 之後 SMF 要 DROP 掉除了第一個 UPF 的 PFCP"
# echo "${yel}[Debug][SMF]${end} SMF Veth: ${VethName} IP: ${podip}"
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
echo "${grn}[Deploy][Wait]${end} 等待 AUSF 服務轉為 Running 狀態..."
waituntilpodready "free5gc-ausf"

echo "${grn}[Deploy][5GC]${end} Deploying WEB-UI"
kubectl apply -f 11-free5gc-webui.yaml
echo "${grn}[Deploy][Wait]${end} 等待 webui 服務轉為 Running 狀態..."
waituntilpodready "free5gc-webui"
getpodinfobyprefix "free5gc-webui"
webuiip="${podip}"
echo "webuiip: ${webuiip}"

echo "${yel}[Debug]${end} 我們先睡 60 秒，快去 WEB-UI 註冊"
hostip=$(hostname -I | awk -F " " '{print $1}')
echo "${yel}[Debug]${end} 參考網址: ${hostip}:31111/#/subscriber"
sleep 30
curl "http://${hostip}:31111/api/subscriber" \
  -H 'Accept: application/json' \
  -H 'Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7,ja-JP;q=0.6,ja;q=0.5' \
  -H 'Connection: keep-alive' \
  -H 'DNT: 1' \
  -H "Referer: http://${hostip}:31111/" \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --insecure

curl "http://${hostip}:31111/api/subscriber/imsi-208930000000003/20893" \
  -H 'Accept: application/json' \
  -H 'Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7,ja-JP;q=0.6,ja;q=0.5' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'DNT: 1' \
  -H "Origin: http://${hostip}:31111" \
  -H "Referer: http://${hostip}:31111/" \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --data-raw '{"plmnID":"20893","ueId":"imsi-208930000000003","AuthenticationSubscription":{"authenticationManagementField":"8000","authenticationMethod":"5G_AKA","milenage":{"op":{"encryptionAlgorithm":0,"encryptionKey":0,"opValue":"8e27b6af0e692e750f32667a3b14605d"}},"opc":{"encryptionAlgorithm":0,"encryptionKey":0,"opcValue":""},"permanentKey":{"encryptionAlgorithm":0,"encryptionKey":0,"permanentKeyValue":"8baf473f2f8fd09487cccbd7097c6862"},"sequenceNumber":"16f3b3f70fc2"},"AccessAndMobilitySubscriptionData":{"gpsis":["msisdn-0900000000"],"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"010203","isDefault":true},{"sst":1,"sd":"112233","isDefault":true}],"singleNssais":[]},"subscribedUeAmbr":{"downlink":"2 Gbps","uplink":"1 Gbps"}},"SessionManagementSubscriptionData":[{"singleNssai":{"sst":1,"sd":"010203"},"dnnConfigurations":{"internet":{"sscModes":{"defaultSscMode":"SSC_MODE_1","allowedSscModes":["SSC_MODE_2","SSC_MODE_3"]},"pduSessionTypes":{"defaultSessionType":"IPV4","allowedSessionTypes":["IPV4"]},"sessionAmbr":{"uplink":"200 Mbps","downlink":"100 Mbps"},"5gQosProfile":{"5qi":9,"arp":{"priorityLevel":8},"priorityLevel":8}},"internet2":{"sscModes":{"defaultSscMode":"SSC_MODE_1","allowedSscModes":["SSC_MODE_2","SSC_MODE_3"]},"pduSessionTypes":{"defaultSessionType":"IPV4","allowedSessionTypes":["IPV4"]},"sessionAmbr":{"uplink":"200 Mbps","downlink":"100 Mbps"},"5gQosProfile":{"5qi":9,"arp":{"priorityLevel":8},"priorityLevel":8}}}},{"singleNssai":{"sst":1,"sd":"112233"},"dnnConfigurations":{"internet":{"sscModes":{"defaultSscMode":"SSC_MODE_1","allowedSscModes":["SSC_MODE_2","SSC_MODE_3"]},"pduSessionTypes":{"defaultSessionType":"IPV4","allowedSessionTypes":["IPV4"]},"sessionAmbr":{"uplink":"200 Mbps","downlink":"100 Mbps"},"5gQosProfile":{"5qi":9,"arp":{"priorityLevel":8},"priorityLevel":8}},"internet2":{"sscModes":{"defaultSscMode":"SSC_MODE_1","allowedSscModes":["SSC_MODE_2","SSC_MODE_3"]},"pduSessionTypes":{"defaultSessionType":"IPV4","allowedSessionTypes":["IPV4"]},"sessionAmbr":{"uplink":"200 Mbps","downlink":"100 Mbps"},"5gQosProfile":{"5qi":9,"arp":{"priorityLevel":8},"priorityLevel":8}}}}],"SmfSelectionSubscriptionData":{"subscribedSnssaiInfos":{"01010203":{"dnnInfos":[{"dnn":"internet"},{"dnn":"internet2"}]},"01112233":{"dnnInfos":[{"dnn":"internet"},{"dnn":"internet2"}]}}},"AmPolicyData":{"subscCats":["free5gc"]},"SmPolicyData":{"smPolicySnssaiData":{"01010203":{"snssai":{"sst":1,"sd":"010203"},"smPolicyDnnData":{"internet":{"dnn":"internet"},"internet2":{"dnn":"internet2"}}},"01112233":{"snssai":{"sst":1,"sd":"112233"},"smPolicyDnnData":{"internet":{"dnn":"internet"},"internet2":{"dnn":"internet2"}}}}},"FlowRules":[]}' \
  --insecure

curl "http://${hostip}:31111/api/subscriber" \
  -H 'Accept: application/json' \
  -H 'Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7,ja-JP;q=0.6,ja;q=0.5' \
  -H 'Connection: keep-alive' \
  -H 'DNT: 1' \
  -H "Referer: http://${hostip}:31111/" \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --insecure


echo "${grn}[Deploy][UERANSIM]${end} Deploying gnb"
kubectl apply -f ueransim/ueransim-gnb.yaml

echo "${grn}[Deploy][UERANSIM]${end} Deploying ue"
kubectl apply -f ueransim/ueransim-ue.yaml
waituntilpodready "ueransim-ue"
echo "${yel}[Debug][UE]${end} UE 內網路介面如下"
kubectl exec -it ${podname} -- ip a
