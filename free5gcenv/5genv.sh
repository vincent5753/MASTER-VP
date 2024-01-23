#!/bin/bash

read -p "請確認運行的 Kubernetes 叢集是全新未部屬的" pause

sudo rm -rf "/mnt/mongo"
cd free5gc/
echo "[Deploy][5GC] Deploying mongoDB"
kubectl apply -f 01-free5gc-mongodb.yaml

echo "[Deploy][Wait] 等待 mongoDB 服務轉為 Running 狀態..."
while true
do
  sleep 5
  mongostatus=$(kubectl get po -o wide | grep "free5gc-mongodb" | awk -F " " '{print $3}')
  if [ "${mongostatus}" == "Running" ]
  then
   break
  fi
done

echo "[Deploy][5GC] Deploying UPF"
kubectl apply -f 02-free5gc-upf.yaml
echo "[Deploy][5GC] Deploying NRF"
kubectl apply -f 03-free5gc-nrf.yaml
echo "[Deploy][Wait] 等待 NRF 服務轉為 Running 狀態..."

while true
do
  sleep 5
  nrfstatus=$(kubectl get po -o wide | grep "free5gc-nrf" | awk -F " " '{print $3}')
  if [ "${nrfstatus}" == "Running" ]
  then
   break
  fi
done

echo "[Deploy][5GC] Deploying AMF"
kubectl apply -f 04-free5gc-amf.yaml

echo "[Deploy][5GC] Deploying SMF"
kubectl apply -f 05-free5gc-smf.yaml

echo "[Deploy][5GC] Deploying UDR"
kubectl apply -f 06-free5gc-udr.yaml

echo "[Deploy][5GC] Deploying PCF"
kubectl apply -f 07-free5gc-pcf.yaml

echo "[Deploy][5GC] Deploying UDM"
kubectl apply -f 08-free5gc-udm.yaml

echo "[Deploy][5GC] Deploying NSSF"
kubectl apply -f 09-free5gc-nssf.yaml

echo "[Deploy][5GC] Deploying AUSF"
kubectl apply -f 10-free5gc-ausf.yaml

echo "[Deploy][5GC] Deploying WEB-UI"
kubectl apply -f 11-free5gc-webui.yaml

read -p "請於 WEB-UI 註冊後按下 ENTER 以繼續"

echo "[Deploy][UERANSIM] Deploying gnb"
kubectl apply -f ueransim/ueransim-gnb.yaml

echo "[Deploy][UERANSIM] Deploying ue"
kubectl apply -f ueransim/ueransim-ue.yaml
