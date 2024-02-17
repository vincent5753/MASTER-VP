#!/bin/bash
# By VP@231027, tested on ubuntu_20.04
# ref: https://stackoverflow.com/questions/70972594/kubernetes-bridge-networking-issue

# PodName="vp-ubuntu-pod2-86d4c797f7-x5sxm"
# PodName="vp-ubuntu-pod-77d975f8c7-lhpdb"

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

for pod in "$@"
do
  echo "Pod: $pod"
  get_containerid "$pod"
  get_containerpid
  get_containerifnum
  get_vethname
  printall
done
