#!/bin/bash
# By VP@231027, tested on ubuntu_20.04
# ref: https://stackoverflow.com/questions/70972594/kubernetes-bridge-networking-issue
# support for containerd by VP@240405
# ref: https://stackoverflow.com/questions/70948748/how-to-retrieve-the-pod-container-in-which-run-a-given-process

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
end=$'\e[0m'

# PodName="vp-ubuntu-pod2-86d4c797f7-x5sxm"
# PodName="vp-ubuntu-pod-77d975f8c7-lhpdb"

# k8s找 docker 的 containerID -> 用 Docker 容器ID 找 PID -> 使用 PID exec 進容器找介面id(ifnum) -> 透過 ifnum 找到 veth

get_containerid(){
#  echo "[Func] get_containerid"
  echo "PodName: $1"
  ContainerID=$(kubectl describe po "$1" | grep "Container ID" | cut -d '/' -f 3)
  #echo "ContainerID: $ContainerID"
}

get_cri(){
  cri=$(kubectl describe po "$1" | grep "Container ID" | cut -d ':' -f 2 | sed 's/\ //g')
}

get_containerpid_containerd(){
  ContainerPID=$(sudo crictl inspect 5c415e9de73a4b21d58e2a6d8aa6467634eb7b670018e05b3c4f1ea6eb66734 | jq -c ".info.pid")
}

get_containerpid_docker(){
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
  VethName=$(ip a | grep -E "^${IfNum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
  #echo "VethName: $VethName"
}

get_macaddress(){
  macaddr=$(kubectl exec -it $1 -- cat /sys/class/net/eth0/address)
}

get_nicbpf(){
  nicebpf=$(ip a | grep ${VethName})
  xdpdrvresult=$(echo ${nicebpf} | grep "xdp/")
  xdpgenericresult=$(echo ${nicebpf} | grep "xdpgeneric/")
  [[ ! -z ${xdpdrvresult} ]] && nicebpfmode="xdpdrv"
  [[ ! -z ${xdpgenericresult} ]] && nicebpfmode="xdpgeneric"
  case ${nicebpfmode} in
    xdpdrv)
        echo "[eBPF][NIC] ${VethName} mounted eBPF in xdpdrv mode!"
        echo "[eBPF][NIC] To ${red}detach${end}, use following command:"
        echo "[eBPF][NIC]   sudo ip link set dev ${VethName} xdp off"
        ;;
    xdpgeneric)
        echo "[eBPF][NIC] ${VethName} mounted eBPF in xdpgeneric mode!"
        echo "[eBPF][NIC] To ${red}detach${end}, use following command:"
        echo "[eBPF][NIC]   sudo ip link set dev ${VethName} xdpgeneric off"
        ;;
    *)
        echo "[eBPF][NIC] ${VethName} has no eBPF mounted!"
        ;;
  esac
}

get_tcbpf(){
  nictcclsact=$(sudo tc qdisc show dev ${VethName} clsact | grep clsact)
  if [[ ! -z ${nictcclsact} ]]
  then
    echo "[eBPF][tc] Detected tc-clsact on ${VethName}!"
    inebpfresult=$(sudo tc filter show dev ${VethName} ingress | grep "direct-action")
      [ -z "${inebpfresult}" ] && inebpfnum=0 || inebpfnum=$(echo "${inebpfresult}" | wc -l)
    eebpfresult=$(sudo tc filter show dev ${VethName} egress | grep "direct-action")
      [ -z "${eebpfresult}" ] && eebpfnum=0 || eebpfnum=$(echo "${eebpfresult}" | wc -l)
    echo "[eBPF][tc] Number of ebpf mounted on ingress: ${yel}${inebpfnum}${end}"
    if [[ "${inebpfnum}" != "0" ]]
    then
      while IFS= read -r line
      do
        echo "[eBPF][tc] ${line}"
        pref=$(echo "${line}" | awk -F " " '{print $5}')
        uid=$(echo "${line}" | awk -F " " '{print $15}')
        tag=$(echo "${line}" | awk -F " " '{print $17}')
        echo "[eBPF][tc] To ${red}detach${end}, use following command:"
        echo "[eBPF][tc]   ${yel}sudo tc filter del dev ${VethName} ingress pref ${pref} handle 0x1 bpf${end}"
      done <<< "${inebpfresult}"
    else
      echo "[eBPF][tc] To ${grn}attach${end} eBPF onto tc, use following command:"
      echo "[eBPF][tc]    ${yel}sudo tc filter add dev ${VethName} ingress bpf da obj${end} \${objname}.o sec \${secname}"
    fi
    echo "[eBPF][tc]"

    echo "[eBPF][tc] Number of ebpf mounted on egress: ${yel}${eebpfnum}${end}"
    if [[ "${eebpfnum}" != "0" ]]
    then
      while IFS= read -r line
      do
        echo "[eBPF][tc] ${line}"
        pref=$(echo "${line}" | awk -F " " '{print $5}')
        uid=$(echo "${line}" | awk -F " " '{print $15}')
        tag=$(echo "${line}" | awk -F " " '{print $17}')
        echo "[eBPF][tc] To ${red}detach${end}, use following command:"
        echo "[eBPF][tc]   ${yel}sudo tc filter del dev ${VethName} egress pref ${pref} handle 0x1 bpf${end}"
      done <<< "${eebpfresult}"
    else
      echo "[eBPF][tc] To ${grn}attach${end} eBPF onto tc, use following command:"
      echo "[eBPF][tc]    ${yel}sudo tc filter add dev ${VethName} egress bpf da obj${end} \${objname}.o sec \${secname}"
    fi
    echo "[eBPF][tc]"

  else
    echo "[eBPF][tc] No tc-clsact on ${VethName}!"
    echo "[eBPF][tc] To add ${grn}eBPF hook point${end} onto tc, use following command:"
    echo "[eBPF][tc]   sudo tc qdisc add dev ${VethName} clsact"
  fi
}

printall(){
  echo "ContainerID: \"${ContainerID}\""
  echo "ContainerPID: \"${ContainerPID}\""
  echo "IfNum: \"${IfNum}\""
  echo "VethName: \"${VethName}\""
  echo "MAC Address: ${macaddr}"
}

for pod in "$@"
do
  echo "Pod: ${pod}"
  get_cri "${pod}"
  get_containerid "${pod}"
  if [ "${cri}" == "containerd" ]
  then
    get_containerpid_containerd
  else
    get_containerpid_docker
  fi
  get_containerifnum
  get_vethname
  get_macaddress "${pod}"
  printall
  get_nicbpf
  get_tcbpf
  echo ""
done
