#!/bin/bash

containers=$(docker ps -a | grep -v CONTAINER | awk -F " " '{print $1" "$NF}')
while read line
do
#  echo "LINE: '${line}'"
  containerid=$(echo ${line} | awk -F " " '{print $1}')
  containername=$(echo ${line} | awk -F " " '{print $2}')
  containerpid=$(docker inspect --format '{{.State.Pid}}' "${containerid}")
  ifnum=$(sudo nsenter -t "$containerpid" -n ip addr | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
  ipincontainer=$(sudo nsenter -t "$containerpid" -n ip -4 addr show eth0 | grep inet | awk -F " " '{print $2}' | awk -F "/" '{print $1}')
  vethname=$(ip a | grep "${ifnum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
  echo "[Info] ID: ${containerid} PID: ${containerpid} ifnum: ${ifnum} vethname: ${vethname} IPinContainer: ${ipincontainer} NAME: ${containername}"
  nicebpf=$(ip a | grep ${vethname})
  xdpdrvresult=$(echo ${nicebpf} | grep "xdp/")
  xdpgenericresult=$(echo ${nicebpf} | grep "xdpgeneric/")
  [[ ! -z ${xdpdrvresult} ]] && nicebpfmode="xdpdrv"
  [[ ! -z ${xdpgenericresult} ]] && nicebpfmode="xdpgeneric"
  case ${nicebpfmode} in
    xdpdrv)
        echo "[eBPF][NIC] ${vethname} mounted eBPF in xdpdrv mode!"
        echo "[eBPF][NIC] To detach, use following command:"
        echo "[eBPF][NIC]   sudo ip link set dev ${vethname} xdp off"
        ;;
    xdpgeneric)
        echo "[eBPF][NIC] ${vethname} mounted eBPF in xdpgeneric mode!"
        echo "[eBPF][NIC] To detach, use following command:"
        echo "[eBPF][NIC]   sudo ip link set dev ${vethname} xdpgeneric off"
        ;;
    *)
        echo "[eBPF][NIC] ${vethname} has no eBPF mounted!"
        ;;
  esac
  nictcclsact=$(sudo tc qdisc show dev ${vethname} clsact | grep clsact)
  if [[ ! -z ${nictcclsact} ]]
  then
    echo "[eBPF][tc] Detected tc-clsact on ${vethname}!"
    # 然後看 ingress 和 egress 的
    # tips: 多行變數記得加 ""
    inebpfresult=$(sudo tc filter show dev ${vethname} ingress | grep "direct-action")
      [ -z "${inebpfresult}" ] && inebpfnum=0 || inebpfnum=$(echo "${inebpfresult}" | wc -l)
#    inebpfnum=$(echo "${inebpfresult}" | wc -l)
#    echo "sudo tc filter show dev ${vethname} egress | grep \"direct-action\""
    eebpfresult=$(sudo tc filter show dev ${vethname} egress | grep "direct-action")
      [ -z "${eebpfresult}" ] && eebpfnum=0 || eebpfnum=$(echo "${eebpfresult}" | wc -l)
#    eebpfnum=$(echo "${eebpfresult}" | wc -l)
#    echo "  [Debug] inebpfnum ${inebpfnum} eebpfnum: ${eebpfnum}"
    echo "[eBPF][tc] Number of ebpf mounted on ingress: ${inebpfnum}"
#    echo "inebpfresult"
#    echo "$inebpfresult"
#    echo "eebpfresult"
#    echo "$eebpfresult"
    if [[ "${inebpfnum}" != "0" ]]
    then
      while IFS= read -r line
      do
        echo "[eBPF][tc] ${line}"
        pref=$(echo "${line}" | awk -F " " '{print $5}')
        uid=$(echo "${line}" | awk -F " " '{print $15}')
        tag=$(echo "${line}" | awk -F " " '{print $17}')
        echo "[eBPF][tc] To detach, use following command:"
        echo "[eBPF][tc]   sudo tc filter del dev ${vethname} ingress pref ${pref} handle 0x1 bpf"
      done <<< "${inebpfresult}"
    else
     echo "[eBPF][tc] To attach eBPF onto tc, use following command:"
     echo "[eBPF][tc]    sudo tc filter add dev ${vethname} ingress bpf da obj \${objname}.o sec \${secname}"
    fi
    echo "[eBPF][tc]"

    echo "[eBPF][tc] Number of ebpf mounted on egress: ${eebpfnum}"
    if [[ "${eebpfnum}" != "0" ]]
    then
      while IFS= read -r line
      do
        echo "[eBPF][tc] ${line}"
        pref=$(echo "${line}" | awk -F " " '{print $5}')
        uid=$(echo "${line}" | awk -F " " '{print $15}')
        tag=$(echo "${line}" | awk -F " " '{print $17}')
        echo "[eBPF][tc] To detach, use following command:"
        echo "[eBPF][tc]   sudo tc filter del dev ${vethname} egress pref ${pref} handle 0x1 bpf"
#        echo "[eBPF][tc]"
      done <<< "${eebpfresult}"
    else
     echo "[eBPF][tc] To attach eBPF onto tc, use following command:"
     echo "[eBPF][tc]    sudo tc filter add dev ${vethname} egress bpf da obj \${objname}.o sec \${secname}"
    fi
    echo "[eBPF][tc]"

  else
    echo "[eBPF][tc] No tc-clsact on ${vethname}!"
    echo "[eBPF][tc] To add eBPF hook point onto tc, use following command:"
    echo "[eBPF][tc]   sudo tc qdisc add dev ${vethname} clsact"
  fi
  echo ""
done < <(echo "$containers")
