#!/bin/bash

# Made by GB

# 重建 SOP
# 1. 砍掉全部 Pod (bash nemesis.sh)
# 2. apply 所有 free5gc 的 yaml (bash 5genv.sh)
# 3. apply another-upfX.yaml | X= 1~3 (bash helper.sh deployupf)
# 4. modify pcap & tcpreplay
# 5. get-pod-veth
# 6. 抓 4 個 UPF 以及 ue 的 pod name 並修改下方變數
# 7. 修改 lb_veth 為沒編號 UPF 的 veth name
# 8. 修改 myhelper.h 中的 4 個 UPF 以及 gnb 的資料
# 9. ping 看看有沒有通 (沒通就代表上面有步驟做錯)
#
# * 另外 UE 重啟過需重新安裝 iperf 等套件


lb_veth=LBVeth2replace  # 要改，lb 的 veth
# lb_veth=test
# real_eth=cni0

# ===== Parameters =====
# ----- Pod -----
ue_name=UEName2replace  # 要改，ue pod name
# activate_pod_name=()
activate_pod_name=(  # 要改，要掛的 pod
  UPF1Name2replace
  UPF2Name2replace
  UPF3Name2replace
  UPFLBName2replace
)

# ----- XDP -----
# xdp.c
bpf_xdp_name=xdp
xdp_section_info=xdp_info

# ----- TC -----
# tc.c
bpf_tc_name=tc
# bpf_tc_name=tc_ingress
tc_section_ingress=ingress_info
tc_section_egress=egress_info
tc_secton_load_balance=load_balance_egress
tc_secton_cni0_bonding_ingress=cni0_bonding_ingress
tc_secton_cni0_bonding_egress=cni0_bonding_egress

DEBUG_LEVEL=3


# ===== Function =====
get_pod_veth() {
    _container_id=$(kubectl get pod ${1} -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's/.*:\/\/\(.\{64\}\)/\1/')
    _container_pid=$(docker inspect --format '{{.State.Pid}}' "${_container_id}")
    _ifnum=$(sudo nsenter -t "${_container_pid}" -n ip addr | grep -o -e "eth0@if\([0-9]*\)" | sed "s/eth0@if//")
    veth_name=$(ip a | grep -o -E "^${_ifnum}: veth[A-Za-z0-9]*" | sed "s/[0-9]*:\ //")
}

for i in "${!activate_pod_name[@]}"; do
  get_pod_veth "${activate_pod_name[i]}"
  activate_veth+=( "${veth_name}" )
done
# activate_pod_name+=( "cni0" )
# activate_veth+=( "cni0" )
# activate_pod_name+=( "flannel.1" )
# activate_veth+=( "flannel.1" )
# activate_pod_name+=( "ens18" )
# activate_veth+=( "ens18" )

helper_mac_format() {
    container_id=$(kubectl get pod ${1} -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's/.*:\/\/\(.\{64\}\)/\1/')
    pod_ip=$(kubectl get pod ${1} -o jsonpath='{.status.podIP}')
    container_pid=$(docker inspect --format '{{.State.Pid}}' "${container_id}")
    ifnum=$(sudo nsenter -t "${container_pid}" -n ip addr | grep -o -e "eth0@if\([0-9]*\)" | sed "s/eth0@if//")
    veth_mac=$(kubectl exec ${1} -- cat /sys/class/net/eth0/address | sed 's/:/, 0x/g')
    echo "${1} / ${pod_ip} / ${ifnum} / 0x${veth_mac}"
}


if [ $# -eq 1 ]
then
  case "${1}" in
    off)
      # XDP
      for veth in "${activate_veth[@]}"; do
        [ ! -z "$(ip addr show ${veth} | grep 'xdp/')" ] && sudo ip link set dev ${veth} xdp off
      done

      # TC
      for veth in "${activate_veth[@]}"; do
        for direction in "ingress" "egress"; do
          for pref in $(sudo tc filter show dev ${veth} ${direction} | grep "direct-action" | awk -F " " '{print $5}'); do
            sudo tc filter del dev ${veth} ${direction} pref ${pref} handle 0x1 bpf
          done
        done
      done
    ;;
    on)
      # Compile XDP
      clang -target bpf -DDEBUG_LEVEL=${DEBUG_LEVEL} -g -O2 -c ${bpf_xdp_name}.c -o ${bpf_xdp_name}.o
      if [ $? -ne 0 ]; then
        echo ${bpf_xdp_name}.c compile error
        exit 1
      fi
      # Compile TC
      clang -target bpf -DDEBUG_LEVEL=${DEBUG_LEVEL} -g -O2 -c ${bpf_tc_name}.c -o ${bpf_tc_name}.o
      if [ $? -ne 0 ]; then
        echo ${bpf_tc_name}.c compile error
        exit 1
      fi

      # Mount XDP
      for veth in "${activate_veth[@]}"; do
        if [ ! "${veth}" = "cni0" ] && [ ! "${veth}" = "flannel.1" ] && [ ! "${veth}" = "ens18" ]; then
          sudo ip link set dev ${veth} xdpdrv obj ${bpf_xdp_name}.o sec ${xdp_section_info}
        fi
      done
      # Mount TC
      for veth in "${activate_veth[@]}"; do
        [[ -z $(sudo tc qdisc show dev ${veth} clsact | grep clsact) ]] && sudo tc qdisc add dev ${veth} clsact
        # Ingress
        sudo tc filter add dev ${veth} ingress bpf da obj ${bpf_tc_name}.o sec ${tc_section_ingress}
        # if [ "${veth}" = "${real_eth}" ]; then
        #   sudo tc filter add dev ${veth} ingress bpf da obj ${bpf_tc_name}.o sec ${tc_secton_cni0_bonding_ingress}
        # else
        #   sudo tc filter add dev ${veth} ingress bpf da obj ${bpf_tc_name}.o sec ${tc_section_ingress}
        # fi
        # Egress
        # sudo tc filter add dev ${veth} egress bpf da obj ${bpf_tc_name}.o sec ${tc_section_egress}
        if [ "${veth}" = "${lb_veth}" ]; then
          sudo tc filter add dev ${veth} egress bpf da obj ${bpf_tc_name}.o sec ${tc_secton_load_balance}
        # elif [ "${veth}" = "${real_eth}" ]; then
        #   sudo tc filter add dev ${veth} egress bpf da obj ${bpf_tc_name}.o sec ${tc_secton_cni0_bonding_egress}
        else
          sudo tc filter add dev ${veth} egress bpf da obj ${bpf_tc_name}.o sec ${tc_section_egress}
        fi
      done
    ;;
    status)
      echo "=== XDP ==="
      for index in "${!activate_veth[@]}"; do
        # veth="${activate_veth[index]}"
        [ ! -z "$(ip addr show ${activate_veth[index]} | grep 'xdp/')" ] && echo "${activate_pod_name[index]}"
      done

      echo "=== TC ==="
      for index in "${!activate_veth[@]}"; do
        echo "- ${activate_pod_name[index]} / ${activate_veth[index]}"
        for direction in "ingress" "egress"; do
          echo "  - ${direction}"
          sec_name=$(sudo tc filter show dev "${activate_veth[index]}" ${direction} | grep -o -E "\w*\.o:\[\w*\]")
          [ ! -z "${sec_name}" ] && echo "    - ${sec_name}"
        done
      done
      exit 0
    ;;
    compile)
      clang -target bpf -DDEBUG_LEVEL=${DEBUG_LEVEL} -g -O2 -c ${bpf_xdp_name}.c -o ${bpf_xdp_name}.o
      clang -target bpf -DDEBUG_LEVEL=${DEBUG_LEVEL} -g -O2 -c ${bpf_tc_name}.c -o ${bpf_tc_name}.o
    ;;
    deployupf)
      for index in $(seq 3); do
        kubectl apply -f "another-upf${index}.yaml"
        sleep 1
      done
    ;;
    removeupf)
      for index in $(seq 3); do
        kubectl delete -f "another-upf${index}.yaml"
        sleep 1
      done
    ;;
    getmac)
      upf_list=$(kubectl get pods --no-headers -o custom-columns=":metadata.name" | grep -E "upf|ueransim")
      for upf_name in $upf_list; do
        helper_mac_format $upf_name
      done
    ;;
    watch)
      sudo cat /sys/kernel/debug/tracing/trace_pipe
    ;;
    ping)
      # kubectl exec -it ${ue_name} -- apt update
      # kubectl exec -it ${ue_name} -- apt install -y iputils-ping
      kubectl exec -it ${ue_name} -- ping -I uesimtun0 -c 1 8.8.8.8
    ;;
    curl)
      # kubectl exec -it ${ue_name} -- apt update
      # kubectl exec -it ${ue_name} -- apt install -y curl
      kubectl exec -it ${ue_name} -- curl --interface uesimtun0 www.google.com
    ;;
    speedtest)
      # kubectl exec -it ${ue_name} -- apt update
      # kubectl exec -it ${ue_name} -- apt install -y iperf3
      kubectl exec -it ${ue_name} -- iperf3 -M 9216 -B 60.60.0.1 -c 10.0.0.155
    ;;
    iperf)
      # kubectl exec -it ${ue_name} -- apt update
      # kubectl exec -it ${ue_name} -- apt install -y iperf
      iperfsvrip="10.0.0.155"
      ueipaddr="60.60.0.1"
      interval="60"
      packetlen="1000"
      parallel="100"
      echo "iperf -u -l ${packetlen} --parallel ${parallel} -t ${interval} -B ${ueipaddr} -c ${iperfsvrip}"
      kubectl exec -it ${ue_name} -- iperf -u -l ${packetlen} --parallel ${parallel} -t ${interval} -B ${ueipaddr} -c ${iperfsvrip}
    ;;
    *)
      echo "ERROR"
    ;;
  esac
fi
