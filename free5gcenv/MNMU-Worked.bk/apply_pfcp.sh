#!/bin/bash
UPF_index=3

lb_upf=$(kubectl get pods -l app=free5gc-upf --no-headers -o custom-columns=":metadata.name")
lb_upf_ip=$(kubectl get pod ${lb_upf} -o jsonpath='{.status.podIP}')
lb_upf_mac=$(kubectl exec ${lb_upf} -- cat /sys/class/net/eth0/address)
# echo 0 | sudo tee /proc/sys/net/ipv4/conf/all/rp_filter


get_pod_info() {
    container_id=$(kubectl get pod ${1} -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's/.*:\/\/\(.\{64\}\)/\1/')
    pod_ip=$(kubectl get pod ${1} -o jsonpath='{.status.podIP}')
    container_pid=$(docker inspect --format '{{.State.Pid}}' "${container_id}")
    ifnum=$(sudo nsenter -t "${container_pid}" -n ip addr | grep -o -e "eth0@if\([0-9]*\)" | sed "s/eth0@if//")
    veth_name=$(ip a | grep -o -E "^${ifnum}: veth[A-Za-z0-9]*" | sed "s/[0-9]*:\ //")
    veth_mac=$(kubectl exec ${1} -- cat /sys/class/net/eth0/address)

    echo "${1} / ${veth_name}"
    echo "${pod_ip}"
    echo "${veth_mac}"

    # echo "python3 pfcp_v2.py -i pfcp.pcap -o pfcp-upf${2}.pcap --newupfip ${pod_ip} --newupfmac ${veth_mac} --upflbip ${lb_upf_ip}"
    python3 pfcp_v2.py -i pfcp.pcap -o pfcp-upf${2}.pcap --newupfip ${pod_ip} --newupfmac ${veth_mac} --upflbip ${lb_upf_ip}
    echo 0 | sudo tee "/proc/sys/net/ipv4/conf/${veth_name}/rp_filter" > /dev/null
    # echo "sudo tcpreplay -i ${veth_name} -t -K pfcp-upf${2}.pcap"
    sudo tcpreplay -i ${veth_name} -t -K "pfcp-upf${2}.pcap"
}


echo "${lb_upf}"
echo "${lb_upf_ip}"
echo "${lb_upf_mac}"
echo "=========="


sudo chown vp:vp pfcp.pcap
for index in $(seq 3)
do
    upf_name=$(kubectl get pods -l "app=free5gc-upf-${index}" --no-headers -o custom-columns=":metadata.name")
    get_pod_info $upf_name $index
    echo "----------"
done
