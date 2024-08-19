#!/bin/bash
# Made by GB

rm *.pcap

while true; do
    sleep 1
    podstatus=$(kubectl get pod -l app=free5gc-upf -o wide | grep "free5gc-upf"  | awk -F " " '{print $3}')
    if [ "${podstatus}" == "Running" ]; then
        break
    fi
done

pod_name=$(kubectl get pods -l app=free5gc-upf --no-headers -o custom-columns=":metadata.name")

container_id=$(kubectl get pod "${pod_name}" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's/.*:\/\/\(.\{64\}\)/\1/')
container_pid=$(docker inspect --format '{{.State.Pid}}' "${container_id}")

sudo nsenter -t ${container_pid} -n tcpdump -w pfcp.pcap -i eth0 ip -v
