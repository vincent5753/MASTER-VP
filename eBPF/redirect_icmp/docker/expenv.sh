#!/bin/bash

osver=$(lsb_release -r | awk -F " " '{print $2}')
echo "You are on Ubuntu ${osver}!"

# docker run --privileged --name=nginx1 -d nginx:latest
# docker run --privileged --name=nginx2 -d nginx:latest
# docker run --privileged --name=lb -d nginx:latest
# docker run --privileged --name=client -d nginx:latest

containers=$(docker ps -a | grep -v CONTAINER | awk -F " " '{print $1" "$NF}')
while read line
do
  containerid=$(echo ${line} | awk -F " " '{print $1}')
  containername=$(echo ${line} | awk -F " " '{print $2}')
  containerpid=$(docker inspect --format '{{.State.Pid}}' "${containerid}")
  ifnum=$(sudo nsenter -t "$containerpid" -n ip addr | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
  ipincontainer=$(sudo nsenter -t "$containerpid" -n ip -4 addr show eth0 | grep inet | awk -F " " '{print $2}' | awk -F "/" '{print $1}')
  vethname=$(ip a | grep "${ifnum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
  echo "ID: ${containerid} PID: ${containerpid} ifnum: ${ifnum} vethname: ${vethname} IPinContainer: ${ipincontainer} NAME: ${containername}"
  # Enable NAPI and disable checksum offload/verify
  sudo ethtool -K "${vethname}" gro on
  sudo ethtool -K "${vethname}" tx off
  sudo ethtool -K "${vethname}" rx off
  case "$containername" in
    "client")
        clientnic=$vethname
        ;;
    "lb")
        lbnic=$vethname
        ;;
    "nginx1")
        nginx1nic=$vethname
        ;;
    "nginx2")
        nginx2nic=$vethname
        ;;
  esac
done < <(echo "$containers")

mode="xdpdrv"
lbxdp="xdp_lb_kern.o"
dummyxdp="justpass.o"

# clinet
echo "update XDP for client"
sudo ip link set dev ${clientnic} xdp off
sudo ip link set dev ${clientnic} xdpgeneric off
sudo ip link set dev ${clientnic} ${mode} obj ${dummyxdp} sec justpass

# LB
echo "update XDP for LB"
sudo ip link set dev ${lbnic} xdp off
sudo ip link set dev ${lbnic} xdpgeneric off
sudo ip link set dev ${lbnic} ${mode} obj ${lbxdp} sec xdp_lb

# nginx2
echo "update XDP for nginx2"
sudo ip link set dev ${nginx2nic} xdp off
sudo ip link set dev ${nginx2nic} xdpgeneric off
sudo ip link set dev ${nginx2nic} ${mode} obj ${dummyxdp} sec justpass

# nginx1
echo "update XDP for nginx1"
sudo ip link set dev ${nginx1nic} xdp off
sudo ip link set dev ${nginx1nic} xdpgeneric off
sudo ip link set dev ${nginx1nic} ${mode} obj ${dummyxdp} sec justpass
