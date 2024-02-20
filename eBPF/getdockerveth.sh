#!/bin/bash

containers=$(docker ps -a | grep -v CONTAINER | awk -F " " '{print $1" "$NF}')
while read line
do
#  echo "LINE: '${line}'"
  containerid=$(echo ${line} | awk -F " " '{print $1}')
  containername=$(echo ${line} | awk -F " " '{print $2}')
  containerpid=$(docker inspect --format '{{.State.Pid}}' "${containerid}")
  ifnum=$(sudo nsenter -t "$containerpid" -n ip addr | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
  vethname=$(ip a | grep "${ifnum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
  echo "ID: ${containerid} PID: ${containerpid} ifnum: ${ifnum} vethname: ${vethname} NAME: ${containername}"
done < <(echo "$containers")
