#!/bin/bash

get_netif_macaddr(){
macaddr=$(cat "/sys/class/net/${1}/address")
}

netif="ens18"

hostname=$(hostname)
if [ "${hostname}"  == "ext-upf1" ]
then
  echo "ext-upf1"
  UPF2Replace="ens18-eu1"
elif [ "${hostname}"  == "ext-upf2" ]
then
  echo "ext-upf2"
  UPF2Replace="ens18-eu2"
elif [ "${hostname}"  == "ext-upf3" ]
then
  echo "ext-upf3"
  UPF2Replace="ens18-eu3"
else
  echo "WTF?"
fi

ipaddr=$(hostname -I | awk '{print $1}')
IP4=$(echo "${ipaddr}" | awk -F "." '{print $NF}')
#echo "${ipaddr}"

get_netif_macaddr "${netif}"
#echo "${macaddr}"

macaddr_hex=$(echo "${macaddr}" | awk -F: '{for(i=1; i<=NF; i++) printf "0x%s%s", $i, (i<NF ? ", " : "\n")}')
MAC2REPLACE="${macaddr_hex}"
#echo "${macaddr_hex}"

template_no_braces=".name = \"UPF2Replace\", .ifnum = 2, .mac = {MAC2REPLACE}, .ipv4 = 10 | (0 << 8) | (0 << 16) | (IP4 << 24)"

#echo "${template_no_braces}"

template_no_braces=$(echo ${template_no_braces} | sed "s/UPF2Replace/${UPF2Replace}/g")
template_no_braces=$(echo ${template_no_braces} | sed "s/MAC2REPLACE/${MAC2REPLACE}/g")
template_no_braces=$(echo ${template_no_braces} | sed "s/IP4/${IP4}/g")

echo "<myhelper.sh header>"
echo "${template_no_braces}"

containerid=$(docker ps | grep "k8s_POD_free5gc-upf-deployment-" | awk -F " " '{print $1}' )
containerpid=$(docker inspect --format '{{.State.Pid}}' "${containerid}")

#echo "containerid: ${containerid} containerpid: ${containerpid}"
containerip=$(sudo nsenter -t "${containerpid}" -n ip a show eth0 | grep inet | awk '{print $2}' | awk -F "/" '{print $1}')
containermac=$(sudo nsenter -t "${containerpid}" -n ip a show eth0 | grep ether | awk '{print $2}')
vethif=$(sudo nsenter -t "${containerpid}" -n ip a show eth0 | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
vethname=$(ip a | grep -E "^${vethif}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
#echo "containerip: ${containerip} containermac: ${containermac}"
echo "<PFCP Rewrite>"
echo "python3 pfcp_v2.py -i pfcp.pcap -o pfcp-exupf.pcap --newupfip ${containerip} --newupfmac ${containermac} --upflbip 10.244.0.5"
echo "<tcpreplay>"
echo "sudo tcpreplay -i ${vethname} -t -K pfcp-exupf.pcap"
