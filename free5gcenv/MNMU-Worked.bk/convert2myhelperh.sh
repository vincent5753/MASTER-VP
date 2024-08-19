#!/bin/bash
# By VP@231027, tested on ubuntu_20.04
# ref: https://stackoverflow.com/questions/70972594/kubernetes-bridge-networking-issue
# support for containerd by VP@240405
# ref: https://stackoverflow.com/questions/70948748/how-to-retrieve-the-pod-container-in-which-run-a-given-process

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
end=$'\e[0m'

# k8s找 docker 的 containerID -> 用 Docker 容器ID 找 PID -> 使用 PID exec 進容器找介面id(ifnum) -> 透過 ifnum 找到 veth

get_containerid(){
  PodName="$1"
  ContainerID=$(kubectl describe po "$1" | grep "Container ID" | cut -d '/' -f 3)
}

get_cri(){
  cri=$(kubectl describe po "$1" | grep "Container ID" | cut -d ':' -f 2 | sed 's/\ //g')
}

get_containerpid_containerd(){
  ContainerPID=$(sudo crictl inspect "${ContainerID}" | jq -c ".info.pid")
}

get_containerpid_docker(){
  ContainerPID=$(docker inspect --format '{{.State.Pid}}' "$ContainerID")
}

get_containerifnum(){
  IfNum=$(sudo nsenter -t "$ContainerPID" -n ip addr | grep "eth0@" | cut -d '@' -f 2 | cut -d ':' -f 1 | sed 's/if//g')
}

get_vethname(){
  VethName=$(ip a | grep -E "^${IfNum}: " | cut -d '@' -f 1 | cut -d ' ' -f 2)
}

get_macaddress(){
  macaddr=$(kubectl exec -it "$1" -- ip a show eth0 | grep 'ether\ ' | awk '{print $2}' | cut -d '/' -f 1)
}

get_ipaddr(){
  ipaddr=$(kubectl exec -it $1 -- ip a show eth0 | grep 'inet\ ' | awk '{print $2}' | cut -d '/' -f 1)
}

gen_clang_header(){
# variables ref
#   ${PodName} -> Name of Pod
#   ${ipaddr}  -> IP addr of Pod

template="
    {
        .name = \"UPF2Replace\",
        .ifnum = ifnum2replace,
        .mac = {0xx1, 0xx2, 0xx3, 0xx4, 0xx5, 0xx6},
        .ipv4 = 10 | (244 << 8) | (0 << 16) | (IP4 << 24)
    },
"

# for last UPF replica (in our case is UPF 3)
template_no_comma="
    {
        .name = \"UPF2Replace\",
        .ifnum = ifnum2replace,
        .mac = {0xx1, 0xx2, 0xx3, 0xx4, 0xx5, 0xx6},
        .ipv4 = 10 | (244 << 8) | (0 << 16) | (IP4 << 24)
    }
"

template_no_braces="
.name = \"UPF2Replace\", .ifnum = ifnum2replace, .mac = {0xx1, 0xx2, 0xx3, 0xx4, 0xx5, 0xx6}, .ipv4 = 10 | (244 << 8) | (0 << 16) | (IP4 << 24)
"

ifnum2replace="${IfNum}"
macaddr="${macaddr}"

# 我知道有 for 迴圈這種東西
mac1="0x$(echo "${macaddr}" | awk -F ":" '{print $1}')"
mac2="0x$(echo "${macaddr}" | awk -F ":" '{print $2}')"
mac3="0x$(echo "${macaddr}" | awk -F ":" '{print $3}')"
mac4="0x$(echo "${macaddr}" | awk -F ":" '{print $4}')"
mac5="0x$(echo "${macaddr}" | awk -F ":" '{print $5}')"
mac6="0x$(echo "${macaddr}" | awk -F ":" '{print $6}')"

IP4=$(echo "${ipaddr}" | awk -F "." '{print $NF}')

# 我知道 function 是啥，就趕鴨子上架
if [[ "${PodName}" =~ ^free5gc-upf-deployment-1-* ]]; then
  # echo "UPF-1"
  UPF2Replace="UPF1"
  # replace name and ifnum
  template=$(echo ${template} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
elif [[ "${PodName}" =~ ^free5gc-upf-deployment-2-* ]]; then
  # echo "UPF-2"
  UPF2Replace="UPF2"
  # replace name and ifnum
  template=$(echo ${template} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
elif [[ "${PodName}" =~ ^free5gc-upf-deployment-3-* ]]; then
  # echo "UPF-3"
  UPF2Replace="UPF3"
  # replace name and ifnum
  # template 被換了，所以後面就甭再用 ${template_no_comma} 了
  template=$(echo ${template_no_comma} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
elif [[ "${PodName}" =~ ^free5gc-upf-deployment-* ]]; then
  # echo "UPF-LB"
  UPF2Replace="LB"
  # replace name and ifnum
  # template 被換了，所以後面就甭再用 ${template_no_braces} 了
  template=$(echo ${template_no_braces} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
elif [[ "${PodName}" =~ ^ueransim-gnb-deployment-* ]]; then
  # echo "gNB"
  UPF2Replace="gNB"
  # replace name and ifnum
  # template 被換了，所以後面就甭再用 ${template_no_braces} 了
  template=$(echo ${template_no_braces} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
elif [[ "${PodName}" =~ ^ueransim-ue-deployment-* ]]; then
  # echo "UE"
  UPF2Replace="UE"
  # replace name and ifnum
  # template 被換了，所以後面就甭再用 ${template_no_braces} 了
  template=$(echo ${template_no_braces} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
else
  echo "No regex matched :("
  UPF2Replace="SomeName"
  # replace name and ifnum
  template=$(echo ${template} | sed "s/UPF2Replace/${UPF2Replace}/g")
  template=$(echo ${template} | sed "s/ifnum2replace/${ifnum2replace}/g")
  # replace MAC Addr
  template=$(echo "${template}" | sed "s/0xx1/${mac1}/g")
  template=$(echo "${template}" | sed "s/0xx2/${mac2}/g")
  template=$(echo "${template}" | sed "s/0xx3/${mac3}/g")
  template=$(echo "${template}" | sed "s/0xx4/${mac4}/g")
  template=$(echo "${template}" | sed "s/0xx5/${mac5}/g")
  template=$(echo "${template}" | sed "s/0xx6/${mac6}/g")
  # replace IP Addr
  template=$(echo "${template}" | sed "s/IP4/${IP4}/g")
fi

echo "${template}"
}

for pod in "$@"
do
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
  get_ipaddr "${pod}"
  gen_clang_header
done
