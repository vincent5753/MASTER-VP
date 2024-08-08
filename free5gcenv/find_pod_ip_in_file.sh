#!/bin/bash

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
end=$'\e[0m'

pods_in_k8s=$(kubectl get po -o wide | grep -v "IP" | awk -F " " '{print $1" "$6}')

# ref: https://askubuntu.com/questions/344407/how-to-read-complete-line-in-for-loop-with-spaces
while read -r pod; do
#  echo ${pod}
  pod_name=$(echo "${pod}" | awk -F " " '{print $1}')
  pod_ip=$(echo "${pod}" | awk -F " " '{print $2}')
  echo "${yel}${pod_name}${end} <-> ${yel}${pod_ip}${end}"
  grep -Rnw "${pod_ip}" ~/ | grep -v "zsh\|vscode\|kube\|fuck\|參考\|位置\|5genv"
  echo "<--------------------------------------->"
done <<< "${pods_in_k8s}"
