#!/bin/bash

compile(){
# clang -target bpf -O2 -c ${input_filename}.c -o ${output_filename}.o
clang -target bpf -O2 -c "$1.c" -o "$2.o"
}

filter_show(){
# sudo tc filter show dev "${if_name}" "${direction}"
sudo tc filter show dev "$1" "$2"
}

filter_del(){
# sudo tc filter del dev "${if}" "${direction}" pref "${pref}" handle 0x1 bpf
sudo tc filter del dev "$1" "$2" pref "$3" handle 0x1 bpf
}

filter_add(){
sudo tc filter add dev "$1" "$2" bpf da obj "$3" sec "$4"
}

update_if_tc(){

name="$1"
ifname="$2"
obj="$3"
tc_ingress_sec="$4"
tc_egress_sec="$5"

echo "<${name} Filter Show>"
filter_show "${ifname}" "ingress"
filter_show "${ifname}" "egress"

echo "<${name} Filter Del>"
filter_del "${ifname}" "ingress" "49152"
filter_del "${ifname}" "egress" "49152"

echo "<${name} Filter Show>"
filter_show "${ifname}" "ingress"
filter_show "${ifname}" "egress"

echo "<${name} Filter Add>"
#filter_add "${ifname}" "ingress" "${obj}" "${tc_ingress_sec}"
#filter_add "${ifname}" "egress" "${obj}" "${tc_egress_sec}"

echo "<${name} Filter Show>"
filter_show "${ifname}" "ingress"
filter_show "${ifname}" "egress"

}

echo "<Compile>"
compile "tc-chksum-udp" "tc-chksum-udp"
#clang -target bpf -O2 -c tc-chksum-udp.c -o tc-chksum-udp.o

## flannel.1
update_if_tc "flannel.1" "flannel.1" "tc-chksum-udp.o" "tc-info-ingress-flannel" "tc-info-egress-flannel"

echo "------------------------------"
# cni0
update_if_tc "cni0" "cni0" "tc-chksum-udp.o" "tc-info-ingress-cni0" "tc-info-egress-cni0"

echo "------------------------------"

# veth of WEB-UI
update_if_tc "WEB-UI" "veth0f91c7f1" "tc-chksum-udp.o" "tc-info-ingress-upf" "tc-info-egress-upf"

# UPF
update_if_tc "UPF" "veth94b8b3bf" "tc-chksum-udp.o" "tc-info-ingress-upf" "tc-info-egress-upf"

#echo "<trace_pip>"
#sudo cat /sys/kernel/debug/tracing/trace_pipe
