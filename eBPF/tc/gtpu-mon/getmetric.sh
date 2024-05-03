#!/bin/bash
# ip ref: https://stackoverflow.com/questions/10768160/ip-address-converter
# jq ref: https://stackoverflow.com/questions/34226370/jq-print-key-and-value-for-each-entry-in-an-object

ip2dec(){ # Convert an IPv4 IP number to its decimal equivalent.
          declare -i a b c d;
          IFS=. read a b c d <<<"$*";
          echo "$(((a<<24)+(b<<16)+(c<<8)+d))";
        }

dec2ip(){ # Convert an IPv4 decimal IP value to an IPv4 IP.
          declare -i a=$((0xff)) b=$1;
          c="$((b>>24&a)).$((b>>16&a)).$((b>>8&a)).$((b&a))";
          echo "$c";
        }

#iplist_ori=$(sudo bpftool map dump id 60 | jq -c -r '.[] | .value')
iplist_ori=$(sudo bpftool map dump id 60 | jq -c -r '.[] | [.key, .value] | @tsv' | awk -F ' ' '{print $1 " " $2}')
traffic_list=$(sudo bpftool map dump id 61 | jq -c -r '.[] | [.key, .value] | @tsv' | awk -F ' ' '{print $1 " " $2}')

while IFS= read -r line
do
#    echo "${line}"
    key=$(echo ${line} | awk -F ' ' '{print $1}')
    ipdecrev=$(echo ${line} | awk -F ' ' '{print $2}')
    iprev=$(dec2ip "${ipdecrev}")
#    echo "${iprev}"
    ip=$(echo "${iprev}" | awk -F'.' '{print $4"."$3"."$2"."$1}')
#    echo "${key} ${ipdecrev} -> ${iprev} -> ${ip}"
    traffic=$(echo "${traffic_list}" | grep "${key}" | awk -F ' ' '{print $2}')
#    echo "key: ${key} ip_dec_rev: ${ipdecrev} -> ip_rev: ${iprev} -> ip: ${ip} traffic: ${traffic}"
    printf "key: %-10s ip_dec_rev: %-14d ip_rev: %-18s ip: %-18s traffic: %d\n" "${key}" "${ipdecrev}" "${iprev}" "${ip}" "${traffic}"
done <<< "${iplist_ori}"
