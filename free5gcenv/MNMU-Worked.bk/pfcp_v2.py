# -*- coding: UTF-8 -*-
import argparse
from scapy.all import rdpcap, wrpcap
from scapy.contrib.pfcp import PFCP, IE_FTEID, IE_OuterHeaderCreation
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP


def modify_pfcp(inputfile: str, outputfile: str, smf_ip: str, new_upf_mac: str, new_upf_ip: str, upf_lb_ip: str = None):
    packets = rdpcap(inputfile)
    for pkt in packets:
        # Layer 2
        if Ether in pkt:
            pkt[Ether].dst = new_upf_mac

        # Layer 3 & 4
        if IP in pkt and UDP in pkt and pkt[IP].src == smf_ip:
            pkt[IP].dst = new_upf_ip
            del pkt[IP].chksum
            del pkt[UDP].chksum
            pkt = pkt.__class__(bytes(pkt))

        if PFCP in pkt:
            if pkt[PFCP].message_type == 5:  # PFCP Association Setup Request
                pass
            elif pkt[PFCP].message_type == 6:  # PFCP Association Setup Response
                pass
            elif pkt[PFCP].message_type == 50:  # PFCP Session Establishment Request
                # Target UPF IP
                pkt[PFCP].payload.IE_list[2][3][IE_FTEID].ipv4 = new_upf_ip
            elif pkt[PFCP].message_type == 51:  # PFCP Session Establishment Response
                pass
            elif pkt[PFCP].message_type == 52:  # PFCP Session Modification Request
                # gNB IP
                if upf_lb_ip is not None:
                    pkt[PFCP].payload.IE_list[2][IE_OuterHeaderCreation].ipv4 = upf_lb_ip
            if pkt[PFCP].message_type == 53:  # PFCP Session Modification Response
                pass
    wrpcap(outputfile, packets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="你應該要告訴 SMF、UPF LB、新 UPF 的 IP 和 MAC 位置 還有輸入輸出的檔案")
    parser.add_argument('-i', '--inputfile', type=str, required=False, default="pfcp.pcap", help='啊 是要從哪輸入？')
    parser.add_argument('-o', '--outputfile', type=str, required=True, help='啊 是要輸出到哪？')
    parser.add_argument('-sip', '--smfip', type=str, required=False, default="10.244.0.8",  help='啊 SMF IP 位置是多少？')
    parser.add_argument('-ulip', '--upflbip', type=str, required=False, default=None, help='啊 UPF-LB IP 位置是多少？')
    parser.add_argument('--newupfip', type=str, required=True,  help='啊 新 UPF IP 位置是多少？')
    parser.add_argument('--newupfmac', type=str, required=True, help='啊 新 UPF MAC 位置是多少？')

    args = parser.parse_args()

    modify_pfcp(inputfile=args.inputfile, outputfile=args.outputfile, smf_ip=args.smfip, new_upf_ip=args.newupfip, new_upf_mac=args.newupfmac, upf_lb_ip=args.upflbip)
