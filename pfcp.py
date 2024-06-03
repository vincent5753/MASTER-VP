#from scapy.all import rdpcap
import json
from scapy.all import *
from scapy.contrib.pfcp import *
import colorama
from colorama import Fore, Style

SMF_IP = "10.244.0.10"
SMF_MAC = "9e:c2:16:37:dd:59"
UPF_LB_IP = "10.244.0.7"            # IP  of UPF-1
UPF_LB_MAC = "ee:02:72:2a:bb:d6"    # MAC of UPF-1
UPF1_IP = "10.244.0.19"
UPF1_MAC = "f2:8b:63:04:1a:6a"
UPF2_IP = ""
UPF2_MAC = ""
UPF3_IP = ""
UPF3_MAC = ""

class color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'
# ref: https://stackoverflow.com/questions/39473297/how-do-i-print-colored-output-with-python-3#:~:text=Since%20Python%20is%20interpreted%20and%20run%20in%20C%2C%20it%20is%20possible%20to%20set%20colors%20without%20a%20module.

def packet_to_json(packet):
    """Converts a Scapy packet to a JSON-like structure."""
    packet_dict = {}
    current_layer = None

    # Iterate over lines of output from packet.show2(dump=True)
    for line in packet.show2(dump=True).split('\n'):
        line = line.strip()
        
        # Detect layer start/end
        if line.startswith('###'):
            current_layer = line.strip('#[] ')
            packet_dict[current_layer] = {}
        # Detect field and value
        elif line and '=' in line:
            key, value = line.split('=', 1)
            packet_dict[current_layer][key.strip()] = value.strip()
    
    # Return the JSON-like structure
    return packet_dict

# 讀取 PCAP
packets = rdpcap('pfcp.pcap')
# print("<<< 開始 >>>")
for packet in packets:
#    print(packet.summary())
#    print(packet.show())
    # someinfo = packet.show(dump=True)
    # print(someinfo)
    # if IP in packet:
    #     # print(packet[IP].src)
    #     # print(packet[IP].dst)
    # if UDP in packet:
    #     print(packet[UDP].sport)
    #     print(packet[UDP].dport)
    
    if PFCP in packet:
        #print(packet[PFCP].version)

        #  第一包 Resquest
        if packet[PFCP].message_type == 5:
            print(color.YELLOW + "<PFCP Association Setup Request>" + color.END)
            print("  Node ID -> IPv4 (SMF IP)")
            print("    " + packet[PFCP].IE_list[0].ipv4)
            print()

        if packet[PFCP].message_type == 6:
            print("<PFCP Association Setup Response>")
            # print(packet[PFCP].IE_list[0].show)
            print("  Node ID -> Type (UPF)")
            print("    " + str(packet[PFCP].IE_list[0].id_type))
            print("  Node ID -> ID (UPF)")
            print("    " + str(packet[PFCP].IE_list[0].id.decode('ascii')))
            print()

        #  第二包 Resquest
        if packet[PFCP].message_type == 50:
            print(color.YELLOW + "<PFCP Session Establishment Request>"+ color.END)
            print("  Node ID -> IPv4 (SMF IP)")
            print("    " + packet[PFCP].payload.IE_list[0][0].ipv4)
            print("  F-SEID -> IPv4 (SMF IP)")
            print("    " + packet[PFCP].payload.IE_list[1][0].ipv4)
            print("  Create PDR -> PDI -> F-TEID (Target UPF IP -> New UPF)")
            print(color.YELLOW + "    " + packet[PFCP].payload.IE_list[2][3][IE_FTEID].ipv4 + color.END)
            packet[PFCP].payload.IE_list[2][3][IE_FTEID].ipv4 = UPF1_IP
            print(color.GREEN + "    " + packet[PFCP].payload.IE_list[2][3][IE_FTEID].ipv4 + color.END)
            print("  Create PDR -> PDI -> UE IP Address (UE IP)")
            print("    " + packet[PFCP].payload.IE_list[2][3][IE_UE_IP_Address].ipv4 + color.END)
            print("  Create PDR -> PDI -> UE IP Address (UE IP)")
            print("    " + packet[PFCP].payload.IE_list[3][3][IE_UE_IP_Address].ipv4 + color.END)
            print()

        if packet[PFCP].message_type == 51:
            print("<PFCP Session Establishment Response>")
            print("  Node ID -> FQDN (UPF FQDN)")
            print("    " + str(packet[PFCP].payload.IE_list[0].id.decode("ascii")) + color.END)
            print()

        #  第三包 Resquest
        if packet[PFCP].message_type == 52:
            print(color.YELLOW + "<PFCP Session Modification Request>" + color.END)
            print("  F-SEID -> IPv4 (SMF IP)")
            print("    " + packet[PFCP].payload.IE_list[0].ipv4)
            print("  Update PDR -> PDI -> UE IP Address -> IPv4 (UE IP)")
            print("    " + packet[PFCP].payload.IE_list[1][3][3].ipv4)
            print("  Update FAR -> Update Forwarding Parameters -> Outer Header Creation -> IPv4 (gNB IP -> UPF_LB)")
            print(color.YELLOW + "    " + packet[PFCP].payload.IE_list[2][IE_OuterHeaderCreation].ipv4 + color.END)
            packet[PFCP].payload.IE_list[2][IE_OuterHeaderCreation].ipv4 = UPF_LB_IP
            print(color.GREEN + "    " + packet[PFCP].payload.IE_list[2][IE_OuterHeaderCreation].ipv4 + color.END)
            print()

        if packet[PFCP].message_type == 53:
            print("<PFCP Session Modification Response>")
            print()
