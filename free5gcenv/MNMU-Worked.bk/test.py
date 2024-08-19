import scapy.all as scapy

def send_icmp_ping(target_ip, interface):
  """Sends an ICMP echo request to the specified target IP using the specified interface."""
  packet = scapy.IP(dst=target_ip)/scapy.ICMP()
  scapy.sendp(packet, iface=interface, verbose=False)

if __name__ == "__main__":
  target_ip = "10.244.1.2"
  interface = "cni0"
  send_icmp_ping(target_ip, interface)
