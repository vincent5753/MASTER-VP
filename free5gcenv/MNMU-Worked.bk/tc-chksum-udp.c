#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/gtp.h>
// #include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include <netinet/in.h>
#include "myhelper-lite.h"

SEC("tc-chksum")
int tc_chksum(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    // __u64 ts = 0;
    // ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-chksum]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    if (ip_h->protocol != IPPROTO_UDP) {
        bpf_printk("Packet Passed without any modify!\n");
        return BPF_OK;
    }

    struct udphdr *udp_h = (void*)ip_h + sizeof(*ip_h);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        return BPF_OK;
    }

    // 等等加轉發

    struct interface * target = NULL;
    target = &cni0;
    // unsigned int target_ifnum = 0;
    // from A -> lb to lb -> B

    // bpf_printk("[Debug] MAC\n");
    // bpf_printk("  [Debug] MAC-SRC\n");
    // bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    // bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    // bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    // bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    // bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    // bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    // bpf_printk("  [Debug] MAC-CN\n");
    // bpf_printk("  Source[0]: %x\n", fln_cn.mac[0]);
    // bpf_printk("  Source[1]: %x\n", fln_cn.mac[1]);
    // bpf_printk("  Source[2]: %x\n", fln_cn.mac[2]);
    // bpf_printk("  Source[3]: %x\n", fln_cn.mac[3]);
    // bpf_printk("  Source[4]: %x\n", fln_cn.mac[4]);
    // bpf_printk("  Source[5]: %x\n", fln_cn.mac[5]);

    // Kinda ugly but worked :)
    if ( eth_h->h_source[0] == fln_cn.mac[0] && eth_h->h_source[1] == fln_cn.mac[1] && eth_h->h_source[2] == fln_cn.mac[2] && eth_h->h_source[3] == fln_cn.mac[3] && eth_h->h_source[4] == fln_cn.mac[4] && eth_h->h_source[5] == fln_cn.mac[5]){
        bpf_printk("[Debug] MAC from CN flannel.\n");
    }
    // bpf_printk("[Debug] IP\n");
    if (ip_h->saddr == lb_veth.ipv4){
        bpf_printk("[Debug] IP from CN LB.\n");
    }
    // bpf_printk("  [Debug] IP of SRC: %x\n", ip_h->saddr);
    // bpf_printk("  [Debug] IP of lb_veth.ipv4: %x\n", lb_veth.ipv4);

    if ( eth_h->h_source[0] == fln_cn.mac[0] && eth_h->h_source[1] == fln_cn.mac[1] && eth_h->h_source[2] == fln_cn.mac[2] && eth_h->h_source[3] == fln_cn.mac[3] && eth_h->h_source[4] == fln_cn.mac[4] && eth_h->h_source[5] == fln_cn.mac[5] && ip_h->saddr == lb_veth.ipv4){
        bpf_printk("Got 1 from CN with IP of LB.\n");
        // MAC -> SRC: flannel.1 DST: Ext-UPF
        // IP -> SRC: UPF-LB DST: Ext-UPF (just don't touch it)

        // Kinda ugly but worked :)
        eth_h->h_source[0] = fln_ext1.mac[0];
        eth_h->h_source[1] = fln_ext1.mac[1];
        eth_h->h_source[2] = fln_ext1.mac[2];
        eth_h->h_source[3] = fln_ext1.mac[3];
        eth_h->h_source[4] = fln_ext1.mac[4];
        eth_h->h_source[5] = fln_ext1.mac[5];
        eth_h->h_dest[0] = ext_upf1.mac[0];
        eth_h->h_dest[1] = ext_upf1.mac[1];
        eth_h->h_dest[2] = ext_upf1.mac[2];
        eth_h->h_dest[3] = ext_upf1.mac[3];
        eth_h->h_dest[4] = ext_upf1.mac[4];
        eth_h->h_dest[5] = ext_upf1.mac[5];
    }

    // ===== Parse ====
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    eth_h = data;
    // ----- IPv4 -----
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    ip_h = (void *)eth_h + ETH_HLEN;
    // ----- UDP -----
    if (ip_h->protocol != IPPROTO_UDP)
        return BPF_OK;
    else if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)
        return BPF_OK;
    udp_h = (void *)ip_h + IP_HLEN;

    // bpf_printk("  UDP CHKSUM AFT: %d\n", udp_h->check);
    // bpf_printk("Packet CHKSUM Recomputerd!");

    return bpf_redirect(target->ifnum, 0);

    return BPF_OK;
}

SEC("tc-info-ingress")
int tc_info_i(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-ingress]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-egress")
int tc_info_e(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-egress]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-ingress-cni0")
int tc_info_i_c(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-ingress-cni0]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-egress-cni0")
int tc_info_e_c(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-egress-cni0]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-ingress-upf")
int tc_info_i_u(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-ingress-upf]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-egress-upf")
int tc_info_e_u(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-egress-upf]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-ingress-flannel")
int tc_info_i_f(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-ingress-flannel]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

SEC("tc-info-egress-flannel")
int tc_info_e_f(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 建立 ethhdr 資料結構
    struct ethhdr *eth_h = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip_h = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }

    bpf_printk("[tc-info-egress-flannel]\n");
    // bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("MAC\n");
    bpf_printk("  Source[0]: %x\n", eth_h->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth_h->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth_h->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth_h->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth_h->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth_h->h_dest[5]);
    bpf_printk("IP\n");
    bpf_printk("SRC in dec raw: %d\n", ip_h->saddr);
    bpf_printk("SRC in hex raw: %x\n", ip_h->saddr);
    __u8 sipv4_0 = ip_h->saddr & 0xFF;
    __u8 sipv4_1 = (ip_h->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip_h->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip_h->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    bpf_printk("DST in dec raw: %d\n", ip_h->daddr);
    bpf_printk("DST in hex raw: %x\n", ip_h->daddr);
    __u8 dipv4_0 = ip_h->daddr & 0xFF;
    __u8 dipv4_1 = (ip_h->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip_h->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip_h->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
