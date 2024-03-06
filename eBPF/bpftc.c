#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3
#define LB 4 
#define CLIENT 5
#define NTP 6

#define IP_SRC_OFF ETH_HLEN + offsetof(struct iphdr, saddr)
#define IP_DST_OFF ETH_HLEN + offsetof(struct iphdr, daddr)
#define IP_CSUM_OFFSET ETH_HLEN + offsetof(struct iphdr, check)
#define UDP_CSUM_OFF ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check)
// #define IS_PSEUDO 0x10

SEC("tc-info")
int cls_info(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = 0;
    ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-info]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("  Source[0]: %x\n", eth->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth->h_dest[5]);
    __u8 sipv4_0 = ip->saddr & 0xFF;
    __u8 sipv4_1 = (ip->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    __u8 dipv4_0 = ip->daddr & 0xFF;
    __u8 dipv4_1 = (ip->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);
    return BPF_OK;
}

SEC("tc-info-ingress")
int cls_info_in(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = 0;
    ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-info-ingress]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex);
    bpf_printk("  Source[0]: %x\n", eth->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth->h_dest[5]);
    __u8 sipv4_0 = ip->saddr & 0xFF;
    __u8 sipv4_1 = (ip->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    __u8 dipv4_0 = ip->daddr & 0xFF;
    __u8 dipv4_1 = (ip->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);
    return BPF_OK;
}

SEC("tc-info-egress")
int cls_info_e(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = 0;
    ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-info-egress]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex);
    bpf_printk("  Source[0]: %x\n", eth->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth->h_dest[5]);
    __u8 sipv4_0 = ip->saddr & 0xFF;
    __u8 sipv4_1 = (ip->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (ip->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (ip->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    __u8 dipv4_0 = ip->daddr & 0xFF;
    __u8 dipv4_1 = (ip->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (ip->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (ip->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);
    return BPF_OK;
}

SEC("tc-redirect")
int cls_redirect(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    // 建立 iphdr 資料結構
    struct iphdr *iph = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-redirect]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  Got packet from %x\n", iph->daddr);
    bpf_printk("  ifindex: %d\n", skb->ifindex);  // 收到容器的 ifindex?
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex);
    // 改寫封包
    // source 和 dst 先反著寫 // 這是因為 ingress 和 egress 掛反
        bpf_printk("  Source[0]: %x\n", eth->h_source[0]);
        bpf_printk("  Source[1]: %x\n", eth->h_source[1]);
        bpf_printk("  Source[2]: %x\n", eth->h_source[2]);
        bpf_printk("  Source[3]: %x\n", eth->h_source[3]);
        bpf_printk("  Source[4]: %x\n", eth->h_source[4]);
        bpf_printk("  Source[5]: %x\n", eth->h_source[5]);
        bpf_printk("  Destination[0]: %x\n", eth->h_dest[0]);
        bpf_printk("  Destination[1]: %x\n", eth->h_dest[1]);
        bpf_printk("  Destination[2]: %x\n", eth->h_dest[2]);
        bpf_printk("  Destination[3]: %x\n", eth->h_dest[3]);
        bpf_printk("  Destination[4]: %x\n", eth->h_dest[4]);
        bpf_printk("  Destination[5]: %x\n", eth->h_dest[5]);
        __u8 sipv4_0 = iph->saddr & 0xFF;
        __u8 sipv4_1 = (iph->saddr >> 8) & 0xFF;
        __u8 sipv4_2 = (iph->saddr >> 16) & 0xFF;
        __u8 sipv4_3 = (iph->saddr >> 24) & 0xFF;
        bpf_printk("  saddr[0]: %d\n", sipv4_0);
        bpf_printk("  saddr[1]: %d\n", sipv4_1);
        bpf_printk("  saddr[2]: %d\n", sipv4_2);
        bpf_printk("  saddr[3]: %d\n", sipv4_3);
        __u8 dipv4_0 = iph->daddr & 0xFF;
        __u8 dipv4_1 = (iph->daddr >> 8) & 0xFF;
        __u8 dipv4_2 = (iph->daddr >> 16) & 0xFF;
        __u8 dipv4_3 = (iph->daddr >> 24) & 0xFF;
        bpf_printk("  daddr[0]: %d\n", dipv4_0);
        bpf_printk("  daddr[1]: %d\n", dipv4_1);
        bpf_printk("  daddr[2]: %d\n", dipv4_2);
        bpf_printk("  daddr[3]: %d\n", dipv4_3);
    if (iph->saddr == IP_ADDRESS(CLIENT)) {
        // return TC_ACT_STOLEN;
        // source MAC/IP 改為 LB
        iph->saddr = IP_ADDRESS(LB);
        eth->h_source[5] = LB;
        // 轉給 BACKEND
        bpf_printk("  [Debug] to backend.\n");
        char be = BACKEND_A;  // BACKEND_A = nginx1
        // 獲取系統時間隨機選兩個後端送
        if (ts % 2) {
            // 送給 nginx 2 // 反著寫
            be = BACKEND_B;  // BACKEND_B = nginx2
            eth->h_dest[5] = LB;
            iph->daddr = IP_ADDRESS(LB);
            eth->h_source[5] = be;
            iph->saddr = IP_ADDRESS(be);
            iph->check = iph_csum(iph);
            bpf_printk("  [Debug] to nginx2!\n");
            return bpf_redirect(17, 1); // 這裡要改
        } else {
            // 送給 nginx1 // 反著寫
            eth->h_dest[5] = LB;
            iph->daddr = IP_ADDRESS(LB);
            eth->h_source[5] = be;
            iph->saddr = IP_ADDRESS(be);
            iph->check = iph_csum(iph);
            bpf_printk("  [Debug] to nginx1!\n");
            return bpf_redirect(15, 1); // 這裡要改
        }
    } else if (iph->saddr == IP_ADDRESS(LB)) {
        // 轉給 client
        bpf_printk("  [Debug] to client!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        // 反著寫
        iph->saddr = IP_ADDRESS(CLIENT);
        eth->h_source[5] = CLIENT;
        iph->daddr = IP_ADDRESS(LB);
        eth->h_dest[5] = LB;
        iph->check = iph_csum(iph);
        // return bpf_redirect(21, 0); // 這裡要改
        return bpf_redirect(21, 1); // 這裡要改
    }
    return BPF_OK; // 預設動作
}

SEC("tc-ntp")
int cls_ntp(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = bpf_ktime_get_ns();
    // __u32 rndnum = bpf_get_prandom_u32();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    // 建立 iphdr 資料結構
    struct iphdr *iph = data + sizeof(struct ethhdr);
    // 邊界檢查 如果封包比 eth+iphdr 小，別理它
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    // 建立 udphdr 資料結構
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // 邊界檢查 如果封包比 eth+iphdr+udphdr 小，別理它
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-ntp]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  Got packet from %x\n", iph->daddr); // 反著寫
    bpf_printk("  ifindex: %d\n", skb->ifindex);  // 收到容器的 ifindex
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex); // 從哪個介面轉過來的
    bpf_printk("  Source[0]: %x\n", eth->h_source[0]);
    bpf_printk("  Source[1]: %x\n", eth->h_source[1]);
    bpf_printk("  Source[2]: %x\n", eth->h_source[2]);
    bpf_printk("  Source[3]: %x\n", eth->h_source[3]);
    bpf_printk("  Source[4]: %x\n", eth->h_source[4]);
    bpf_printk("  Source[5]: %x\n", eth->h_source[5]);
    bpf_printk("  Destination[0]: %x\n", eth->h_dest[0]);
    bpf_printk("  Destination[1]: %x\n", eth->h_dest[1]);
    bpf_printk("  Destination[2]: %x\n", eth->h_dest[2]);
    bpf_printk("  Destination[3]: %x\n", eth->h_dest[3]);
    bpf_printk("  Destination[4]: %x\n", eth->h_dest[4]);
    bpf_printk("  Destination[5]: %x\n", eth->h_dest[5]);
    __u8 sipv4_0 = iph->saddr & 0xFF;
    __u8 sipv4_1 = (iph->saddr >> 8) & 0xFF;
    __u8 sipv4_2 = (iph->saddr >> 16) & 0xFF;
    __u8 sipv4_3 = (iph->saddr >> 24) & 0xFF;
    bpf_printk("  saddr[0]: %d\n", sipv4_0);
    bpf_printk("  saddr[1]: %d\n", sipv4_1);
    bpf_printk("  saddr[2]: %d\n", sipv4_2);
    bpf_printk("  saddr[3]: %d\n", sipv4_3);
    __u8 dipv4_0 = iph->daddr & 0xFF;
    __u8 dipv4_1 = (iph->daddr >> 8) & 0xFF;
    __u8 dipv4_2 = (iph->daddr >> 16) & 0xFF;
    __u8 dipv4_3 = (iph->daddr >> 24) & 0xFF;
    bpf_printk("  daddr[0]: %d\n", dipv4_0);
    bpf_printk("  daddr[1]: %d\n", dipv4_1);
    bpf_printk("  daddr[2]: %d\n", dipv4_2);
    bpf_printk("  daddr[3]: %d\n", dipv4_3);
    if (iph->saddr == IP_ADDRESS(CLIENT)) {
        // return TC_ACT_STOLEN;
        // 轉給 BACKEND
        bpf_printk("  [Debug] to Backend.\n");
        // 送給 NTP
        char be = NTP;
        eth->h_source[5] = LB;
        eth->h_dest[5] = be;
        // iph->saddr = IP_ADDRESS(LB);
        // iph->daddr = IP_ADDRESS(be);
        // iph->check = iph_csum(iph);

        // update checksum
        unsigned int lb_ip = 172 + (17 << 8) + (0 << 16) + (4 << 24);
        unsigned int ntp_ip = 172 + (17 << 8) + (0 << 16) + (6 << 24);
        unsigned int csum = 0;
        csum = bpf_csum_diff(&iph->saddr, 4, &lb_ip, 4, csum);
        csum = bpf_csum_diff(&iph->daddr, 4, &ntp_ip, 4, csum);
        long res = 0;
        // BPF_F_RECOMPUTE_CSUM
        res = bpf_skb_store_bytes(skb, IP_SRC_OFF, &lb_ip, 4, 0);
        if (res) {
            bpf_printk("IP SRC ERROR\n");
        }
        res = bpf_skb_store_bytes(skb, IP_DST_OFF, &ntp_ip, 4, 0);
        if (res) {
            bpf_printk("IP DST ERROR\n");
        }
        res = bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);  // 替換IP checksum | 好像不需要也可以過？
        if (res) {
            bpf_printk("IP checksum ERROR\n");
        }
        res = bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
        if (res) {
            bpf_printk("UDP checksum ERROR\n");
        }

        // 檢查是否已修改
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if (data + sizeof(struct ethhdr) > data_end){
            return BPF_OK;
        }
        iph = data + sizeof(struct ethhdr);
        // 邊界檢查 如果封包比 eth+iphdr 小，別理它
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
            return BPF_OK;
        }
        __u8 new_sipv4_0 = iph->saddr & 0xFF;
        __u8 new_sipv4_1 = (iph->saddr >> 8) & 0xFF;
        __u8 new_sipv4_2 = (iph->saddr >> 16) & 0xFF;
        __u8 new_sipv4_3 = (iph->saddr >> 24) & 0xFF;
        bpf_printk("  saddr[0]: %d\n", new_sipv4_0);
        bpf_printk("  saddr[1]: %d\n", new_sipv4_1);
        bpf_printk("  saddr[2]: %d\n", new_sipv4_2);
        bpf_printk("  saddr[3]: %d\n", new_sipv4_3);
        __u8 new_dipv4_0 = iph->daddr & 0xFF;
        __u8 new_dipv4_1 = (iph->daddr >> 8) & 0xFF;
        __u8 new_dipv4_2 = (iph->daddr >> 16) & 0xFF;
        __u8 new_dipv4_3 = (iph->daddr >> 24) & 0xFF;
        bpf_printk("  daddr[0]: %d\n", new_dipv4_0);
        bpf_printk("  daddr[1]: %d\n", new_dipv4_1);
        bpf_printk("  daddr[2]: %d\n", new_dipv4_2);
        bpf_printk("  daddr[3]: %d\n", new_dipv4_3);
        bpf_printk("  [Debug] to NTP!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        return bpf_redirect(63, 0); // 這裡要改？
    } else if (iph->saddr == IP_ADDRESS(NTP)) {
        // 轉給 client
        bpf_printk("  [Debug] to Client!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        eth->h_source[5] = LB;
        eth->h_dest[5] = CLIENT;
        // iph->saddr = IP_ADDRESS(LB);
        // iph->daddr = IP_ADDRESS(CLIENT);
        // iph->check = iph_csum(iph);

        // update checksum
        unsigned int client_ip = 172 + (17 << 8) + (0 << 16) + (5 << 24);
        unsigned int lb_ip = 172 + (17 << 8) + (0 << 16) + (4 << 24);
        unsigned int csum = 0;
        csum = bpf_csum_diff(&iph->saddr, 4, &lb_ip, 4, csum);
        csum = bpf_csum_diff(&iph->daddr, 4, &client_ip, 4, csum);
        long res = 0;
        res = bpf_skb_store_bytes(skb, IP_SRC_OFF, &lb_ip, 4, BPF_F_RECOMPUTE_CSUM);
        if (res) {
            bpf_printk("IP SRC ERROR\n");
        }
        res = bpf_skb_store_bytes(skb, IP_DST_OFF, &client_ip, 4, BPF_F_RECOMPUTE_CSUM);
        if (res) {
            bpf_printk("IP DST ERROR\n");
        }
        res = bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
        if (res) {
            bpf_printk("IP checksum ERROR\n");
        }
        res = bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
        if (res) {
            bpf_printk("UDP checksum ERROR\n");
        }

        // 檢查是否已修改
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if (data + sizeof(struct ethhdr) > data_end){
            return BPF_OK;
        }
        iph = data + sizeof(struct ethhdr);
        // 邊界檢查 如果封包比 eth+iphdr 小，別理它
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
            return BPF_OK;
        }
        __u8 new_sipv4_0 = iph->saddr & 0xFF;
        __u8 new_sipv4_1 = (iph->saddr >> 8) & 0xFF;
        __u8 new_sipv4_2 = (iph->saddr >> 16) & 0xFF;
        __u8 new_sipv4_3 = (iph->saddr >> 24) & 0xFF;
        bpf_printk("  saddr[0]: %d\n", new_sipv4_0);
        bpf_printk("  saddr[1]: %d\n", new_sipv4_1);
        bpf_printk("  saddr[2]: %d\n", new_sipv4_2);
        bpf_printk("  saddr[3]: %d\n", new_sipv4_3);
        __u8 new_dipv4_0 = iph->daddr & 0xFF;
        __u8 new_dipv4_1 = (iph->daddr >> 8) & 0xFF;
        __u8 new_dipv4_2 = (iph->daddr >> 16) & 0xFF;
        __u8 new_dipv4_3 = (iph->daddr >> 24) & 0xFF;
        bpf_printk("  daddr[0]: %d\n", new_dipv4_0);
        bpf_printk("  daddr[1]: %d\n", new_dipv4_1);
        bpf_printk("  daddr[2]: %d\n", new_dipv4_2);
        bpf_printk("  daddr[3]: %d\n", new_dipv4_3);
        return bpf_redirect(21, 0); // 這裡要改？
    }
    return BPF_OK; // 預設動作
}

char _license[] SEC("license") = "GPL";
