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

SEC("tc-info")
int cls_info(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 ts = 0;
    ts = bpf_ktime_get_ns();
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊際檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // 我們只處理 IP 封包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // 我們只處理 IP 封包
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    bpf_printk("[tc-info]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  ifindex: %d\n", skb->ifindex);
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex);
    bpf_printk("  local_ip4: %d\n",skb->local_ip4);
    bpf_printk("  remote_ip4: %d\n",skb->remote_ip4);
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
    // 邊際檢查，如果封包比 ethhdr 小，別理它
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
    bpf_printk("[tc-redirect]\n");
    bpf_printk("  timestamp: %llu\n", ts);
    bpf_printk("  Got packet from %x\n", iph->daddr);
    bpf_printk("  ifindex: %d\n", skb->ifindex);  // 收到容器的 ifindex?
    bpf_printk("  ingress_ifindex: %d\n",skb->ingress_ifindex);
    // 改寫封包
    // source 和 dst 先反著寫
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
    if (iph->daddr == IP_ADDRESS(CLIENT)) {
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

char _license[] SEC("license") = "GPL";
