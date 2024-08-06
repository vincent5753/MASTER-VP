#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>

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

char __license[] SEC("license") = "GPL";
