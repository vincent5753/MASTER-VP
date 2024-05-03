#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include "gtp5g-gtpu.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1000);
} hash_map_4_traffic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1000);
} hash_map_4_ip SEC(".maps");

SEC("counter")
int pkgcounter(struct __sk_buff *skb) {
    /* ===== Parsor ===== */
    // 建立封包結構
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ----- Ethernet II (DIX Frame) -----
    struct ethhdr *eth = data;
    // bounds checking
    if (data + sizeof(struct ethhdr) > data_end)
        return BPF_OK;
    // not ip protocol
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return BPF_OK;

    // ----- IPv4 -----
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // bounds checking
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return BPF_OK;

    // ----- UDP -----
    // 建立 udphdr 資料結構
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // 邊界檢查 如果封包比 eth+iphdr+udphdr 小，別理它
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return BPF_OK;
    if (udph->dest != ntohs(2152))
        return BPF_OK;
    struct gtpv1_5gc *gtpv1_5gc = (void*)udph + sizeof(*udph);
    if ((void*)gtpv1_5gc + sizeof(*gtpv1_5gc) > data_end)
        return BPF_OK;

    struct iphdr *ip2 = (void*)gtpv1_5gc + sizeof(*gtpv1_5gc);
    if ((void*)ip2 + sizeof(*ip2) > data_end)
        return BPF_OK;

    /* ===== Process ===== */
    int *valueptr;
    uint64_t initval = skb->len;
    int key = ntohs(ip2->daddr);

    // ----- save ip -----
    valueptr = bpf_map_lookup_elem(&hash_map_4_ip, &key);
    if (!valueptr)
        bpf_map_update_elem(&hash_map_4_ip, &key, &key, BPF_ANY);
    // ----- save length -----
    valueptr = bpf_map_lookup_elem(&hash_map_4_traffic, &key);
    if (!valueptr)
        bpf_map_update_elem(&hash_map_4_traffic, &key, &initval, BPF_ANY);
    else
        __sync_fetch_and_add(valueptr, initval);
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
