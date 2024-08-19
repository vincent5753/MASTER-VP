#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// === const ===
#define NO_INFO 0
#define SOME_INFO 1
#define MORE_INFO 2
#define ALL_INFO 3

#ifndef DEBUG_LEVEL
    // 0 -> No info
    // 1 -> some info
    // 2 -> LB info
    // 3 -> all info
    #define DEBUG_LEVEL NO_INFO
#endif

#define UPF_COUNT 1
#define EXUPF_COUNT 1
// L2
#define ETH_SRC_OFF offsetof(struct ethhdr, h_source)
#define ETH_DST_OFF offsetof(struct ethhdr, h_dest)
// L3
#define IP_HLEN sizeof(struct iphdr)
#define IP_SRC_OFF ETH_HLEN + offsetof(struct iphdr, saddr)
#define IP_DST_OFF ETH_HLEN + offsetof(struct iphdr, daddr)
#define IP_CSUM_OFFSET ETH_HLEN + offsetof(struct iphdr, check)
// L4
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define TCP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check)
#define UDP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check)

#define TCP_DPORT_OFF ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, dest)
#define UDP_DPORT_OFF ETH_HLEN + IP_HLEN + offsetof(struct udphdr, dest)

// 記得加 interface
struct interface {
    char name[10];
    const unsigned int ifnum;
    unsigned char mac[ETH_ALEN];
    __be32 ipv4;
};

struct interface lb_veth = {
.name = "LB", .ifnum = 11, .mac = {0xd6, 0x11, 0x16, 0xf5, 0x0d, 0xf4}, .ipv4 = 10 | (244 << 8) | (0 << 16) | (5 << 24)
};

struct interface fln_cn = {
.name = "FLN_CN", .ifnum = 4, .mac = {0xb6, 0x17, 0xe3, 0xd3, 0x0b, 0xe3}, .ipv4 = 10 | (244 << 8) | (0 << 16) | (5 << 24)
};

struct interface fln_ext1 = {
.name = "FLN_EXT1", .ifnum = 4, .mac = {0xc2, 0x5f, 0xf6, 0x65, 0x7c, 0x14}, .ipv4 = 10 | (244 << 8) | (1 << 16) | (2 << 24)
};

struct interface ext_upf1 = {
.name = "EX-UPF1", .ifnum = 6, .mac = {0x36, 0xc5, 0xd9, 0xc0, 0x74, 0xda}, .ipv4 = 10 | (244 << 8) | (1 << 16) | (2 << 24)
};

struct interface cni0 = {
.name = "CNI0-EU1", .ifnum = 5, .mac = {0x02, 0x8c, 0x3b, 0xd1, 0xf9, 0x3a}, .ipv4 = 10 | (244 << 8) | (1 << 16) | (2 << 24)
};


static __always_inline unsigned int fnat(struct __sk_buff *skb, struct iphdr *ip_h, struct interface *from, struct interface *to) {
    // 我們有關 rp_filter
    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_printk("- Full NAT\n");
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->saddr, 4, &from->ipv4, 4, csum);
    csum = bpf_csum_diff(&ip_h->daddr, 4, &to->ipv4, 4, csum);
    // ----- change L4 header -----
    if (ip_h->protocol == IPPROTO_TCP)
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    else if (ip_h->protocol == IPPROTO_UDP)
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
        // bpf_l4_csum_replace(skb, 0, 0, csum, 0);
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &from->ipv4, 4, 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &to->ipv4, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_SRC_OFF, &from->mac, 6, 0);
    bpf_skb_store_bytes(skb, ETH_DST_OFF, &to->mac, 6, 0);
    return csum;
}
