#include <linux/bpf.h>  // XDP_PASS, ...
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>  // SEC, bpf_printk
#include "myhelper.h"


SEC("xdp_info")
int xdp_ingress_info(struct xdp_md *ctx) {
    // ===== Parse =====
    void * data = (void *)(long)ctx->data;
    void * data_end = (void *)(long)ctx->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return XDP_PASS;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return XDP_PASS;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return XDP_PASS;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // ----- UDP -----
    // if (ip_h->protocol != IPPROTO_UDP)
    //     return XDP_PASS;
    // if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)
    //     return XDP_PASS;
    // struct udphdr * udp_h = (void *)ip_h + IP_HLEN;
    // if (bpf_ntohs(udp_h->source) == 4997 || bpf_ntohs(udp_h->dest) == 4997)
    //     return XDP_PASS;

    // ===== Process =====
    // ===== Info =====
    if (DEBUG_LEVEL >= SOME_INFO) {
        int find_flag = 0;
        for (int i=0; i<UPF_COUNT; i++) {
            if (ctx->ingress_ifindex == upf_veth[i].ifnum) {
                bpf_printk("=== %s XDP ===\n", upf_veth[i].name);
                find_flag = 1;
            }
        }
        if (find_flag == 0 && ctx->ingress_ifindex == lb_veth.ifnum)
            bpf_printk("=== %s XDP ===\n", lb_veth.name);
        else if (find_flag == 0 && ctx->ingress_ifindex == gnb_veth.ifnum)
            bpf_printk("=== %s XDP ===\n", gnb_veth.name);
        else if (find_flag == 0 && ctx->ingress_ifindex == ue_veth.ifnum)
            bpf_printk("=== %s XDP ===\n", ue_veth.name);
        else if (find_flag == 0){
            bpf_printk("=== unknown XDP ===\n");
            bpf_printk("%d\n", ctx->ingress_ifindex);
        }
        if (DEBUG_LEVEL >= ALL_INFO) {
            // echo_mac(eth_h);
            echo_ipv4(ip_h);
            // echo_udp(udp_h);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
