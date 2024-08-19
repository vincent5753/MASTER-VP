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
#include "myhelper.h"
// #include <netinet/in.h>

struct connect {
    __be32  saddr;
    __be32  daddr;
    __u8    proto;
    __be16  sport;
    __be16  dport;
};
// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, struct connect);
//   __type(value, unsigned int);
//   __uint(max_entries, 16);
// } connect_map SEC(".maps");

// --- ori socket info ---
struct bpf_map_def SEC("maps") connect_map = {
    .type=BPF_MAP_TYPE_HASH,
    .key_size=sizeof(struct connect),
    .value_size=sizeof(unsigned int),
    .max_entries=64
};

// struct bpf_map_def SEC("maps") count_map = {
//     .type=BPF_MAP_TYPE_ARRAY,
//     .key_size=sizeof(unsigned int),
//     .value_size=sizeof(unsigned int),
//     .max_entries=1
// };


SEC("ingress_info")
int tc_ingress_info(struct __sk_buff *skb) {
    // ===== Parse ====
    void * data = (void *)(long)skb->data;
    void * data_end = (void *)(long)skb->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return BPF_OK;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // // ----- UDP -----
    // // Not UDP
    // if (ip_h->protocol != IPPROTO_UDP)
    //     return BPF_OK;
    // if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)
    //     return BPF_OK;
    // struct udphdr * udp_h = (void *)ip_h + IP_HLEN;
    // // Not UE to gNB health check
    // if (bpf_ntohs(udp_h->source) == 4997 || bpf_ntohs(udp_h->dest) == 4997)
    //     return BPF_OK;
    // // ----- GTP-U -----
    // // Not GTP-U
    // if (bpf_ntohs(udp_h->source) != 2152 && bpf_ntohs(udp_h->source) != 2152)
    //     return BPF_OK;
    // if ((void *)udp_h + UDP_HLEN + sizeof(struct gtphdr) > data_end)   // size check
    //     return BPF_OK;
    // struct gtphdr * gtp_h = (void *)udp_h + UDP_HLEN;
    // // GTP-U extension header
    // if ((void *)gtp_h + sizeof(struct gtphdr) + sizeof(struct gtp_exhdr_pdu_session_container) > data_end)   // size check
    //     return BPF_OK;
    // struct gtp_exhdr_pdu_session_container * gtp_exh = (void *)gtp_h + sizeof(struct gtphdr);
    // // ----- IP -----
    // if ((void *)gtp_exh + sizeof(struct gtp_exhdr_pdu_session_container) + IP_HLEN > data_end)  // size check
    //     return BPF_OK;
    // struct iphdr * ip_h_2 = (void *)gtp_exh + sizeof(struct gtp_exhdr_pdu_session_container);

    // ===== Process =====
    // ===== Info =====
    if (DEBUG_LEVEL >= SOME_INFO) {
        int find_flag = 0;
        for (int i=0; i<UPF_COUNT; i++) {
            if (skb->ingress_ifindex == upf_veth[i].ifnum) {
                bpf_printk("=== %s TC ingress ===\n", upf_veth[i].name);
                find_flag = 1;
            }
        }
        if (find_flag == 0 && skb->ingress_ifindex == lb_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", lb_veth.name);
        else if (find_flag == 0 && skb->ingress_ifindex == gnb_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", gnb_veth.name);
        else if (find_flag == 0 && skb->ingress_ifindex == ue_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", ue_veth.name);
        else if (find_flag == 0 && skb->ingress_ifindex == cni0_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", cni0_veth.name);
        else if (find_flag == 0 && skb->ingress_ifindex == ens18_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", ens18_veth.name);
        else if (find_flag == 0)
            bpf_printk("=== unknown TC ingress ===\n");
        if (DEBUG_LEVEL >= ALL_INFO) {
            bpf_printk("from ifnum: %d\n", skb->ingress_ifindex);
            bpf_printk("to ifnum: %d\n", skb->ifindex);
            // echo_mac(eth_h);
            echo_ipv4(ip_h);
            // echo_udp(udp_h);
            // echo_gtp(gtp_h);
            // echo_ipv4(ip_h_2);
        }
    }
    return BPF_OK;
}

SEC("egress_info")
int tc_egress_info(struct __sk_buff *skb) {
    // ===== Parse ====
    void * data = (void *)(long)skb->data;
    void * data_end = (void *)(long)skb->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return BPF_OK;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // // ----- UDP -----
    // // Not UDP
    // if (ip_h->protocol != IPPROTO_UDP)
    //     return BPF_OK;
    // if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)
    //     return BPF_OK;
    // struct udphdr * udp_h = (void *)ip_h + IP_HLEN;
    // // Not UE to gNB health check
    // if (bpf_ntohs(udp_h->source) == 4997 || bpf_ntohs(udp_h->dest) == 4997)
    //     return BPF_OK;
    // // ----- GTP-U -----
    // // Not GTP-U
    // if (bpf_ntohs(udp_h->source) != 2152 && bpf_ntohs(udp_h->source) != 2152)
    //     return BPF_OK;
    // if ((void *)udp_h + UDP_HLEN + sizeof(struct gtphdr) > data_end)   // size check
    //     return BPF_OK;
    // struct gtphdr * gtp_h = (void *)udp_h + UDP_HLEN;
    // // GTP-U extension header
    // if ((void *)gtp_h + sizeof(struct gtphdr) + sizeof(struct gtp_exhdr_pdu_session_container) > data_end)   // size check
    //     return BPF_OK;
    // struct gtp_exhdr_pdu_session_container * gtp_exhdr = (void *)gtp_h + sizeof(struct gtphdr);
    // // ----- IP -----
    // if ((void *)gtp_exhdr + sizeof(struct gtp_exhdr_pdu_session_container) + IP_HLEN > data_end)  // size check
    //     return BPF_OK;
    // struct iphdr * ip_h_2 = (void *)gtp_exhdr + sizeof(struct gtp_exhdr_pdu_session_container);

    // ===== Process =====
    // ===== Info =====
    if (DEBUG_LEVEL >= SOME_INFO) {
        int find_flag = 0;
        for (int i=0; i<UPF_COUNT; i++) {
            if (skb->ifindex == upf_veth[i].ifnum) {
                bpf_printk("=== %s TC egress ===\n", upf_veth[i].name);
                find_flag = 1;
            }
        }
        if (find_flag == 0 && skb->ifindex == lb_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", lb_veth.name);
        else if (find_flag == 0 && skb->ifindex == gnb_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", gnb_veth.name);
        else if (find_flag == 0 && skb->ifindex == ue_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", ue_veth.name);
        else if (find_flag == 0 && skb->ifindex == cni0_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", cni0_veth.name);
        else if (find_flag == 0 && skb->ifindex == ens18_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", ens18_veth.name);
        else if (find_flag == 0)
            bpf_printk("=== unknown TC egress ===\n");
        if (DEBUG_LEVEL >= ALL_INFO) {
            bpf_printk("from ifnum: %d\n", skb->ingress_ifindex);
            bpf_printk("to ifnum: %d\n", skb->ifindex);
            // echo_mac(eth_h);
            echo_ipv4(ip_h);
            // echo_udp(udp_h);
            // echo_gtp(gtp_h);
            // echo_ipv4(ip_h_2);
        }
    }
    return BPF_OK;
}


SEC("load_balance_egress")
int tc_load_balance_egress(struct __sk_buff *skb) {
    // ===== Parse ====
    void * data = (void *)(long)skb->data;
    void * data_end = (void *)(long)skb->data_end;
    // ----- Etherne    t Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return BPF_OK;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // ----- UDP -----
    // Not UDP
    if (ip_h->protocol != IPPROTO_UDP)
        return BPF_OK;
    if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)  // size check
        return BPF_OK;
    struct udphdr * udp_h = (void *)ip_h + IP_HLEN;

    // ----- GTP-U -----
    if ((void *)udp_h + UDP_HLEN + sizeof(struct gtphdr) > data_end)   // size check
        return BPF_OK;
    struct gtphdr * gtp_h = (void *)udp_h + UDP_HLEN;
    // GTP-U extension header
    if ((void *)gtp_h + sizeof(struct gtphdr) + sizeof(struct gtp_exhdr_pdu_session_container) > data_end)   // size check
        return BPF_OK;
    struct gtp_exhdr_pdu_session_container * gtp_exhdr = (void *)gtp_h + sizeof(struct gtphdr);
    // ----- IP -----
    if ((void *)gtp_exhdr + sizeof(struct gtp_exhdr_pdu_session_container) + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h_2 = (void *)gtp_exhdr + sizeof(struct gtp_exhdr_pdu_session_container);

    // ===== Process =====
    struct interface * target = NULL;
    // unsigned int target_ifnum = 0;
    // from A -> lb to lb -> B
    if (ip_h->saddr == gnb_veth.ipv4 && ip_h->daddr == lb_veth.ipv4) {

        unsigned int upf_index = bpf_get_prandom_u32() % UPF_COUNT;
        switch (upf_index) {
            case 0:
//                bpf_printk("UPF 1\n");
                target = &upf_veth[0];  // 哈扣，記得要改，很重要
                break;
            case 1:
//                bpf_printk("UPF 2\n");
                target = &upf_veth[1];  // 哈扣，記得要改，很重要
                break;
            case 2:
//                bpf_printk("UPF 3\n");
                target = &upf_veth[2];  // 哈扣，記得要改，很重要
                break;
            default:
//                bpf_printk("UPF unknown\n");
                target = &upf_veth[0];  // 哈扣，記得要改，很重要
                break;
        }

        // target = &upf_veth[2];  // 哈扣，記得要改，很重要
        fnat(skb, ip_h, &lb_veth, target);
    }
    // from B -> lb to lb -> A
    else if (ip_h->daddr == lb_veth.ipv4) {
        for (int i=0; i<UPF_COUNT; i++) {
            if (ip_h->saddr == upf_veth[i].ipv4) {
                target = &gnb_veth;
                fnat(skb, ip_h, &lb_veth, target);
                break;
            }
        }
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

    if (target == NULL)
        return BPF_OK;
    else
        return bpf_redirect(target->ifnum, 0);
}


SEC("cni0_bonding_ingress")
int tc_cni0_bonding_ingress(struct __sk_buff *skb) {
    // ===== Parse ====
    void * data = (void *)(long)skb->data;
    void * data_end = (void *)(long)skb->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return BPF_OK;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // ----- UDP -----
    // Not UDP
    // if (ip_h->protocol != IPPROTO_UDP)
    //     return BPF_OK;
    // if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)  // size check
    //     return BPF_OK;
    // struct udphdr * udp_h = (void *)ip_h + IP_HLEN;
    // echo_ipv4(ip_h);
    if (DEBUG_LEVEL >= 0) {
        bpf_printk("=== cni0 TC ingress ===\n");
        bpf_printk("from ifnum: %d\n", skb->ingress_ifindex);
        bpf_printk("to ifnum: %d\n", skb->ifindex);
        echo_ipv4(ip_h);
    }

    // ===== Process =====
    // ===== Info =====
    for (int i=0; i<UPF_COUNT; i++) {
        if (ip_h->saddr == upf_veth[i].ipv4) {
            snat(skb, ip_h, &upf_veth[0]);
            break;
        }
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
    // ===== Info =====
    if (DEBUG_LEVEL >= 0) {
        // echo_mac(eth_h);
        echo_ipv4(ip_h);
        // echo_udp(udp_h);
    }

    return BPF_OK;
}


SEC("cni0_bonding_egress")
int tc_cni0_bonding_egress(struct __sk_buff *skb) {
    // ===== Parse ====
    void * data = (void *)(long)skb->data;
    void * data_end = (void *)(long)skb->data_end;
    // ----- Ethernet Frame -----
    if (data + ETH_HLEN > data_end)   // size check
        return BPF_OK;
    struct ethhdr * eth_h = data;
    // ----- IPv4 -----
    // Not IP Packet
    if (bpf_ntohs(eth_h->h_proto) != ETH_P_IP)
        return BPF_OK;
    if ((void *)eth_h + ETH_HLEN + IP_HLEN > data_end)  // size check
        return BPF_OK;
    struct iphdr * ip_h = (void *)eth_h + ETH_HLEN;
    // ----- UDP -----
    // Not UDP
    // if (ip_h->protocol != IPPROTO_UDP)
    //     return BPF_OK;
    // if ((void *)ip_h + IP_HLEN + UDP_HLEN > data_end)  // size check
    //     return BPF_OK;
    // struct udphdr * udp_h = (void *)ip_h + IP_HLEN;
    // echo_ipv4(ip_h);
    if (DEBUG_LEVEL >= 0) {
        bpf_printk("=== cni0 TC egress ===\n");
        bpf_printk("from ifnum: %d\n", skb->ingress_ifindex);
        bpf_printk("to ifnum: %d\n", skb->ifindex);
        echo_ipv4(ip_h);
    }

    // ===== Process =====
    // ===== Info =====
    for (int i=0; i<UPF_COUNT; i++) {
        if (ip_h->daddr == upf_veth[i].ipv4) {
            dnat(skb, ip_h, &upf_veth[0]);
            break;
        }
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
    // ===== Info =====
    if (DEBUG_LEVEL >= 0) {
        // echo_mac(eth_h);
        echo_ipv4(ip_h);
        // echo_udp(udp_h);
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
