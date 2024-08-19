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
    if (DEBUG_LEVEL >= SOME_INFO && (ip_h->saddr == exupf_veth[0].ipv4 || ip_h->daddr == exupf_veth[0].ipv4)) {
        if (skb->ingress_ifindex == lb_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", lb_veth.name);
        else if (skb->ingress_ifindex == gnb_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", gnb_veth.name);
        else if (skb->ingress_ifindex == ue_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", ue_veth.name);
        else if (skb->ingress_ifindex == cni0_veth.ifnum)
            bpf_printk("=== %s TC ingress ===\n", cni0_veth.name);
        else if (skb->ingress_ifindex == ens18_cn.ifnum)
            bpf_printk("=== %s TC ingress ===\n", ens18_cn.name);
        else
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
    if (DEBUG_LEVEL >= SOME_INFO && (ip_h->saddr == exupf_veth[0].ipv4 || ip_h->daddr == exupf_veth[0].ipv4)) {
        if (skb->ifindex == lb_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", lb_veth.name);
        else if (skb->ifindex == gnb_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", gnb_veth.name);
        else if (skb->ifindex == ue_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", ue_veth.name);
        else if (skb->ifindex == cni0_veth.ifnum)
            bpf_printk("=== %s TC egress ===\n", cni0_veth.name);
        else if (skb->ifindex == ens18_cn.ifnum)
            bpf_printk("=== %s TC egress ===\n", ens18_cn.name);
        else
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


SEC("egress_redirect")
int tc_egress_redirect(struct __sk_buff *skb) {
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

    if (DEBUG_LEVEL >= SOME_INFO) {
        bpf_printk("=== LB TC egress ===\n");
        if (DEBUG_LEVEL >= MORE_INFO) {
            // echo_mac(eth_h);
            echo_ipv4(ip_h);
            // echo_udp(udp_h);
        }
    }

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

    if (DEBUG_LEVEL >= ALL_INFO) {
        // echo_gtp(gtp_h);
        echo_ipv4(ip_h_2);
    }

    // ===== Process =====
    struct interface * target = NULL;
    // unsigned int target_ifnum = 0;
    // from A -> LB / "LB -> CNI0" / CNI0 -> flannel.1 / flannel.1 -> B
    // L2 MAC  SRC LB_MAC / DST CNI0_MAC
    // L3  IP  SRC LB_IP / DST Ext_UPF_IP
    // 所以我直接把 CNI0 的 IP 改成 Ext_UPF_IP (10.244.1.2)，然後 MAC 不變(同 host 上 veth 那個)
    if (udp_h->dest == bpf_ntohs(2152)) {
        bpf_printk("[bpf_ntohs] it's GTP-U :) \n");
    }
    if (udp_h->dest == bpf_htons(2152)) {
        bpf_printk("[bpf_htons] it's GTP-U :) \n");
    }
    bpf_printk("UPF Port: %d \n", udp_h->dest);
    bpf_printk("UPF Port: %x \n", udp_h->dest);
    unsigned char udpportdst[2];
    udpportdst[0] = udp_h->dest >> 8 & 0xFF;
    udpportdst[1] = udp_h->dest & 0xFF;
    bpf_printk("UPF Port[0]: %x \n", udpportdst[0]);
    bpf_printk("UPF Port[1]: %x \n", udpportdst[1]);

    bpf_printk("UPF Port[1]: %x \n", udpportdst[1]);
    bpf_printk("UPF Port[0]: %x \n", udpportdst[0]);

    // ext-upf1 -> 32152
    // udp_h->dest = bpf_htons(32152) ;
    // ext-upf1 -> 32153
    // udp_h->dest = bpf_htons(32153) ;
    // ext-upf1 -> 32154
    // udp_h->dest = bpf_htons(32154) ;
    udpportdst[0] = udp_h->dest >> 8 & 0xFF;
    udpportdst[1] = udp_h->dest & 0xFF;
    bpf_printk("UPF Port[0]: %x \n", udpportdst[0]);
    bpf_printk("UPF Port[1]: %x \n", udpportdst[1]);

    bpf_printk("UPF Port[1]: %x \n", udpportdst[1]);
    bpf_printk("UPF Port[0]: %x \n", udpportdst[0]);
    bpf_printk("UPF Port: %d \n", udp_h->dest);
    bpf_printk("UPF Port: %x \n", udp_h->dest);

    if (ip_h->saddr == gnb_veth.ipv4 && ip_h->daddr == lb_veth.ipv4) {
        // 哈扣，記得要改，很重要
        // UPF1
        // target = &ens18_extupf1;  
        // udp_h->dest = bpf_htons(32152) ;
        // target = &ens18_extupf2;  
        // udp_h->dest = bpf_htons(32153) ;
        target = &ens18_extupf3;  
        udp_h->dest = bpf_htons(32154) ;
        // udpportdst[0] = udp_h->dest >> 8 & 0xFF;
        // udpportdst[1] = udp_h->dest & 0xFF;
        // bpf_printk("UPF Port[0]: %x \n", udpportdst[0]);
        // bpf_printk("UPF Port[1]: %x \n", udpportdst[1]);
        // fnat(skb, ip_h, &SRC, DST);
        // fnat(skb, ip_h, &fln_cn, target);
        // from LB 2 CNI0
        // fnat(skb, ip_h, &lb_veth, target);
        fnat(skb, ip_h, &ens18_cn, target);
        // dnat(skb, ip_h, target);
    }
    // from B -> lb to lb -> A
    else if (ip_h->daddr == lb_veth.ipv4) {
        for (int i=0; i<EXUPF_COUNT; i++) {
            if (ip_h->saddr == exupf_veth[i].ipv4) {
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

    // ===== Info =====
    if (DEBUG_LEVEL >= MORE_INFO) {
        // echo_mac(eth_h);
        echo_ipv4(ip_h);
        // echo_udp(udp_h);
    }

    if (target == NULL)
        return BPF_OK;
    else
        return bpf_redirect(target->ifnum, 0);
}

char _license[] SEC("license") = "GPL";
