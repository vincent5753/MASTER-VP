#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

/*
ping-1-privileged                           1/1     Running   0          13m    10.244.0.64   ubuntu-pve   <none>
ping-2-privileged                           1/1     Running   0          13m    10.244.0.63   ubuntu-pve   <none>
ping-3-privileged                           1/1     Running   0          13m    10.244.0.62   ubuntu-pve   <none>
*/

// mac in pod
const unsigned char ping_1_mac[6] = {0x92, 0xd3, 0x27, 0xf3, 0x2b, 0x11};
const unsigned char ping_2_mac[6] = {0xba, 0x0f, 0x32, 0xb0, 0xc6, 0x20};
const unsigned char ping_3_mac[6] = {0x72, 0x2f, 0xc1, 0xcd, 0x63, 0xa9};

const __u32 ping_1_ip = 10 | (244 << 8) | (0 << 16) | (64 << 24);
const __u32 ping_2_ip = 10 | (244 << 8) | (0 << 16) | (63 << 24);
const __be32 ping_3_ip = 10 | (244 << 8) | (0 << 16) | (62 << 24);

SEC("xdpprogram")
int myxdpprogram(struct xdp_md *ctx) {
    void * data = (void *)(long)ctx->data;
    void * data_end = (void *)(long)ctx->data_end;

    struct ethhdr * eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end) {  // MAC ram size check
        struct iphdr * ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {  // IP ram size check
            if (ip->protocol == 1) { // check ICMP protocol
                struct icmphdr * icmp = data + sizeof(*eth) + sizeof(*ip);
                if ((void*)icmp + sizeof(*icmp) <= data_end) {  // ICMP ram size check
                    __u32 ifindex2 = 67;
                    bpf_printk("[Debug] ifindex2: %d\n", ifindex2);
                    bpf_printk("==========\n");

                    _Bool check_result = 1;
                    for (int i=0; i<6; i++) { // check mac
                        if (eth->h_source[i] != ping_3_mac[i] || eth->h_dest[i] != ping_1_mac[i]) {
                            bpf_printk("MAC ERROR\n");
                            check_result = 0;
                            break;
                        }
                    }
                    if (ip->saddr != ping_3_ip || ip->daddr != ping_1_ip) { // check ip
                        bpf_printk("IP ERROR\n");
                        check_result = 0;
                    }

                    if (check_result == 1) {
                        bpf_printk("[ Start of REWRITE! ]\n");

                        for (int i=0; i<6; i++) {
                            bpf_printk("[PRI][MAC][SRC][ORI] %x\n", eth->h_source[i]);
                        }
                        for (int i=0; i<6; i++) {
                            bpf_printk("[PRI][MAC][DEST][ORI] %x\n", eth->h_dest[i]);
                        }
                        // 改封包
                        bpf_printk("  ---  ETH ADDR CHANGED! --- \n");
                        for (int i=0; i<6; i++) {
                            eth->h_dest[i] = ping_2_mac[i];
                            eth->h_source[i] = ping_2_mac[i];
                        }
                        for (int i=0; i<6; i++) {
                            bpf_printk("[PRI][MAC][SRC][MDF] %x\n", eth->h_source[i]);
                        }
                        for (int i=0; i<6; i++) {
                            bpf_printk("[PRI][MAC][DEST][MDF] %x\n", eth->h_dest[i]);
                        }
                            bpf_printk("  ------------  Dividers ------------ \n");
                        __u8 sipv4_0 = ip->saddr & 0xFF;
                        __u8 sipv4_1 = (ip->saddr >> 8) & 0xFF;
                        __u8 sipv4_2 = (ip->saddr >> 16) & 0xFF;
                        __u8 sipv4_3 = (ip->saddr >> 24) & 0xFF;
                        bpf_printk("[PRI][IP][SRC][ORI][0]: %d\n", sipv4_0);
                        bpf_printk("[PRI][IP][SRC][ORI][0]: %d\n", sipv4_1);
                        bpf_printk("[PRI][IP][SRC][ORI][0]: %d\n", sipv4_2);
                        bpf_printk("[PRI][IP][SRC][ORI][0]: %d\n", sipv4_3);
                        __u8 dipv4_0 = ip->daddr & 0xFF;
                        __u8 dipv4_1 = (ip->daddr >> 8) & 0xFF;
                        __u8 dipv4_2 = (ip->daddr >> 16) & 0xFF;
                        __u8 dipv4_3 = (ip->daddr >> 24) & 0xFF;
                        bpf_printk("[PRI][IP][DST][ORI][0]: %d\n", dipv4_0);
                        bpf_printk("[PRI][IP][DST][ORI][1]: %d\n", dipv4_1);
                        bpf_printk("[PRI][IP][DST][ORI][2]: %d\n", dipv4_2);
                        bpf_printk("[PRI][IP][DST][ORI][3]: %d\n", dipv4_3);
                        bpf_printk("  ---  IP SRC ADDR CHANGED! --- \n");
                        ip->saddr = ping_2_ip;
                        ip->daddr = ping_2_ip;
                        __u8 sipv4_0_1 = ip->saddr & 0xFF;
                        __u8 sipv4_1_1 = (ip->saddr >> 8) & 0xFF;
                        __u8 sipv4_2_1 = (ip->saddr >> 16) & 0xFF;
                        __u8 sipv4_3_1 = (ip->saddr >> 24) & 0xFF;
                        bpf_printk("[PRI][IP][SRC][MDF][0]: %d\n", sipv4_0_1);
                        bpf_printk("[PRI][IP][SRC][MDF][0]: %d\n", sipv4_1_1);
                        bpf_printk("[PRI][IP][SRC][MDF][0]: %d\n", sipv4_2_1);
                        bpf_printk("[PRI][IP][SRC][MDF][0]: %d\n", sipv4_3_1);
                        __u8 dipv4_0_1 = ip->daddr & 0xFF;
                        __u8 dipv4_1_1 = (ip->daddr >> 8) & 0xFF;
                        __u8 dipv4_2_1 = (ip->daddr >> 16) & 0xFF;
                        __u8 dipv4_3_1 = (ip->daddr >> 24) & 0xFF;
                        bpf_printk("[PRI][IP][DST][MDF][0]: %d\n", dipv4_0_1);
                        bpf_printk("[PRI][IP][DST][MDF][1]: %d\n", dipv4_1_1);
                        bpf_printk("[PRI][IP][DST][MDF][2]: %d\n", dipv4_2_1);
                        bpf_printk("[PRI][IP][DST][MDF][3]: %d\n", dipv4_3_1);
                        bpf_printk("[ End of REWRITE! ]\n");

                        // return bpf_redirect(ifindex2, 0);
                        // return XDP_TX;
                        return XDP_REDIRECT;
                    }
                    bpf_printk("ping-3\n");
                }
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL v2";
