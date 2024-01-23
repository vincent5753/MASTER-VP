#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include "gtp5g-gtpu.h"
#include <stdio.h>
#include <stdlib.h>

// x86 -> Little endian

SEC("xdpprogram")
int myxdpprogram(struct xdp_md *ctx) {
  // XDP 剛傳進來的封包起始和結束位置
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // 將封包位置傳給 Ethernet 資料結構(struct)
  struct ethhdr *eth = data;
  // 檢查封包大小是否大於等於 Ethernet Frame 的標頭(不然它就不是 eth 封包)
  // 如果 起始位置 + eth標頭大小 小於等於 資料結束位置還小(也就是在範圍內)
  if ((void*)eth + sizeof(*eth) <= data_end) {

    // 建立 IP 封包資料結構
     // ip 標頭位置 = 封包起始位置 + eth 封包大小
    struct iphdr *ip = data + sizeof(*eth);
    // 如果 IP 標頭 的 起始位置 + IP 標頭大小 小於等於 封包結束位置
    if ((void*)ip + sizeof(*ip) <= data_end) {
      if (ip->protocol == IPPROTO_UDP) {
      // 建立 UDP 標頭結構， UDP 標頭起始位置 = IP 封包位置結尾
      struct udphdr *udp = (void*)ip + sizeof(*ip);
      // 如果 UDP 標頭 的 起始位置 + UDP 標頭大小 小於等於 封包結束位置
      if ((void*)udp + sizeof(*udp) <= data_end) {
        if (udp->dest == ntohs(2152)) {
          bpf_printk("<Start of packet>\n");
                  bpf_printk("[Start of ETH]\n");
                  bpf_printk("  [ETH][MAC][SRC]\n");
                  for (char i=0; i<ETH_ALEN; i++) {
                    bpf_printk("  %x\n", eth->h_source[i]);
                  }
                  //bpf_printk("  [ETH][RAW][SRC][RAW] %x\n", ntohs(eth->h_source));
                  //if( ntohs(eth->h_source) == 1761 ){
                  //   bpf_printk("  [ETH][SND] UPF\n");
                  // }
                  bpf_printk("  [ETH][MAC][DST]\n");
                  for (char i=0; i<ETH_ALEN; i++) {
                    bpf_printk("  %x\n", eth->h_dest[i]);
                  }
                  // bpf_printk("  [ETH][MAC][DST][RAW] %x\n", ntohs(eth->h_dest));
                  // 2048 = 0x0800 = IPV4
                  if( ntohs(eth->h_proto) == 2048 ){
                    bpf_printk("  [ETH][TYPE] IPV4\n");
                  }
                  bpf_printk("[End of ETH]\n");
                  bpf_printk("[Start of 1st IP packet]\n");
                  unsigned char s2sipbytes[4];
                  s2sipbytes[0] = ip->saddr & 0xFF;
                  s2sipbytes[1] = (ip->saddr >> 8) & 0xFF;
                  s2sipbytes[2] = (ip->saddr >> 16) & 0xFF;
                  s2sipbytes[3] = (ip->saddr >> 24) & 0xFF;
                  bpf_printk("  [1stIP][SRC]\n");
                  bpf_printk("    sIP1:%d\n", s2sipbytes[0]);
                  bpf_printk("    sIP2:%d\n", s2sipbytes[1]);
                  bpf_printk("    sIP3:%d\n", s2sipbytes[2]);
                  bpf_printk("    sIP4:%d\n", s2sipbytes[3]);
                  unsigned char s2dipbytes[4];
                  s2dipbytes[0] = ip->daddr & 0xFF;
                  s2dipbytes[1] = (ip->daddr >> 8) & 0xFF;
                  s2dipbytes[2] = (ip->daddr >> 16) & 0xFF;
                  s2dipbytes[3] = (ip->daddr >> 24) & 0xFF;
                  bpf_printk("  [1stIP][DEST]\n");
                  bpf_printk("    dIP1:%d\n", s2dipbytes[0]);
                  bpf_printk("    dIP2:%d\n", s2dipbytes[1]);
                  bpf_printk("    dIP3:%d\n", s2dipbytes[2]);
                  bpf_printk("    dIP4:%d\n", s2dipbytes[3]);
                  bpf_printk("  [1stIP][Version] %d\n", ip->version);
                  bpf_printk("  [1stIP][HeaderLength] %d Byte\n", ip->ihl);
                  bpf_printk("  [1stIP][DCSP/ToS] %d\n", ip->tos);
                  bpf_printk("  [1stIP][Total Lenth] %d\n", htons(ip->tot_len));
                  bpf_printk("  [1stIP][FRAG OFFSET] %x\n", htons(ip->frag_off));
                  bpf_printk("  [1stIP][TTL] %u\n", ip->ttl);
                  bpf_printk("  [1stIP][Protocol] %u\n", ip->protocol);
                  bpf_printk("[End of 1st IP packet]\n");
                    bpf_printk("[Start of UDP]\n");
                    bpf_printk("  [UDP][SRC] %d\n", htons(udp->source));
                    bpf_printk("  [UDP][DST] %d\n", htons(udp->dest));
                    bpf_printk("  [UDP][LEN] %d\n", htons(udp->len));
                    bpf_printk("  [UDP][CHK] %x\n", htons(ip->check));
                    bpf_printk("[END of UDP]\n");
          // 如果比 GTP-U 的 Header 還短就 PASS (因為那就不會是 GTP-U)
          struct gtpv1_5gc *gtpv1_5gc = (void*)udp + sizeof(*udp);
          if ((void*)gtpv1_5gc + sizeof(*gtpv1_5gc) <= data_end) {
            bpf_printk("[Start of GTP-U]\n");
            bpf_printk("  [GTP-U][FLAG] %x\n", gtpv1_5gc->flags);
            bpf_printk("  [GTP-U][TYPE] %x\n", gtpv1_5gc->type);
            bpf_printk("  [GTP-U][LEN] %x\n", htons(gtpv1_5gc->length));
            bpf_printk("[End of GTP-U]\n");

            // GTP-U 裡的 IP 封包
            struct iphdr *ip = (void*)gtpv1_5gc + sizeof(*gtpv1_5gc);
            if ((void*)ip + sizeof(*ip) <= data_end) {
                  bpf_printk("[Start of 2nd IP packet]\n");
                  unsigned char s2sipbytes[4];
                  s2sipbytes[0] = ip->saddr & 0xFF;
                  s2sipbytes[1] = (ip->saddr >> 8) & 0xFF;
                  s2sipbytes[2] = (ip->saddr >> 16) & 0xFF;
                  s2sipbytes[3] = (ip->saddr >> 24) & 0xFF;
                  bpf_printk("  [2ndIP][SRC]\n");
                  bpf_printk("    sIP1:%d\n", s2sipbytes[0]);
                  bpf_printk("    sIP2:%d\n", s2sipbytes[1]);
                  bpf_printk("    sIP3:%d\n", s2sipbytes[2]);
                  bpf_printk("    sIP4:%d\n", s2sipbytes[3]);
                  unsigned char s2dipbytes[4];
                  s2dipbytes[0] = ip->daddr & 0xFF;
                  s2dipbytes[1] = (ip->daddr >> 8) & 0xFF;
                  s2dipbytes[2] = (ip->daddr >> 16) & 0xFF;
                  s2dipbytes[3] = (ip->daddr >> 24) & 0xFF;
                  bpf_printk("  [2ndIP][DEST]\n");
                  bpf_printk("    dIP1:%d\n", s2dipbytes[0]);
                  bpf_printk("    dIP2:%d\n", s2dipbytes[1]);
                  bpf_printk("    dIP3:%d\n", s2dipbytes[2]);
                  bpf_printk("    dIP4:%d\n", s2dipbytes[3]);
                  bpf_printk("[End of 2nd IP packet]\n");
              if (ip->daddr == 0x08080808) {
                bpf_printk("[Debug_GTP-U]: Got GTP-U packet with dst 8.8.8.8!\n");
                return XDP_DROP;
               }
              if (ip->daddr == 0x01010101) {
                bpf_printk("[Debug_GTP-U]: Got GTP-U packet with dst 1.1.1.1!\n");
                return XDP_DROP;
              }
              if (ip->daddr == 0x09090909) {
                bpf_printk("[Debug_GTP-U]: Got GTP-U packet with dst 9.9.9.9!\n");
              }
              bpf_printk("<End of packet>\n");
            }
          }
         }
      }
      }
    }
 }
 // 預設動作
 return XDP_PASS;
}
char _license[] SEC("license") = "GPL v2";
