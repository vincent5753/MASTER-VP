#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, uint32_t);
        __type(value, uint32_t);
        __uint(max_entries, 10);
} count_map SEC(".maps");

SEC("countntp")
int countontc(struct __sk_buff *skb)
{
  int key = 0; /* 0 packet count | 1 total len | 2 ntp count | 3 total len of ntp packet */
  int initval = 0, *valueptr;
  valueptr = bpf_map_lookup_elem(&count_map, &key);
    /* 如果找不到 key 所對應的指標，表示你沒創建過這個 key */
  if (!valueptr){
    bpf_map_update_elem(&count_map, &key, &initval, BPF_ANY); /* BPF_ANY     -> 如果鍵存在，則更新元素的值；如果鍵不存在，則創建一個新元素
                                                                 BPF_NOEXIST -> 如果鍵不存在，則創建一個新元素；如果鍵存在，則操作失敗並回傳 -EEXIST
                                                                 BPF_EXIST   -> 如果鍵存在，則更新元素的值；如果鍵不存在，則操作失敗並返回 -ENOENT */
  }else{
    /* 如果存在就直接加 */
    __sync_fetch_and_add(valueptr, 1);
  }
  // 建立封包結構
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
    // ETH
    // 建立 ethhdr 資料結構
    struct ethhdr *eth = data;
    // 邊界檢查，如果封包比 ethhdr 小，別理它
    if (data + sizeof(struct ethhdr) > data_end){
        return BPF_OK;
    }
    // NTP 是基於 UDP，所以如果底層不是 IP 的封包就可以丟了
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return BPF_OK;
    }
    // ETH -> IP
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // 邊界檢查，如果封包比 ethhdr + iphdr 小，別理它 (MAC 和 IP 的 SIZE 應該要小於 data_end，反之)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
        return BPF_OK;
    }
    // ETH -> IP -> UDP
    // 建立 udphdr 資料結構
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // 邊界檢查 如果封包比 eth+iphdr+udphdr 小，別理它
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return BPF_OK;
    }
    // NTP port == 123
    if (bpf_ntohs(udph->dest) == 123){
      key = 2;
      valueptr = bpf_map_lookup_elem(&count_map, &key);
      if (!valueptr){
        bpf_map_update_elem(&count_map, &key, &initval, BPF_ANY); /* BPF_ANY     -> 如果鍵存在，則更新元素的值；如果鍵不存在，則創建一個新元素
                                                                     BPF_NOEXIST -> 如果鍵不存在，則創建一個新元素；如果鍵存在，則操作失敗並回傳 -EEXIST
                                                                     BPF_EXIST   -> 如果鍵存在，則更新元素的值；如果鍵不存在，則操作失敗並返回 -ENOENT */
      }else{
        /* 如果存在就直接加 */
        __sync_fetch_and_add(valueptr, 1);
      }
    }
  return 0;
}

char _license[] SEC("license") = "GPL";
