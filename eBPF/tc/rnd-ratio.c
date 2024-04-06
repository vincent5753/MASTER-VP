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
        __uint(max_entries, 4);
} count_map SEC(".maps");

SEC("getsomerndnum")
int getsomerndnumwhentcrcv(struct __sk_buff *skb)
{
  int key = 0; /* 0 packet count | 1 total len | 2 GTP-U packet count | 3 total len of GTP-U packet */
  int initval = 1, *valueptr;
  valueptr = bpf_map_lookup_elem(&count_map, &key);
  __u32 somerndnum = bpf_get_prandom_u32();
  bpf_map_update_elem(&count_map, &key, &somerndnum, BPF_ANY); /* BPF_ANY     -> 如果鍵存在，則更新元素的值；如果鍵不存在，則創建一個新元素
                                                                 BPF_NOEXIST -> 如果鍵不存在，則創建一個新元素；如果鍵存在，則操作失敗並回傳 -EEXIST
                                                                 BPF_EXIST   -> 如果鍵存在，則更新元素的值；如果鍵不存在，則操作失敗並返回 -ENOENT */
  __u32 dvd = 4294967295 * 0.3;
  if ( somerndnum > dvd){
      key = 1;
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
    }else{
      key = 2;
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
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
