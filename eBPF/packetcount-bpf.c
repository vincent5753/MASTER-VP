#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY); /* 定義 map 的種類 */
        __type(key, uint32_t);    /* 裡面會有個 key  */
        __type(value, uint32_t);  /*      同上       */
        __uint(max_entries, 1);           /*     最多 1 筆   */
} count_map SEC(".maps");                 /* 叫做 count_map  */

SEC("countc")
int countontc(struct __sk_buff *skb)
{
  int key = 0;
  int initval = 0, *valueptr;
  valueptr = bpf_map_lookup_elem(&count_map, &key);

  if (!valueptr){
    bpf_map_update_elem(&count_map, &key, &initval, BPF_ANY); /* BPF_ANY     -> 如果鍵存在，則更新元素的值；如果鍵不存在，則創建一個新元素
                                                                 BPF_NOEXIST -> 如果鍵不存在，則創建一個新元素；如果鍵存在，則操作失敗並回傳 -EEXIST
                                                                 BPF_EXIST   -> 如果鍵存在，則更新元素的值；如果鍵不存在，則操作失敗並回傳 -ENOENT */
    return 0;
  }
  __sync_fetch_and_add(valueptr, 1);
  return 0;
}

char _license[] SEC("license") = "GPL";
