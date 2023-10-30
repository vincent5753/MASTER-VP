# eBPF
獲取 `veth` 請參考 [getpodveth.sh](https://github.com/vincent5753/MASTER-VP/blob/main/getpodveth.sh)
## XDP_DROP-ALL
編譯
```
clang -target bpf -c XDP_DROP-ALL.c -o drop.o -O2
```

掛載至網卡
```
sudo ip link set dev vethe102c1e6 xdpdrv obj XDP_DROP-ALL.o sec .text
```

```
sudo ip link set dev vethe102c1e6 xdp off
```

## XDP_DROP-ICMP
編譯
```
clang -target bpf -c XDP_DROP-ICMP.c -o XDP_DROP-ICMP.o -O2
```

掛載至網卡
```
sudo ip link set dev vethe102c1e6 xdpdrv obj XDP_DROP-ICMP.o sec drop_icmp
```

卸載
```
sudo ip link set dev vethe102c1e6 xdp off
```
