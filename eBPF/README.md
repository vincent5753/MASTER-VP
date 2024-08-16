# eBPF
To find the relationship between a `Pod` and a `veth`, look up [getpodveth.sh](https://github.com/vincent5753/MASTER-VP/blob/main/eBPF/getpodveth.sh).

## ENV setup
```
sudo apt install -y clang llvm
sudo apt install -y libbpf-dev libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install -y linux-headers-$(uname -r) linux-tools-common linux-tools-generic linux-tools-$(uname -r)
sudo apt install -y clang libmnl-dev bison flex pkg-config dwarves
```

## Compile
```
clang -target bpf -O2 -g -c ${code}.c -o ${obj}.o
```

## XDP
```
# Attach
sudo ip link set dev ${if} xdpdrv obj ${code}.o sec ${sec}

# Detach
sudo ip link set dev ${if} xdpdrv off
```

## tc
```
# Check if interface has clsact
 ## Tips: You will need to do this, every time you reboot the host.
sudo tc qdisc show dev ${if} clsact

# Adding clsact
sudo tc qdisc add dev ${if} clsact


# Lookup attached ebpf progs on tc
 ## ingress
sudo tc filter show dev ${if} ingress
 ## egress
sudo tc filter show dev ${if} egress

# Attach
 ## to ingress
sudo tc filter add dev ${if} ingress bpf da obj ${objname}.o sec ${secname}
 ## to egress
sudo tc filter add dev ${if} egress bpf da obj ${objname}.o sec ${secname}

# Detach
 ## from ingress
sudo tc filter del dev ${if} ingress pref 49152 handle 0x1 bpf
 ## from egress
sudo tc filter del dev ${if} egress pref 49152 handle 0x1 bpf
```

## trace_pipe
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
