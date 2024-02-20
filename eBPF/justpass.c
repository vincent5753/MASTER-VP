#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("justpass")
int myxdpprogram(struct xdp_md *ctx) {
    void * data = (void *)(long)ctx->data;
    void * data_end = (void *)(long)ctx->data_end;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL v2";
