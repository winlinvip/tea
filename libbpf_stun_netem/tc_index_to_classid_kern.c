#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("cls")
int cls_main(struct __sk_buff *ctx) {
    if (ctx->protocol != bpf_htons(0x0800)) return 0; /*ETH_P_IP*/

    struct ethhdr* eth = (void*)(uintptr_t)ctx->data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);
    if ((void*)(iph + 1) > (void*)(uintptr_t)ctx->data_end) return 0;

    /* After clsact set the tc_classid, here we can get it from the tc_index */
    if (ctx->tc_index && !ctx->tc_classid) {
        ctx->tc_classid = ctx->tc_index;
    }
    return 0; /* TC_ACT_UNSPEC(-1) TC_ACT_OK(0) TC_ACT_RECLASSIFY(1) TC_ACT_SHOT(2) */
}
char __license[] SEC("license") = "GPL";

