#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK     0
#define TC_ACT_SHOT       2 /* Drop packet */
#define ETH_P_IP   0x0800    /* Internet Protocol packet    */

SEC("tc")
int hello(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr* eth = (void*)(long)skb->data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (skb->protocol != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr* iph = (struct iphdr*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr* udph = (struct udphdr*)(iph + 1);
    if ((void*)(udph + 1) > data_end) return TC_ACT_OK;

    __u64 *payload = (__u64*)(udph + 1);
    if ((void*)(payload + 1) > data_end) return TC_ACT_OK;

    __u64 val2 = *(__u64*)payload;
    __u16 stun_type = (__u16)(val2 & 0xffff);
    __u16 stun_length = (__u16)((val2 >> 16) & 0xffff);
    __u32 stun_magic = (__u32)((val2 >> 32) & 0xffffffff);
    if (stun_type != bpf_htons(0x0001) && stun_type != bpf_htons(0x0101)) return TC_ACT_OK;
    if (stun_magic != bpf_htonl(0x2112a442)) return TC_ACT_OK;

    bpf_printk("Drop STUN packet, type=0x%02x, len=%d, magic=0x%02x", stun_type, stun_length, stun_magic);
    return TC_ACT_SHOT;
}
char __license[] SEC("license") = "GPL";

