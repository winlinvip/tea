#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Object pinning settings */
#define PIN_NONE                0
#define PIN_OBJECT_NS                1
#define PIN_GLOBAL_NS                2
/* ELF map definition */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#define MAX_ARRAY_ELEMS 16

struct bpf_elf_map SEC("maps") tc_stun_drop_all = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(__u32), /* (udp dst<<16 | udp src port) % max_elem */
        .size_value = sizeof(__u32), /* dropped packets */
        .max_elem = MAX_ARRAY_ELEMS,
        .pinning = PIN_GLOBAL_NS,
};

struct bpf_elf_map SEC("maps") tc_stun_drop_all_ports = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(__u32), /* (udp dst<<16 | udp src port) % max_elem */
        .size_value = sizeof(__u32), /* udp dst<<16 | udp src port */
        .max_elem = MAX_ARRAY_ELEMS,
        .pinning = PIN_GLOBAL_NS,
};

struct bpf_elf_map SEC("maps") tc_stun_drop_all_bytes = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(__u32), /* (udp dst<<16 | udp src port) % max_elem */
        .size_value = sizeof(__u64), /* udp payload first 8 bytes */
        .max_elem = MAX_ARRAY_ELEMS,
        .pinning = PIN_GLOBAL_NS,
};

#define TC_ACT_OK     0
#define TC_ACT_SHOT       2 /* Drop packet */
#define ETH_P_IP   0x0800    /* Internet Protocol packet    */

SEC("cls") int cls_main(struct __sk_buff *skb) {
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

    __u32 val = ((__u32)bpf_htons(udph->dest))<<16 | (__u32)bpf_htons(udph->source);
    __u32 key = val % MAX_ARRAY_ELEMS;
    bpf_map_update_elem(&tc_stun_drop_all_ports, &key, &val, BPF_ANY);
    bpf_map_update_elem(&tc_stun_drop_all_bytes, &key, &val2, BPF_ANY);

    __u32 *dropped = bpf_map_lookup_elem(&tc_stun_drop_all, &key);
    if (dropped) __sync_fetch_and_add(dropped, 1);
    return TC_ACT_SHOT;
}
char __license[] SEC("license") = "GPL";

