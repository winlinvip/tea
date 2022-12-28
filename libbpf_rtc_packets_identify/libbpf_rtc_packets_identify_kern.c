#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK     0
#define TC_ACT_SHOT       2 /* Drop packet */
#define ETH_P_IP   0x0800    /* Internet Protocol packet    */

const volatile __u32 target_port = 0;
const volatile __u32 target_sport = 0;
const volatile __u32 target_dport = 0;
const volatile __u32 target_stun = 1;
const volatile __u32 target_dtls = 1;
const volatile __u32 target_rtcp = 1;
const volatile __u32 target_pli = 1;
const volatile __u32 target_rtp = 1;

char buf[1024] = {};

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

    /* Optional: Filter by source port */
    __u16 source = bpf_htons(udph->source);
    __u16 dest = bpf_htons(udph->dest);
    if (target_port && source != target_port && dest != target_port) return TC_ACT_OK;
    if (target_sport && source != target_sport) return TC_ACT_OK;
    if (target_dport && dest != target_dport) return TC_ACT_OK;

    /* Identify protocol from UDP payload */
    __u64 *payload = (__u64*)(udph + 1);
    if ((void*)(payload + 1) > data_end) return TC_ACT_OK;
    __u64 val = *(__u64*)payload;
    __u8 val0 = (__u8)(val & 0xff);

    /* See https://github.com/ossrs/srs/blob/5.0release/trunk/src/app/srs_app_rtc_server.cpp#L126 */
    if (val0 == 0x00 || val0 == 0x01) {
        if (target_stun) bpf_printk("Got STUN type=0x%02x, %s", val0, buf);
    } else if (val0 > 19 && val0 < 64) {
        if (target_dtls) bpf_printk("Got DTLS type=0x%02x, %d=>%d", val0, source, dest);
    } else if ((val0 & 0xC0) == 0x80) {
        __u8 val1 = (__u8)((val >> 8) & 0xff);
        if ((val0 & 0x80) == 0x80 && (val1 >= 192 && val1 <= 223)) {
            __u8 pt = val1;
            /* PLI: PT=PSFB(206), FMT=PLI(1), see https://github.com/ossrs/srs/blob/5.0release/trunk/src/kernel/srs_kernel_rtc_rtcp.cpp#L1445 */
            if (pt == 206 && (val0 & 0x1f) == 0x01) {
                if (target_pli) bpf_printk("Got PLI %d=>%d, len=%d", source, dest, skb->len);
            } else {
                if (target_rtcp) bpf_printk("Got RTCP %d=>%d, pt=%d", source, dest, pt);
            }
        } else {
            __u8 pt = val1 & 0x7f;
            if (target_rtp) bpf_printk("Got RTP %d=>%d, pt=%d", source, dest, pt);
        }
    }

    return TC_ACT_OK;
}
char __license[] SEC("license") = "GPL";

