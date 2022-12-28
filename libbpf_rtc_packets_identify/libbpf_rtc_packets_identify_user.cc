#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <string>
#include "libbpf_rtc_packets_identify_kern.skel.h"

struct BpfHandler {
    libbpf_rtc_packets_identify_kern* obj;
    bpf_tc_hook* tc_hook;
    bpf_tc_opts* tc_opts;
    BpfHandler(libbpf_rtc_packets_identify_kern* obj) {
        this->obj = obj;
        tc_hook = NULL;
        tc_opts = NULL;

        // Mount the debugfs for /sys/kernel/debug/tracing/trace_pipe
        system("grep -qs '/sys/kernel/debug' /proc/mounts || mount -t debugfs none /sys/kernel/debug");
    }
    ~BpfHandler() {
        if (tc_opts) {
            tc_opts->flags = tc_opts->prog_fd = tc_opts->prog_id = 0;
            bpf_tc_detach(tc_hook, tc_opts);
        }
        if (tc_hook) bpf_tc_hook_destroy(tc_hook);
        if (obj) libbpf_rtc_packets_identify_kern__destroy(obj);
        system("grep -qs '/sys/kernel/debug' /proc/mounts && umount /sys/kernel/debug");
    }
};

void usage(int argc, char** argv) {
    printf("Usage: %s [--ifindex=1|2|3] [--ingress=1|0] [--port=val] [--sport=val] [--dport=val] [--stun=1|0] [--dtls=1|0] [--rtcp=1|0] [--pli=1|0] [--rtp=1|0] [--help|-h]\n", argv[0]);
    printf("        --ifindex=1|2|3     The interface index to attach, use \"ip a\" to query. Default: 1\n");
    printf("        --ingress=1|0       Whether filter ingress packet. Default: 0\n");
    printf("        --port=val          The port to filter the source or dest, 0 to match all. Default: 0\n");
    printf("        --sport=val         The source port to filter, 0 to match all. Default: 0\n");
    printf("        --dport=val         The dest port to filter, 0 to match all. Default: 0\n");
    printf("        --stun=1|0          Whether filter STUN packet. Default: 1\n");
    printf("        --dtls=1|0          Whether filter DTLS packet. Default: 1\n");
    printf("        --rtcp=1|0          Whether filter RTCP packet. Default: 1\n");
    printf("        --pli=1|0           Whether filter RTCP(PLI) packet. Default: 1\n");
    printf("        --rtp=1|0           Whether filter RTP packet. Default: 1\n");
    printf("Example:\n");
    printf("    %s --help\n", argv[0]);
    printf("    %s --ifindex=1 --port=8000 --stun=1 --dtls=0 --rtcp=0 --pli=1 --rtp=0\n", argv[0]);
}

int main(int argc, char** argv) {
    int ifindex = 1, ingress = 0, target_port = 0, target_sport = 0, target_dport = 0, target_stun = 1, target_dtls = 1, target_rtcp = 1, target_pli = 1, target_rtp = 1;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            usage(argc, argv); return 0;
        } else if (arg.find("--ifindex=") == 0) {
            ifindex = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--ingress=") == 0) {
            ingress = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--port=") == 0) {
            target_port = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--sport=") == 0) {
            target_sport = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--dport=") == 0) {
            target_dport = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--stun=") == 0) {
            target_stun = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--dtls=") == 0) {
            target_dtls = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--rtcp=") == 0) {
            target_rtcp = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--pli=") == 0) {
            target_pli = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        } else if (arg.find("--rtp=") == 0) {
            target_rtp = ::atoi(arg.substr(arg.find("=") + 1).c_str());
        }
    }
    printf("Run with ifindex=%d, ingress=%d, port=%d, sport=%d, dport=%d, stun=%d, dtls=%d, rtcp=%d, pli=%d, rtp=%d\n",
        ifindex, ingress, target_port, target_sport, target_dport, target_stun, target_dtls, target_rtcp, target_pli, target_rtp);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path="./vmlinux.btf");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = (ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS));
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

    // Reset the custom path, use system /sys/kernel/btf/vmlinux if exists.
    if (opts.btf_custom_path && ::access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        printf("BTF: Use system /sys/kernel/btf/vmlinux not %s\n", opts.btf_custom_path);
        opts.btf_custom_path = NULL;
    }

    BpfHandler hdr(libbpf_rtc_packets_identify_kern__open_opts(&opts));
    if (!hdr.obj) {
        printf("init eBPF failed\n");
        return 1;
    }

    // Setup the config as global variable for eBPF.
    hdr.obj->rodata->target_port = target_port;
    hdr.obj->rodata->target_sport = target_sport;
    hdr.obj->rodata->target_dport = target_dport;
    hdr.obj->rodata->target_stun = target_stun;
    hdr.obj->rodata->target_dtls = target_dtls;
    hdr.obj->rodata->target_rtcp = target_rtcp;
    hdr.obj->rodata->target_pli = target_pli;
    hdr.obj->rodata->target_rtp = target_rtp;

    int r0;
    if ((r0 = libbpf_rtc_packets_identify_kern__load(hdr.obj)) != 0) {
        printf("load ebpf failed, r0=%d\n", r0);
        return 1;
    }
    if ((r0 = libbpf_rtc_packets_identify_kern__attach(hdr.obj)) != 0) {
        printf("attach ebpf failed, r0=%d\n", r0);
        return 1;
    }

    r0 = bpf_tc_hook_create(&tc_hook);
    if (r0 && r0 != -EEXIST) {
        printf("create TC hook failed, r0=%d\n", r0);
        return r0;
    }
    hdr.tc_hook = &tc_hook;

    tc_opts.prog_fd = bpf_program__fd(hdr.obj->progs.hello);
    if ((r0 = bpf_tc_attach(&tc_hook, &tc_opts)) != 0) {
        printf("attach TC failed, r0=%d\n", r0);
        return r0;
    }
    hdr.tc_opts = &tc_opts;

    // User can execute it in the shell also.
    printf("Identify WebRTC packets...\n");
    system("cat /sys/kernel/debug/tracing/trace_pipe");
    printf("\nquiting\n");

    return 0;
}