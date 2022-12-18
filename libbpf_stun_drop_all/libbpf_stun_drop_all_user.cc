#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "libbpf_stun_drop_all_kern.skel.h"

struct BpfHandler {
    libbpf_stun_drop_all_kern* obj;
    bpf_tc_hook* tc_hook;
    bpf_tc_opts* tc_opts;
    BpfHandler(libbpf_stun_drop_all_kern* obj) {
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
        if (obj) libbpf_stun_drop_all_kern__destroy(obj);
        system("grep -qs '/sys/kernel/debug' /proc/mounts && umount /sys/kernel/debug");
    }
};

int main(int argc, char** argv) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path="./vmlinux.btf");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = 1, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

    // Reset the custom path, use system /sys/kernel/btf/vmlinux if exists.
    if (opts.btf_custom_path && ::access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        printf("BTF: Use system /sys/kernel/btf/vmlinux not %s\n", opts.btf_custom_path);
        opts.btf_custom_path = NULL;
    }

    BpfHandler hdr(libbpf_stun_drop_all_kern__open_opts(&opts));
    if (!hdr.obj) {
        printf("init eBPF failed\n");
        return 1;
    }

    int r0;
    if ((r0 = libbpf_stun_drop_all_kern__load(hdr.obj)) != 0) {
        printf("load ebpf failed, r0=%d\n", r0);
        return 1;
    }
    if ((r0 = libbpf_stun_drop_all_kern__attach(hdr.obj)) != 0) {
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
    printf("Dropping all STUN packets...\n");
    system("cat /sys/kernel/debug/tracing/trace_pipe");
    printf("\nquiting\n");

    return 0;
}