//go:build ignore
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int testfunc(struct pt_regs *ctx)
{
    u64 pid;
    const char * pathname;
    pid = bpf_get_current_pid_tgid() >> 32;
    struct filename *fname = (struct filename *)PT_REGS_PARM2(ctx);
    pathname = BPF_CORE_READ(fname, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, pathname);
    return 0;
}

// SEC("kprobe/do_unlinkat")
// int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
// {
//     pid_t pid;
//     const char *filename;

//     pid = bpf_get_current_pid_tgid() >> 32;
//     filename = BPF_CORE_READ(name, name);
//     bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
//     return 0;
// }

SEC("kretprobe/do_unlinkat")
int kretprobe_do_unlinkat(long ret)
{
    u64 pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}