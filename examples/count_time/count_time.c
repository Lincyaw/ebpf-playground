//go:build ignore

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} start_time SEC(".maps");

SEC("kprobe/do_unlinkat")
int sys_openat(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int retsys_openat(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;

    tsp = bpf_map_lookup_elem(&start_time, &pid);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_printk("do_unlinkat executed in %llu ns\n", delta);
        bpf_map_delete_elem(&start_time, &pid);
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
