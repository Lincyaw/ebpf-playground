//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// 定义一个用于传递数据的结构体
struct event {
    u64 pid;        // 进程ID
    u64 timestamp;  // 时间戳
    u8 input[64]; // 输入字符串的副本
};

// 定义一个BPF Map来传递数据到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// Uprobe处理函数
SEC("uprobe/demonstrateDynamicMemory")
int BPF_KPROBE(handle_dynamic_memory, const char *input) {
    struct event event;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();

    bpf_probe_read_user_str(event.input, sizeof(event.input), input);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
