#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    
    pid_t pid;
    struct pt_regs *newctx = (struct pt_regs *)ctx;
    struct filename *fname = (struct filename *)PT_REGS_PARM2(newctx);

    const char * pathname = BPF_CORE_READ(fname, name); 
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, pathname);
    return 0;
}

// SEC("fexit/do_unlinkat")
// int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
// {
//     pid_t pid;

//     pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
//     return 0;
// }


// SEC("fentry/do_unlinkat")
// int BPF_PROG(do_unlinkat)
// {
//     long pid_tgid = bpf_get_current_pid_tgid();
//     int pid = pid_tgid >> 32; // 获取进程ID

//     struct filename *fname = (struct filename *)PT_REGS_PARM2(ctx);

//     // 使用BPF_CORE_READ宏安全地读取name字段
//     const char *pathname = BPF_CORE_READ(fname, name);

//     // 使用bpf_printk打印信息到内核日志（仅用于调试）
//     bpf_printk("fentry: pid = %d, filename = %s\n", pid, pathname);

//     return 0;
// }

// SEC("fentry/do_unlinkat")
// int do_unlinkat(struct pt_regs *ctx)
// {
//     pid_t pid;
//     struct filename *fname = (struct filename *)PT_REGS_PARM2(ctx);
//     pid = bpf_get_current_pid_tgid() >> 32;
    
//     const char * pathname = BPF_CORE_READ(fname, name);   
//     bpf_printk("fentry: pid = %d, filename = %s\n", pid, pathname);
//     return 0;
// }

// SEC("fexit/do_unlinkat")
// int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
// {
    
//     pid_t pid;

//     pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
//     return 0;
// }