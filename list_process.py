#!/usr/bin/python3
from bcc import BPF

# BPF program to trace sys_write, tracking only vim or nano processes
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

// Data structure to pass information to user space
struct data_t {
    u32 pid;
    u64 ts;
    int ret;
    char comm[TASK_COMM_LEN];
    char filename[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Track only vim and nano processes
    if (!((data.comm[0] == 'v' && data.comm[1] == 'i' && data.comm[2] == 'm') ||
          (data.comm[0] == 'n' && data.comm[1] == 'a' && data.comm[2] == 'n' && data.comm[3] == 'o'))) {
        return 0;
    }

    bpf_probe_read_kernel(&data.filename, sizeof(data.filename), file->f_path.dentry->d_name.name);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="vfs_write", fn_name="trace_write")

# Process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.ts:18} {event.pid:6} {event.comm.decode('utf-8', 'replace'):16} {event.filename.decode('utf-8', 'replace')}")

b["events"].open_perf_buffer(print_event)

print("Tracing file writes (only for vim and nano processes)... Ctrl-C to stop.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()