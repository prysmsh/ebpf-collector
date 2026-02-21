#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "programs.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB ring buffer
} events SEC(".maps");

// Per-CPU drop counter
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} file_drop_cnt SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 key = DROP_COUNTER_KEY;
    __u64 *val = bpf_map_lookup_elem(&file_drop_cnt, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void fill_ppid(struct security_event *event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    if (real_parent)
        event->ppid = BPF_CORE_READ(real_parent, tgid);
}

static __inline struct security_event *reserve_event(void)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return NULL;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_FILE_ACCESS;
    event->pid = pid_tgid >> 32;
    event->tgid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->security_level = SECURITY_LEVEL_INFO;
    event->ppid = 0;
    event->_pad0 = 0;
    __builtin_memset(event->container_id, 0, sizeof(event->container_id));
    __builtin_memset(&event->data, 0, sizeof(event->data));
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    fill_ppid(event);

    return event;
}

// do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
// filename is the 2nd argument (PARM2)
SEC("kprobe/do_sys_open")
int trace_file_open(struct pt_regs *ctx)
{
    struct security_event *event = reserve_event();
    if (!event)
        return 0;

    // Read the actual filename from userspace (2nd argument)
    const char *fname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(event->data.file.filename, MAX_STRING_SIZE, fname);

    unsigned long flags = PT_REGS_PARM3(ctx);
    event->data.file.flags = (__u32)flags;

    unsigned long mode = PT_REGS_PARM4(ctx);
    event->data.file.mode = (__u32)mode;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_file_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct security_event *event = reserve_event();
    if (!event)
        return 0;

    // Read filename from arg[0] (pathname pointer)
    const char *fname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->data.file.filename, MAX_STRING_SIZE, fname);

    event->security_level = SECURITY_LEVEL_MEDIUM;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/chmod_common")
int trace_chmod(struct pt_regs *ctx)
{
    struct security_event *event = reserve_event();
    if (!event)
        return 0;

    event->security_level = SECURITY_LEVEL_MEDIUM;
    bpf_ringbuf_submit(event, 0);
    return 0;
}
