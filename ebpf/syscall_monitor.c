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

// Syscall filter map: only emit events for syscalls in this map.
// Populated from userspace based on loaded rules.
// Key: syscall number, Value: 1 (enabled)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, __u32);
} syscall_filter SEC(".maps");

// Per-CPU drop counter
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_drop_cnt SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 key = DROP_COUNTER_KEY;
    __u64 *val = bpf_map_lookup_elem(&syscall_drop_cnt, &key);
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

static __inline struct security_event *reserve_event(__u64 syscall_nr)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return NULL;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SYSCALL_ANOMALY;
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
    event->data.syscall.syscall_nr = syscall_nr;

    fill_ppid(event);

    return event;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 nr = ctx->id;

    // Only emit events for syscalls in the filter map.
    // If the map is empty (no rules loaded), skip everything to avoid flooding.
    __u32 *enabled = bpf_map_lookup_elem(&syscall_filter, &nr);
    if (!enabled)
        return 0;

    struct security_event *event = reserve_event(nr);
    if (!event)
        return 0;

    event->data.syscall.args[0] = ctx->args[0];
    event->data.syscall.args[1] = ctx->args[1];
    event->data.syscall.args[2] = ctx->args[2];
    event->data.syscall.args[3] = ctx->args[3];
    event->data.syscall.args[4] = ctx->args[4];
    event->data.syscall.args[5] = ctx->args[5];

    bpf_ringbuf_submit(event, 0);
    return 0;
}
