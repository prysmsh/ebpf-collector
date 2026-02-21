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
} proc_drop_cnt SEC(".maps");

static __always_inline void fill_ppid(struct security_event *event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *real_parent;

    real_parent = BPF_CORE_READ(task, real_parent);
    if (real_parent)
        event->ppid = BPF_CORE_READ(real_parent, tgid);
}

static __always_inline void submit_base_event(struct security_event *event, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->event_type = event_type;
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
}

static __always_inline void count_drop(void)
{
    __u32 key = DROP_COUNTER_KEY;
    __u64 *val = bpf_map_lookup_elem(&proc_drop_cnt, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }

    submit_base_event(event, EVENT_PROCESS_EXEC);

    // Read filename from tracepoint __data_loc_filename field.
    // The __data_loc encoding stores (offset << 16 | length) relative to the ctx pointer.
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(event->data.exec.filename, MAX_STRING_SIZE,
                       (void *)ctx + fname_off);

    // Read argv[0..3] from the current task's mm->arg_start (userspace memory).
    // This gives us the actual command line, not just the comm (which is truncated to 15 chars).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        if (arg_start && arg_end > arg_start) {
            unsigned long len = arg_end - arg_start;
            if (len > MAX_ARGS_SIZE)
                len = MAX_ARGS_SIZE;
            bpf_probe_read_user(event->data.exec.argv, len, (void *)arg_start);
            // Replace null separators between argv entries with spaces for readability
            // (bounded loop for verifier)
            for (int i = 0; i < MAX_ARGS_SIZE - 1; i++) {
                if ((unsigned long)i >= len - 1)
                    break;
                if (event->data.exec.argv[i] == '\0')
                    event->data.exec.argv[i] = ' ';
            }
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }

    submit_base_event(event, EVENT_PROCESS_EXIT);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
