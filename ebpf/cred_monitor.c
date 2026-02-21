#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "programs.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cred_drop_cnt SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 key = DROP_COUNTER_KEY;
    __u64 *val = bpf_map_lookup_elem(&cred_drop_cnt, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Hook commit_creds to detect credential changes (setuid, setgid, capability changes).
// commit_creds(struct cred *new) is called when credentials are installed.
// We compare the new creds with the current task's creds.
SEC("kprobe/commit_creds")
int trace_commit_creds(struct pt_regs *ctx)
{
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    if (!new_cred)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old_cred = BPF_CORE_READ(task, real_cred);
    if (!old_cred)
        return 0;

    // Read old credentials
    __u32 old_uid = 0, old_gid = 0;
    __u64 old_cap = 0;
    BPF_CORE_READ_INTO(&old_uid, old_cred, uid.val);
    BPF_CORE_READ_INTO(&old_gid, old_cred, gid.val);
    BPF_CORE_READ_INTO(&old_cap, old_cred, cap_effective.val);

    // Read new credentials
    __u32 new_uid = 0, new_gid = 0;
    __u64 new_cap = 0;
    BPF_CORE_READ_INTO(&new_uid, new_cred, uid.val);
    BPF_CORE_READ_INTO(&new_gid, new_cred, gid.val);
    BPF_CORE_READ_INTO(&new_cap, new_cred, cap_effective.val);

    // Only emit if something actually changed
    if (old_uid == new_uid && old_gid == new_gid && old_cap == new_cap)
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_CRED_CHANGE;
    event->pid = pid_tgid >> 32;
    event->tgid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->ppid = 0;
    event->_pad0 = 0;
    __builtin_memset(event->container_id, 0, sizeof(event->container_id));
    __builtin_memset(&event->data, 0, sizeof(event->data));
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Fill PPID
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    if (real_parent)
        event->ppid = BPF_CORE_READ(real_parent, tgid);

    // Determine severity
    if (new_uid == 0 && old_uid != 0) {
        event->security_level = SECURITY_LEVEL_HIGH; // Privilege escalation to root
    } else if (old_cap != new_cap) {
        event->security_level = SECURITY_LEVEL_MEDIUM; // Capability change
    } else {
        event->security_level = SECURITY_LEVEL_LOW;
    }

    event->data.cred.old_uid = old_uid;
    event->data.cred.new_uid = new_uid;
    event->data.cred.old_gid = old_gid;
    event->data.cred.new_gid = new_gid;
    event->data.cred.old_cap_effective = old_cap;
    event->data.cred.new_cap_effective = new_cap;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
