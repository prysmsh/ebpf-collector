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

// Map: (pid, fd) -> filename for tracking which files FDs refer to
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, struct fd_entry);
} fd_table SEC(".maps");

// Temporary map to save openat args between entry and return
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, __u64); // userspace filename pointer
} openat_args SEC(".maps");

// Set of sensitive path prefixes to monitor for read/write.
// We use a simple prefix-check approach rather than a map for
// common sensitive paths.
static __always_inline int is_sensitive_prefix(const char *filename)
{
    // Check a few known sensitive prefixes character by character.
    // The verifier needs bounded access, so we check fixed-length prefixes.

    // /etc/shadow (11 chars)
    char buf[16];
    bpf_probe_read_kernel(buf, 12, filename);
    if (buf[0] == '/' && buf[1] == 'e' && buf[2] == 't' && buf[3] == 'c' && buf[4] == '/') {
        if (buf[5] == 's' && buf[6] == 'h' && buf[7] == 'a' && buf[8] == 'd')
            return 1;
        if (buf[5] == 's' && buf[6] == 'u' && buf[7] == 'd' && buf[8] == 'o')
            return 1;
        if (buf[5] == 'p' && buf[6] == 'a' && buf[7] == 's' && buf[8] == 's')
            return 1;
    }

    // /root/.ssh (10 chars)
    if (buf[0] == '/' && buf[1] == 'r' && buf[2] == 'o' && buf[3] == 'o' && buf[4] == 't')
        return 1;

    // /proc/*/mem
    if (buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r' && buf[3] == 'o' && buf[4] == 'c')
        return 1;

    return 0;
}

// Hook sys_enter_openat to save the filename pointer
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 fname_ptr = ctx->args[1]; // filename argument
    bpf_map_update_elem(&openat_args, &pid_tgid, &fname_ptr, BPF_ANY);
    return 0;
}

// Hook sys_exit_openat to record (pid, fd) -> filename
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fname_ptr = bpf_map_lookup_elem(&openat_args, &pid_tgid);
    if (!fname_ptr) {
        return 0;
    }

    long ret = ctx->ret;
    bpf_map_delete_elem(&openat_args, &pid_tgid);

    // Only track successful opens (ret >= 0 is the fd)
    if (ret < 0)
        return 0;

    struct fd_key key = {
        .pid = pid_tgid >> 32,
        .fd = (__u32)ret,
    };

    struct fd_entry entry = {};
    entry.pid = key.pid;
    bpf_probe_read_user_str(entry.filename, MAX_STRING_SIZE, (void *)*fname_ptr);

    bpf_map_update_elem(&fd_table, &key, &entry, BPF_ANY);
    return 0;
}

// Hook close to clean up fd tracking
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_key key = {
        .pid = pid_tgid >> 32,
        .fd = (__u32)ctx->args[0],
    };
    bpf_map_delete_elem(&fd_table, &key);
    return 0;
}
