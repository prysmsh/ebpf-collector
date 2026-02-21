// SPDX-License-Identifier: GPL-2.0
// tls_monitor.c — eBPF uprobes for SSL_read/SSL_write plaintext capture.
//
// Attached dynamically to libssl.so / libgnutls.so via uprobe.
// Events are emitted on a dedicated ring buffer (tls_events) because
// each event carries up to 4 KB of plaintext data.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "programs.h"

// Dedicated ring buffer for TLS data events (8 MB).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} tls_events SEC(".maps");

// Hash map to pass SSL_read arguments from entry to return probe.
// Key: pid_tgid (u64), Value: ssl_args.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct ssl_args);
} ssl_read_args SEC(".maps");

// Per-PID rate limiter: at most N events per second.
// Key: tgid (u32), Value: tls_rate_limit.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct tls_rate_limit);
} tls_rate_map SEC(".maps");

// Configurable rate limit (events per second per PID).
// Userspace can update this via map update; default = 100.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tls_rate_config SEC(".maps");

#define RATE_WINDOW_NS 1000000000ULL  // 1 second in nanoseconds
#define DEFAULT_RATE_LIMIT 100

// check_rate_limit returns 0 if the event should be emitted, -1 if rate-limited.
static __always_inline int check_rate_limit(__u32 tgid) {
    __u64 now = bpf_ktime_get_ns();

    // Look up configured rate limit.
    __u32 key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&tls_rate_config, &key);
    __u32 limit = cfg ? *cfg : DEFAULT_RATE_LIMIT;

    struct tls_rate_limit *rl = bpf_map_lookup_elem(&tls_rate_map, &tgid);
    if (rl) {
        if ((now - rl->window_start) >= RATE_WINDOW_NS) {
            // New window: reset counter.
            rl->window_start = now;
            rl->count = 1;
            return 0;
        }
        if (rl->count >= limit) {
            return -1; // rate limited
        }
        rl->count += 1;
        return 0;
    }

    // First event from this PID: create entry.
    struct tls_rate_limit new_rl = {
        .window_start = now,
        .count = 1,
    };
    bpf_map_update_elem(&tls_rate_map, &tgid, &new_rl, BPF_ANY);
    return 0;
}

// emit_tls_event reads plaintext from user buffer and submits a tls_data_event
// to the ring buffer.
static __always_inline int emit_tls_event(void *buf, __u32 len, __u8 direction) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    if (check_rate_limit(tgid) < 0)
        return 0;

    // Cap at TLS_DATA_MAX_SIZE.
    __u32 capture_len = len;
    if (capture_len > TLS_DATA_MAX_SIZE)
        capture_len = TLS_DATA_MAX_SIZE;
    if (capture_len == 0)
        return 0;

    // Reserve space in ring buffer.
    struct tls_data_event *evt = bpf_ringbuf_reserve(&tls_events,
        sizeof(struct tls_data_event), 0);
    if (!evt)
        return 0;

    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tgid = tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);

    // Read ppid from current task.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt->ppid, sizeof(evt->ppid), &parent->tgid);

    evt->data_len = capture_len;
    evt->direction = direction;
    evt->fd = 0; // FD tracking is optional; zeroed for now.

    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    // Read plaintext from user-space buffer. We must read exactly capture_len
    // bytes (NOT TLS_DATA_MAX_SIZE) because bpf_probe_read_user uses
    // copy_from_user_nofault which fails atomically if ANY byte is
    // inaccessible. Reading past the actual buffer into unmapped pages
    // causes -EFAULT and the event would be discarded.
    //
    // Re-assert upper bound so the verifier can track it past the ringbuf
    // reserve call. capture_len is already in [1, TLS_DATA_MAX_SIZE] from
    // the checks above; this second check makes the verifier see it locally.
    if (capture_len > TLS_DATA_MAX_SIZE) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    long ret = bpf_probe_read_user(evt->data, capture_len, buf);
    if (ret < 0) {
        bpf_printk("tls_mon: probe_read_user failed ret=%ld len=%u", ret, capture_len);
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_printk("tls_mon: submitting event pid=%u dir=%u len=%u", evt->pid, evt->direction, capture_len);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ---- OpenSSL / BoringSSL ----
//
// int SSL_write(SSL *ssl, const void *buf, int num);
// Captures outbound plaintext BEFORE encryption.

SEC("uprobe/SSL_write")
int trace_ssl_write_entry(struct pt_regs *ctx) {
    // arg0 = SSL*, arg1 = buf, arg2 = num
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int   num = (int)PT_REGS_PARM3(ctx);

    bpf_printk("tls_mon: SSL_write entry pid=%d num=%d buf=%lx",
        (__u32)(bpf_get_current_pid_tgid()), num, (unsigned long)buf);

    if (num <= 0)
        return 0;

    return emit_tls_event(buf, (__u32)num, TLS_DIR_WRITE);
}

// int SSL_read(SSL *ssl, void *buf, int num);
// We need the return probe to know how many bytes were actually read.
// Entry: save args.  Return: read buffer.

SEC("uprobe/SSL_read")
int trace_ssl_read_entry(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_args args = {};
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.len = (int)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int trace_ssl_read_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!args)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
        return 0;
    }

    void *buf = args->buf;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    return emit_tls_event(buf, (__u32)ret, TLS_DIR_READ);
}

// ---- GnuTLS ----
//
// ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t sizeofdata);
// ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t sizeofdata);

SEC("uprobe/gnutls_record_send")
int trace_gnutls_send_entry(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int   num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0)
        return 0;

    return emit_tls_event(buf, (__u32)num, TLS_DIR_WRITE);
}

SEC("uprobe/gnutls_record_recv")
int trace_gnutls_recv_entry(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_args args = {};
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.len = (int)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int trace_gnutls_recv_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!args)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
        return 0;
    }

    void *buf = args->buf;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    return emit_tls_event(buf, (__u32)ret, TLS_DIR_READ);
}

char _license[] SEC("license") = "GPL";
