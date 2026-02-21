#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "programs.h"

char LICENSE[] SEC("license") = "GPL";

// ztunnel/Istio ambient mesh ports
#define ZTUNNEL_INBOUND_PORT   15008  // HBONE tunnel port
#define ZTUNNEL_OUTBOUND_PORT  15001  // Envoy outbound
#define ZTUNNEL_INBOUND_PLAIN  15006  // Inbound plaintext
#define ZTUNNEL_METRICS_PORT   15020  // Metrics
#define ZTUNNEL_HEALTH_PORT    15021  // Health check

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB ring buffer
} events SEC(".maps");

// Map to track active connections for byte counting
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // connection tuple hash
    __type(value, struct network_connection);
} connections SEC(".maps");

// Map to pass sock pointer from tcp_v4_connect entry to return probe.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, __u64); // struct sock * (stored as u64)
} tcp_connect_socks SEC(".maps");

// Per-CPU drop counter
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} net_drop_cnt SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 key = DROP_COUNTER_KEY;
    __u64 *val = bpf_map_lookup_elem(&net_drop_cnt, &key);
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

static __inline struct security_event *reserve_event(__u32 event_type)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return NULL;
    }

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

    return event;
}

static __inline void submit_event(struct security_event *event)
{
    if (event)
        bpf_ringbuf_submit(event, 0);
}

// Check if port is ztunnel-related
static __inline int is_ztunnel_port(__u16 port)
{
    return port == ZTUNNEL_INBOUND_PORT ||
           port == ZTUNNEL_OUTBOUND_PORT ||
           port == ZTUNNEL_INBOUND_PLAIN;
}

// Check if an IP belongs to a k8s pod or service CIDR
static __inline int is_cluster_ip(__u32 addr_be)
{
    __u8 *b = (__u8 *)&addr_be;
    // Pod CIDR: 10.42.0.0/16
    if (b[0] == 10 && b[1] == 42)
        return 1;
    // Service CIDR: 10.43.0.0/16
    if (b[0] == 10 && b[1] == 43)
        return 1;
    // Docker compose network: 172.21.0.0/16
    if (b[0] == 172 && b[1] == 21)
        return 1;
    return 0;
}

// Entry probe: save sock pointer for the return probe to use.
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_socks, &pid_tgid, &sk_ptr, BPF_ANY);
    return 0;
}

// Return probe: source IP is now assigned by the kernel's route lookup.
SEC("kretprobe/tcp_v4_connect")
int trace_tcp_connect_ret(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *sk_ptr = bpf_map_lookup_elem(&tcp_connect_socks, &pid_tgid);
    if (!sk_ptr)
        return 0;

    struct sock *sk = (struct sock *)(*sk_ptr);
    bpf_map_delete_elem(&tcp_connect_socks, &pid_tgid);

    // Emit on successful connect: ret == 0 (blocking) or ret == -EINPROGRESS (non-blocking).
    // Most K8s workloads (Go, containerd) use non-blocking sockets, so -EINPROGRESS is the
    // common success path. Only skip on real errors (e.g. -ECONNREFUSED, -ENETUNREACH).
    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115)
        return 0;

    __u32 daddr = 0;
    __u16 dport = 0;
    __u32 saddr = 0;
    __u16 sport = 0;

    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    dport = bpf_ntohs(dport);

    // Emit when: (a) cluster-to-cluster, (b) ztunnel ports, or (c) pod egress
    int cluster_to_cluster = is_cluster_ip(daddr) || is_cluster_ip(saddr);
    int ztunnel = is_ztunnel_port(dport) || is_ztunnel_port(sport);
    int pod_egress = is_cluster_ip(saddr) && !is_cluster_ip(daddr);
    if (!cluster_to_cluster && !ztunnel && !pod_egress) {
        return 0;
    }

    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    event->data.network.family = AF_INET;
    event->data.network.type = SOCK_STREAM;
    event->data.network.protocol = IPPROTO_TCP;
    event->data.network.src_addr[0] = saddr;
    event->data.network.dst_addr[0] = daddr;
    event->data.network.src_port = sport;
    event->data.network.dst_port = dport;
    event->data.network.direction = NET_DIR_OUTBOUND;

    // Mark ztunnel traffic with higher security level for prioritized processing
    if (is_ztunnel_port(dport) || is_ztunnel_port(sport)) {
        event->security_level = SECURITY_LEVEL_LOW;
    }

    submit_event(event);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int trace_tcp_v6_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    __u16 dport = 0;
    __u16 sport = 0;

    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);

    dport = bpf_ntohs(dport);

    // Read IPv6 addresses
    BPF_CORE_READ_INTO(&event->data.network.src_addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&event->data.network.dst_addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

    event->data.network.family = 10; // AF_INET6
    event->data.network.type = SOCK_STREAM;
    event->data.network.protocol = IPPROTO_TCP;
    event->data.network.src_port = sport;
    event->data.network.dst_port = dport;
    event->data.network.direction = NET_DIR_OUTBOUND;

    if (is_ztunnel_port(dport) || is_ztunnel_port(sport)) {
        event->security_level = SECURITY_LEVEL_LOW;
    }

    submit_event(event);
    return 0;
}

// Minimal sockaddr_in for reading from userspace msg_name
struct sockaddr_in_read {
    __u16 sin_family;
    __be16 sin_port;
    __u32 sin_addr;
};

SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!sk || !msg)
        return 0;

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;

    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    dport = bpf_ntohs(dport);

    // For unconnected sockets, read dest from msg->msg_name
    if (daddr == 0 && dport == 0) {
        void *msg_name = NULL;
        BPF_CORE_READ_INTO(&msg_name, msg, msg_name);
        if (msg_name) {
            struct sockaddr_in_read addr;
            if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0 &&
                addr.sin_family == AF_INET) {
                daddr = addr.sin_addr;
                dport = bpf_ntohs(addr.sin_port);
                BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
                BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
            }
        }
    }

    if (dport == 0)
        return 0;

    int cluster_to_cluster = is_cluster_ip(daddr) || is_cluster_ip(saddr);
    int pod_egress = is_cluster_ip(saddr) && !is_cluster_ip(daddr);
    if (!cluster_to_cluster && !pod_egress) {
        return 0;
    }

    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    event->data.network.family = AF_INET;
    event->data.network.type = SOCK_DGRAM;
    event->data.network.protocol = IPPROTO_UDP;
    event->data.network.src_addr[0] = saddr;
    event->data.network.dst_addr[0] = daddr;
    event->data.network.src_port = sport;
    event->data.network.dst_port = dport;
    event->data.network.direction = NET_DIR_OUTBOUND;
    event->data.network.bytes_sent = 0;
    event->data.network.bytes_received = 0;

    submit_event(event);
    return 0;
}

// TCP connection close with byte counters
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u32 daddr = 0;
    __u32 saddr = 0;
    __u16 dport = 0;
    __u16 sport = 0;

    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    dport = bpf_ntohs(dport);

    int cluster_to_cluster = is_cluster_ip(daddr) || is_cluster_ip(saddr);
    int ztunnel = is_ztunnel_port(dport) || is_ztunnel_port(sport);
    int pod_egress = is_cluster_ip(saddr) && !is_cluster_ip(daddr);
    if (!cluster_to_cluster && !ztunnel && !pod_egress) {
        return 0;
    }

    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u64 bytes_sent = 0;
    __u64 bytes_recv = 0;
    BPF_CORE_READ_INTO(&bytes_recv, tp, bytes_received);
    BPF_CORE_READ_INTO(&bytes_sent, tp, bytes_sent);

    event->data.network.family = AF_INET;
    event->data.network.type = SOCK_STREAM;
    event->data.network.protocol = IPPROTO_TCP;
    event->data.network.src_addr[0] = saddr;
    event->data.network.dst_addr[0] = daddr;
    event->data.network.src_port = sport;
    event->data.network.dst_port = dport;
    event->data.network.direction = NET_DIR_OUTBOUND;
    event->data.network.bytes_sent = bytes_sent;
    event->data.network.bytes_received = bytes_recv;
    event->security_level = SECURITY_LEVEL_MEDIUM; // Close event marker

    submit_event(event);
    return 0;
}

// --- Phase 3d: accept/bind/listen hooks for inbound connection detection ---

// inet_csk_accept returns the new accepted sock. Hook the return to get addresses.
SEC("kretprobe/inet_csk_accept")
int trace_inet_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk)
        return 0;

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;

    BPF_CORE_READ_INTO(&saddr, newsk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, newsk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&sport, newsk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, newsk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Emit for all accepted connections (security-relevant: bind shell detection)
    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    event->data.network.family = AF_INET;
    event->data.network.type = SOCK_STREAM;
    event->data.network.protocol = IPPROTO_TCP;
    event->data.network.src_addr[0] = saddr;
    event->data.network.dst_addr[0] = daddr;
    event->data.network.src_port = sport;
    event->data.network.dst_port = dport;
    event->data.network.direction = NET_DIR_INBOUND;

    submit_event(event);
    return 0;
}

// inet_bind: captures when a process binds to a port (listener setup)
SEC("kprobe/inet_bind")
int trace_inet_bind(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    // Read the sockaddr from 2nd argument to get the bind port
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!addr)
        return 0;

    struct sockaddr_in_read sin;
    if (bpf_probe_read_kernel(&sin, sizeof(sin), addr) != 0)
        return 0;

    if (sin.sin_family != AF_INET)
        return 0;

    __u16 port = bpf_ntohs(sin.sin_port);
    if (port == 0)
        return 0;

    struct security_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (!event)
        return 0;

    event->data.network.family = AF_INET;
    event->data.network.type = SOCK_STREAM;
    event->data.network.protocol = IPPROTO_TCP;
    event->data.network.src_addr[0] = sin.sin_addr;
    event->data.network.src_port = port;
    event->data.network.direction = NET_DIR_LISTEN;

    submit_event(event);
    return 0;
}
