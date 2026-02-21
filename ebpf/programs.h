#ifndef __PRYSM_EBPF_PROGRAMS_H__
#define __PRYSM_EBPF_PROGRAMS_H__

#ifndef __PRYSM_EBPF_TYPES__
#define __PRYSM_EBPF_TYPES__
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#endif

// Event types for security monitoring
#define EVENT_PROCESS_EXEC     1
#define EVENT_NETWORK_CONNECT  2
#define EVENT_FILE_ACCESS      3
#define EVENT_SYSCALL_ANOMALY  4
#define EVENT_CONTAINER_ESCAPE 5
#define EVENT_PROCESS_EXIT     6
#define EVENT_CRED_CHANGE      7
#define EVENT_TLS_DATA         8

// Security levels
#define SECURITY_LEVEL_INFO    0
#define SECURITY_LEVEL_LOW     1
#define SECURITY_LEVEL_MEDIUM  2
#define SECURITY_LEVEL_HIGH    3
#define SECURITY_LEVEL_CRITICAL 4

// TLS capture
#define TLS_DATA_MAX_SIZE      4096
#define TLS_DIR_WRITE          0
#define TLS_DIR_READ           1

// Maximum sizes
#define MAX_STRING_SIZE        256
#define MAX_ARGS_SIZE          512
#define MAX_CONTAINER_ID_SIZE  128
#define MAX_ARGV_ENTRIES       4

// Network direction
#define NET_DIR_OUTBOUND       0
#define NET_DIR_INBOUND        1
#define NET_DIR_LISTEN         2

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Dropped event counter key
#define DROP_COUNTER_KEY 0

// Common event structure
struct security_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 security_level;
    __u32 ppid;       // Parent PID (real_parent->tgid)
    __u32 _pad0;      // Alignment padding
    char comm[16];
    char container_id[MAX_CONTAINER_ID_SIZE];
    union {
        struct {
            char filename[MAX_STRING_SIZE];
            char argv[MAX_ARGS_SIZE];
            __u32 flags;
        } exec;
        struct {
            __u32 family;
            __u32 type;
            __u32 protocol;
            __u32 src_addr[4];
            __u32 dst_addr[4];
            __u16 src_port;
            __u16 dst_port;
            __u8  direction;  // NET_DIR_OUTBOUND, NET_DIR_INBOUND, NET_DIR_LISTEN
            __u8  _pad1[3];
            __u64 bytes_sent;
            __u64 bytes_received;
        } network;
        struct {
            char filename[MAX_STRING_SIZE];
            __u32 flags;
            __u32 mode;
        } file;
        struct {
            __u64 syscall_nr;
            __u64 args[6];
            char description[MAX_STRING_SIZE];
        } syscall;
        struct {
            __u32 old_uid;
            __u32 new_uid;
            __u32 old_gid;
            __u32 new_gid;
            __u64 old_cap_effective;
            __u64 new_cap_effective;
        } cred;
    } data;
};

// Process tracking structure
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 start_time;
    char comm[16];
    char container_id[MAX_CONTAINER_ID_SIZE];
    __u32 suspicious_score;
};

// Network connection tracking
struct network_connection {
    __u32 src_addr[4];
    __u32 dst_addr[4];
    __u16 src_port;
    __u16 dst_port;
    __u32 protocol;
    __u32 pid;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 first_seen;
    __u64 last_seen;
};

// File access tracking
struct file_access {
    char filename[MAX_STRING_SIZE];
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 mode;
    __u64 timestamp;
    __u32 access_count;
};

// File descriptor tracking entry
struct fd_entry {
    char filename[MAX_STRING_SIZE];
    __u32 pid;
};

// FD tracker key
struct fd_key {
    __u32 pid;
    __u32 fd;
};

// TLS data event — emitted via a dedicated ring buffer to avoid
// bloating the main security_event union (4KB payload per event).
struct tls_data_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 ppid;
    __u32 data_len;       // actual captured bytes (≤ TLS_DATA_MAX_SIZE)
    __u8  direction;      // TLS_DIR_WRITE (0) or TLS_DIR_READ (1)
    __u8  _pad[3];
    __u32 fd;
    char  comm[16];
    char  data[TLS_DATA_MAX_SIZE]; // plaintext payload
};

// Arguments saved between SSL_read entry and return probes.
struct ssl_args {
    void *buf;        // user buffer pointer
    __u32 len;        // requested length
    __u32 fd;         // placeholder for FD correlation
};

// Per-PID rate limit entry for TLS capture.
struct tls_rate_limit {
    __u64 window_start;   // nanosecond timestamp of current window
    __u32 count;          // events emitted in current window
    __u32 _pad;
};

#endif /* __PRYSM_EBPF_PROGRAMS_H__ */
