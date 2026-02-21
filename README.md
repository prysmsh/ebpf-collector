# ebpf-collector

Kernel-level security monitoring agent powered by eBPF. Captures process, file, network, and syscall events in real time with zero application instrumentation.

## Features

- **Process monitoring** — exec, fork, exit with full process tree tracking
- **File monitoring** — open, read, write, unlink on sensitive paths
- **Network monitoring** — TCP connect/accept, DNS, with connection tracking
- **Syscall monitoring** — ptrace, mount, setuid, and other security-relevant syscalls
- **TLS inspection** — uprobe-based capture of cleartext from OpenSSL/GnuTLS/NSS
- **Malware detection** — behavioral heuristics (crypto miners, reverse shells, fileless execution)
- **Container enrichment** — automatic container ID, image, and namespace resolution
- **CEL-based rule engine** — flexible detection rules with YAML definitions
- **Mesh topology** — captures service mesh (ztunnel/Istio) connection events
- **Security hardening** — eBPF program signature verification, ring buffer encryption, rate limiting

## Requirements

- Linux kernel 5.8+ (BTF support required)
- Go 1.24+
- Clang/LLVM (for compiling eBPF C programs)

## Quick Start

```bash
# Build
go build -o ebpf-collector .

# Run (requires elevated capabilities)
sudo ./ebpf-collector
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PRYSM_ORG_ID` | Organization ID | — |
| `PRYSM_SINK_ID` | Sink/agent ID | — |
| `PRYSM_ENDPOINT` | Ingestion API endpoint | — |
| `PRYSM_TOKEN` | Authentication token | — |
| `PRYSM_NODE_NAME` | Node identifier | hostname |
| `PRYSM_CLUSTER_ID` | Cluster identifier | — |
| `PRYSM_NAMESPACE` | Kubernetes namespace | `default` |
| `PRYSM_HEARTBEAT_INTERVAL` | Heartbeat frequency | `30s` |
| `PRYSM_MESH_ENABLED` | Enable mesh event forwarding | `false` |
| `PRYSM_MESH_CAPTURE_ALL` | Capture all TCP connections for mesh topology | `false` |
| `PRYSM_PROC_ROOT` | Override `/proc` path (e.g. `/host/proc`) | `/proc` |
| `PRYSM_EBPF_ASSET_DIR` | Path to compiled eBPF `.o` files | `./ebpf` |

## Docker

```bash
docker build -t ebpf-collector .

docker run --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf:ro \
  -v /proc:/host/proc:ro \
  -e PRYSM_PROC_ROOT=/host/proc \
  ebpf-collector
```

For production Kubernetes deployments, see [`hardened-manifest.yaml`](hardened-manifest.yaml) which uses specific capabilities instead of `--privileged`.

## Architecture

```
┌─────────────────────────────────────┐
│           Kernel Space              │
│  ┌──────────┐ ┌──────────────────┐  │
│  │ kprobes  │ │ tracepoints      │  │
│  └────┬─────┘ └────────┬─────────┘  │
│       └───────┬────────┘            │
│          Ring Buffers               │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│         User Space                  │
│  ┌────────────┐ ┌────────────────┐  │
│  │ Event      │ │ Container      │  │
│  │ Processing │ │ Enrichment     │  │
│  └─────┬──────┘ └───────┬────────┘  │
│        └──────┬─────────┘           │
│  ┌────────────▼──────────────────┐  │
│  │ Rule Engine (CEL)             │  │
│  └────────────┬──────────────────┘  │
│  ┌────────────▼──────────────────┐  │
│  │ Output (HTTP / NATS / stdout) │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

## Detection Rules

Rules are defined in YAML under [`rules/builtin/`](rules/builtin/) and evaluated with CEL expressions:

```yaml
- id: reverse_shell
  name: Reverse Shell Detected
  severity: critical
  condition: >
    event.event_type == "exec" &&
    (event.comm == "bash" || event.comm == "sh") &&
    event.args.contains("-i") &&
    (event.args.contains("/dev/tcp") || event.args.contains("nc "))
```

## eBPF Programs

Source files live in [`ebpf/`](ebpf/) and are compiled to `.o` at build time:

| Program | Hook | Events |
|---|---|---|
| `process_monitor.c` | tracepoint `sched_process_exec/exit/fork` | Process lifecycle |
| `file_monitor.c` | kprobe `vfs_open/read/write/unlink` | File access |
| `network_monitor.c` | kprobe `tcp_v4_connect`, tracepoint `net_dev_xmit` | Network connections |
| `syscall_monitor.c` | tracepoint `sys_enter` | Security-sensitive syscalls |
| `tls_monitor.c` | uprobe `SSL_read/SSL_write` | TLS cleartext capture |

## License

Apache 2.0 — see [LICENSE](LICENSE).
