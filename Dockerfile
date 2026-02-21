FROM golang:1.24-alpine AS builder

RUN apk add --no-cache clang llvm lld linux-headers libbpf-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile eBPF programs from source (ensures .o files match .c sources)
RUN cd ebpf && for f in network_monitor.c process_monitor.c file_monitor.c syscall_monitor.c; do \
      [ -f "$f" ] && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c "$f" -o "${f%.c}.o" ; \
    done

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ebpf-collector .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /src/ebpf-collector /usr/bin/ebpf-collector
COPY --from=builder /src/ebpf /app/ebpf
COPY --from=builder /src/rules/builtin /app/rules/builtin

ENV PRYSM_EBPF_ASSET_DIR=/app/ebpf

USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/ebpf-collector"]
