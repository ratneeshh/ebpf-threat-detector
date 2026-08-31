//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Event type tags so userspace knows which tracepoint fired.
#define EVENT_EXEC   1
#define EVENT_SETUID 2
#define EVENT_OPEN   3

// Event structure shared with userspace. Keep this in sync with the Go
// `event` struct in cmd/agent/main.go — field order and sizes must match.
struct event {
    __u32 pid;
    __u32 uid;
    __u32 type;
    char comm[16];
    char filename[64]; // only populated for EVENT_OPEN
};

// Ring buffer used to stream events from kernel space to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB, plenty for execve rate
} events SEC(".maps");

// Format for the sys_enter_execve tracepoint — needed to read the
// filename argument (the full path being executed), not just the comm.
struct trace_event_raw_sys_enter_execve {
    __u64 unused;
    __s32 __syscall_nr;
    __u32 pad;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event *e;

    // Reserve space in the ring buffer. If this fails (buffer full),
    // we just drop the event rather than blocking anything.
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = EVENT_EXEC;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Fires whenever a process changes its real/effective/saved UID all at
// once — the mechanism actual sudo/su implementations use (plain setuid()
// is rarely called directly by modern privilege-escalation tools).
struct trace_event_raw_sys_enter_setresuid {
    __u64 unused;
    __s32 __syscall_nr;
    __u32 pad;
    __s32 ruid;
    __s32 euid;
    __s32 suid;
};

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter_setresuid *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = ctx->euid; // the UID being switched TO, not the caller's current UID
    e->type = EVENT_SETUID;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Format for the sys_enter_openat tracepoint's fields — needed to read
// the filename argument correctly. Matches the kernel's tracepoint format
// (check with: sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format)
struct trace_event_raw_sys_enter_openat {
    __u64 unused;
    __s32 __syscall_nr;
    __u32 pad;
    __s32 dfd;
    const char *filename;
    __s32 flags;
    __u16 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = EVENT_OPEN;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read the filename string from userspace memory. bpf_probe_read_user_str
    // is required here (not a plain memcpy) because the pointer points into
    // the calling process's address space, not the kernel's.
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}