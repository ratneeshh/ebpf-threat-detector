# eBPF Runtime Threat Detector

A lightweight Linux security daemon that hooks directly into kernel
tracepoints via eBPF to detect privilege escalation, sensitive file access,
and dropper-style execution — in real time, from kernel space, with no
agent running in the processes it's watching.

Traditional user-space security agents (antivirus, EDR tools running as a
regular process) can be starved, killed, or simply never see an event that
happens faster than their polling interval. This project takes the
approach modern infrastructure security tools (Cilium, Tetragon, Falco)
use instead: observe syscalls as they happen, inside the kernel, before
they can be hidden or raced.

![status](https://img.shields.io/badge/status-working-brightgreen)
![go](https://img.shields.io/badge/go-1.22-blue)
![kernel](https://img.shields.io/badge/kernel-5.15%2B-lightgrey)

## Demo

![demo](docs/demo.gif)
*(see [Capturing a demo](#capturing-a-demo) below for how this was recorded)*

## What it detects

| Detection | Mechanism | Severity |
|---|---|---|
| **Privilege escalation** | Hooks `sys_enter_setresuid` (what `sudo`/`su` actually call) and flags any transition to UID 0 | High |
| **Dropper / reverse-shell execution** | Hooks `sys_enter_execve`, flags anything run from `/tmp`, `/dev/shm`, or `/var/tmp` | High |
| **Sensitive file access** | Hooks `sys_enter_openat`, flags reads of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, SSH private keys | Medium |

## Architecture

```mermaid
flowchart LR
    subgraph Kernel Space
        A[execve] --> H[bpf/monitor.c]
        B[setresuid] --> H
        C[openat] --> H
        H --> R[(Ring Buffer)]
    end
    subgraph User Space — privileged
        R --> D[cmd/agent<br/>Go daemon]
        D -->|human-readable| L[console log]
        D -->|structured| J[alerts.jsonl]
    end
    subgraph User Space — unprivileged
        J --> W[cmd/dashboard<br/>Go HTTP server]
        W -->|poll every 2s| B2[Browser]
    end
```

The privileged agent (needs root to load eBPF programs) and the dashboard
(needs no privileges at all — it only reads a log file) are deliberately
separate binaries. The only thing that crosses that boundary is a JSON
file. This mirrors how real detection tools are architected: the
privileged collector should be as small and auditable as possible, and
everything else should be able to run unprivileged.

## Project layout

```
.
├── bpf/
│   └── monitor.c           # eBPF program: 3 tracepoints, ring buffer output
├── cmd/
│   ├── agent/
│   │   └── main.go         # loads the eBPF program, applies detection rules,
│   │                       # writes console + alerts.jsonl (needs sudo)
│   └── dashboard/
│       └── main.go         # reads alerts.jsonl, serves a live web view
│                            # (no sudo needed)
├── go.mod
└── README.md
```

## Setup

Tested on Ubuntu 24.04 (kernel 6.8+), should work on any distro with a
BTF-enabled kernel 5.8+.

```bash
# 1. Toolchain
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-$(uname -r) \
    linux-tools-common linux-tools-generic build-essential golang-go

# 2. Confirm your kernel has BTF (needed for CO-RE portability)
ls /sys/kernel/btf/vmlinux   # should exist, no output needed if it does

# 3. Generate the kernel type header from your running kernel's BTF info
cd bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
cd ..

# 4. Fetch Go deps
go mod tidy
```

## Running it

**Terminal 1 — the agent** (needs root to load eBPF programs):
```bash
cd cmd/agent
go generate ./...
go build -o agent .
sudo ./agent
```

**Terminal 2 — the dashboard** (regular user, no sudo):
```bash
cd cmd/dashboard
go build -o dashboard .
./dashboard -alertlog ../agent/alerts.jsonl
```
Open **http://localhost:8080**.

**Terminal 3 — trigger some alerts:**
```bash
sudo -k && sudo whoami                 # privilege escalation + sensitive file access
sudo cat /etc/shadow                   # sensitive file access
cp /bin/ls /tmp/test && /tmp/test      # suspicious exec path
```
Watch either the agent's console output or the dashboard — both update
within about 2 seconds.

## Design decisions worth knowing

**Why debounce alerts?** A single `sudo` invocation genuinely triggers
`openat` on `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` multiple times
through PAM and NSS internals — that's real `sudo` behavior, not a bug.
Without debouncing, one `sudo whoami` produced 8–10 duplicate lines. The
agent suppresses repeat alerts for the same `(pid, kind, detail)` within a
2-second window, so one real event produces one line.

**Why capture broadly in the kernel but filter narrowly in userspace?**
`openat` fires thousands of times per second on a normal desktop. The
eBPF program pushes every event; the Go daemon decides what's worth
surfacing. This is the same design every real runtime security tool uses
— the kernel side stays fast and dumb, the userspace side carries the
(easily updated) logic.

**Why a separate unprivileged dashboard process?** Keeping the attack
surface of "code running as root" as small as possible. The dashboard
never touches eBPF or syscalls — it just tails a file — so it doesn't
need, and doesn't get, elevated privileges.

## Bugs found and fixed along the way

- **String corruption from ring buffer reuse.** Filenames were showing up
  with garbage trailing characters (e.g. `/etc/passwd/pro\!=0`). The ring
  buffer reuses memory between events, so a shorter string's null
  terminator doesn't erase a longer previous string's leftover bytes.
  Fixed by cutting Go strings at the *first* null byte instead of trimming
  trailing nulls.
- **Wrong syscall hooked for privilege escalation.** The first version
  hooked `setuid()`, which never fired when testing `sudo`. Modern `sudo`
  calls `setresuid()` instead. Confirmed by testing against real `sudo`
  behavior rather than assuming the "obvious" syscall was the right one.

## Known limitations / future work

- **False positives from legitimate daemons.** `cron` and `polkitd`
  periodically read `/etc/passwd` as part of normal operation and
  currently show up as alerts. A production version would maintain an
  allowlist of known-benign system processes.
- **Detection only, not prevention.** This hooks tracepoints, which can
  observe but not block. Moving to LSM (Linux Security Module) hooks
  would allow actually denying the syscall, not just alerting on it.
- **Single-host only.** No aggregation across machines — a real deployment
  would ship `alerts.jsonl` to a central collector (the JSON Lines format
  is already ready for that).
- **No container awareness.** Doesn't currently map PIDs to container
  names via cgroup ID, so alerts inside containers show host-level PIDs.

## Capturing a demo

To reproduce the `docs/demo.gif` referenced above:
1. Install a terminal recorder, e.g. [asciinema](https://asciinema.org/) or
   [peek](https://github.com/phw666/peek) (GUI GIF recorder).
2. Arrange the agent terminal and the dashboard browser tab side by side.
3. Record: start the agent, run `sudo -k && sudo whoami`, then
   `cp /bin/ls /tmp/test && /tmp/test`, and let the dashboard update live.
4. Trim to ~15–20 seconds and export as GIF (asciinema → `agg`, or peek
   exports GIF directly).
5. Save as `docs/demo.gif` in this repo.

## Stack

Linux tracepoints (eBPF/CO-RE) · C · Go · `cilium/ebpf` · vanilla
HTML/CSS/JS dashboard