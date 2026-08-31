// This generates Go bindings from bpf/monitor.c using bpf2go.
// Run `go generate ./...` after editing the C file.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target amd64 monitor ../../bpf/monitor.c -- -I../../bpf

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// event mirrors the C `struct event` in bpf/monitor.c byte-for-byte.
type event struct {
	Pid      uint32
	Uid      uint32
	Type     uint32
	Comm     [16]byte
	Filename [64]byte
}

const (
	eventExec   = 1
	eventSetuid = 2
	eventOpen   = 3
)

// sensitivePaths is intentionally a small starter list. Grow this as you
// find more paths worth watching (e.g. ~/.aws/credentials, /etc/cron.d).
var sensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	".ssh/authorized_keys",
	".ssh/id_rsa",
}

func isSensitivePath(path string) bool {
	for _, p := range sensitivePaths {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// suspiciousExecDirs are world-writable locations that legitimate software
// essentially never executes binaries from directly. A process launched
// from one of these is a classic dropper / reverse-shell pattern.
var suspiciousExecDirs = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
}

func isSuspiciousExecPath(path string) bool {
	for _, dir := range suspiciousExecDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// debounce suppresses repeated alerts for the same (pid, kind, detail)
// combination within a short window. Real tools like sudo legitimately
// trigger the same syscall many times in a row (PAM stacks, NSS lookups),
// so without this every human-facing alert would be an unreadable spam
// burst instead of one clear line per actual event.
type debounce struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
}

func newDebounce(window time.Duration) *debounce {
	return &debounce{window: window, seen: make(map[string]time.Time)}
}

// allow reports whether this key should be printed now, and records it.
func (d *debounce) allow(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[key] = now
	return true
}

// Alert is the structured form of every [ALERT] line, written as one JSON
// object per line to alerts.jsonl. This format (JSON Lines / NDJSON) is
// the standard for log shipping — it's what you'd feed to a webhook,
// Elasticsearch, Loki, or a `jq`-based dashboard without any conversion.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`     // "privilege_escalation" | "sensitive_file_access" | "suspicious_exec"
	Severity  string    `json:"severity"` // "high" | "medium"
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	Comm      string    `json:"comm"`
	Detail    string    `json:"detail"` // the file path or exec path involved, when applicable
}

// alertLog appends structured alerts to a JSON Lines file. A plain
// *os.File plus json.Encoder is enough here — we're append-only and never
// need to read the file back within the process.
type alertLog struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newAlertLog(path string) (*alertLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &alertLog{enc: json.NewEncoder(f)}, nil
}

func (a *alertLog) write(al Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(al); err != nil {
		log.Printf("writing alert log: %v", err)
	}
}

// cString truncates a fixed-size byte array at the first null terminator.
// bytes.TrimRight only strips trailing \x00 bytes, which isn't enough here:
// the ring buffer reuses memory between events, so leftover bytes from a
// previous, longer string can sit right after this string's null
// terminator. Cutting at the *first* null is the correct C-string read.
func cString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}

func main() {
	// Older kernels enforce a memlock rlimit that blocks BPF map creation.
	// Harmless no-op on modern kernels, but keep it for portability.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	var objs monitorObjects
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the compiled program to each tracepoint we care about.
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attaching execve tracepoint: %v", err)
	}
	defer tpExec.Close()

	tpSetresuid, err := link.Tracepoint("syscalls", "sys_enter_setresuid", objs.HandleSetresuid, nil)
	if err != nil {
		log.Fatalf("attaching setresuid tracepoint: %v", err)
	}
	defer tpSetresuid.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("attaching openat tracepoint: %v", err)
	}
	defer tpOpen.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Handle Ctrl+C cleanly so deferred Close() calls actually run and
	// unload the eBPF program instead of leaking it.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		rd.Close()
	}()

	log.Println("watching for execve, setuid, and sensitive file access... (Ctrl+C to stop)")

	// -alertlog lets you point output anywhere; default keeps it next to
	// the binary regardless of the shell's current working directory, so
	// "where did my alerts go" is never a mystery.
	alertLogPath := flag.String("alertlog", "alerts.jsonl", "path to write structured JSON alerts")
	flag.Parse()

	// One alert per (pid, kind, detail) at most every 2 seconds. Plain
	// [EXEC] lines are left unthrottled since they're routine telemetry,
	// not alerts.
	alerts := newDebounce(2 * time.Second)

	alertLogger, err := newAlertLog(*alertLogPath)
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	if abs, err := filepath.Abs(*alertLogPath); err == nil {
		log.Printf("writing structured alerts to %s", abs)
	} else {
		log.Printf("writing structured alerts to %s", *alertLogPath)
	}

	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			log.Println("stopping: reader closed")
			return
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		comm := cString(e.Comm[:])

		switch e.Type {
		case eventExec:
			path := cString(e.Filename[:])
			if isSuspiciousExecPath(path) {
				key := fmt.Sprintf("exec:%d:%s", e.Pid, path)
				if alerts.allow(key) {
					log.Printf("[ALERT]  execution from suspicious path: PID=%-8d UID=%-6d COMM=%s PATH=%s", e.Pid, e.Uid, comm, path)
					alertLogger.write(Alert{
						Timestamp: time.Now(),
						Kind:      "suspicious_exec",
						Severity:  "high",
						PID:       e.Pid,
						UID:       e.Uid,
						Comm:      comm,
						Detail:    path,
					})
				}
			}
			// Routine execs (the overwhelming majority) are intentionally
			// not logged — a shell or binary launching from a normal
			// location isn't a security signal by itself.

		case eventSetuid:
			// Any UID transition to 0 that isn't the well-known sudo/su
			// binaries is worth a second look.
			if e.Uid == 0 {
				key := fmt.Sprintf("setuid:%d:%s", e.Pid, comm)
				if alerts.allow(key) {
					log.Printf("[ALERT]  privilege escalation to root: PID=%-8d COMM=%s", e.Pid, comm)
					alertLogger.write(Alert{
						Timestamp: time.Now(),
						Kind:      "privilege_escalation",
						Severity:  "high",
						PID:       e.Pid,
						UID:       e.Uid,
						Comm:      comm,
					})
				}
			} else {
				log.Printf("[SETUID] PID=%-8d UID=%-6d COMM=%s", e.Pid, e.Uid, comm)
			}

		case eventOpen:
			filename := cString(e.Filename[:])
			if isSensitivePath(filename) {
				key := fmt.Sprintf("open:%d:%s", e.Pid, filename)
				if alerts.allow(key) {
					log.Printf("[ALERT]  sensitive file accessed: PID=%-8d UID=%-6d COMM=%s FILE=%s", e.Pid, e.Uid, comm, filename)
					alertLogger.write(Alert{
						Timestamp: time.Now(),
						Kind:      "sensitive_file_access",
						Severity:  "medium",
						PID:       e.Pid,
						UID:       e.Uid,
						Comm:      comm,
						Detail:    filename,
					})
				}
			}
			// Non-sensitive opens are dropped here — logging every file
			// open would be thousands of lines per second. This is the
			// core design decision every runtime security tool makes:
			// capture broadly in the kernel, filter narrowly in userspace.
		}
	}
}