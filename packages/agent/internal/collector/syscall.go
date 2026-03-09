package collector

// syscall.go — eBPF-based syscall collector.
//
// Drop-in replacement for the original stub. Every public symbol, field name,
// logger call, and config reference matches the rest of the collector package.
//
// Build prerequisites (run once per machine / CI image):
//
//	sudo apt-get install -y clang llvm libbpf-dev bpftool
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c \
//	    > agent/internal/collector/headers/vmlinux.h
//
// Then generate the Go eBPF bindings:
//
//	cd agent/internal/collector
//	go generate ./...
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I./bpf" -output-dir . -package collector bpf ./bpf/probes.bpf.c

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// ─── Raw kernel event layout (must stay in sync with probes.bpf.c) ───────────

const (
	bpfTaskCommLen    = 16
	bpfSyscallNameLen = 32
	bpfContainerIDLen = 64
	bpfMaxArgs        = 6
	bpfMaxStringLen   = 256
)

// bpfSyscallEvent mirrors struct syscall_event in probes.bpf.c.
// Field order and sizes must be identical (little-endian, no implicit padding).
type bpfSyscallEvent struct {
	Timestamp   uint64
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	SyscallID   uint32
	_pad        uint32
	Comm        [bpfTaskCommLen]byte
	SyscallName [bpfSyscallNameLen]byte
	Args        [bpfMaxArgs]uint64
	Ret         int64
	ContainerID [bpfContainerIDLen]byte
	StrArg0     [bpfMaxStringLen]byte // path / filename
	StrArg1     [bpfMaxStringLen]byte // argv[0] for execve
}

// ─── EventCallback — identical to the rest of the collector package ───────────

// EventCallback is the type used across all collectors.
// Defined here (once) so filesystem.go, network.go, process.go can reference
// the same type without redeclaring it.
type EventCallback func(eventType models.EventType, payload map[string]interface{}, containerID string)

// ─── SyscallCollector ─────────────────────────────────────────────────────────

// SyscallCollector monitors system calls via eBPF tracepoints.
// Its public API is identical to the original stub so collector.go needs
// no changes at all.
type SyscallCollector struct {
	cfg      *config.CollectorConfig
	callback EventCallback
	logger   *logrus.Entry
	cancel   context.CancelFunc

	// eBPF objects (loaded by go generate / bpf2go)
	objs  *bpfObjects
	links []link.Link

	// Ring buffer reader
	reader *ringbuf.Reader

	// Internal pipeline
	rawCh chan bpfSyscallEvent

	// cgroup-ID → short container ID cache (avoids /proc reads on every event)
	cgroupCache sync.Map // map[uint64]string

	// Metrics counters
	eventsReceived atomic.Uint64
	eventsDropped  atomic.Uint64
	eventsEmitted  atomic.Uint64

	wg sync.WaitGroup
}

// NewSyscallCollector creates a new syscall collector.
// Signature is unchanged from the original stub.
func NewSyscallCollector(cfg *config.CollectorConfig, callback EventCallback) (*SyscallCollector, error) {
	return &SyscallCollector{
		cfg:      cfg,
		callback: callback,
		logger:   logrus.WithField("collector", "syscall"),
		rawCh:    make(chan bpfSyscallEvent, cfg.BatchSize*4),
	}, nil
}

// Start begins syscall monitoring via eBPF.
// Signature is unchanged from the original stub.
func (s *SyscallCollector) Start(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("syscall collector requires root privileges")
	}

	// Verify the kernel is new enough for eBPF ring buffers (≥ 4.18).
	if err := s.checkKernelVersion(4, 18); err != nil {
		return fmt.Errorf("kernel version check failed: %w", err)
	}

	// Remove the memlock rlimit so eBPF maps can be allocated (< kernel 5.11).
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// Load compiled eBPF programs + maps into the kernel.
	s.objs = &bpfObjects{}
	if err := loadBpfObjects(s.objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	// Attach tracepoints for every syscall we monitor.
	if err := s.attachProbes(); err != nil {
		_ = s.objs.Close()
		return fmt.Errorf("attach probes: %w", err)
	}

	// Open the ring buffer reader.
	reader, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.detachProbes()
		_ = s.objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	s.reader = reader

	var innerCtx context.Context
	innerCtx, s.cancel = context.WithCancel(ctx)

	// Two goroutines: one reads raw bytes from the ring buffer, one enriches
	// and dispatches events to the callback.
	s.wg.Add(2)
	go s.readLoop(innerCtx)
	go s.dispatchLoop(innerCtx)

	s.logger.Info("Syscall monitoring started (eBPF)")
	return nil
}

// Stop gracefully shuts down eBPF monitoring and detaches all probes.
// Signature is unchanged from the original stub.
func (s *SyscallCollector) Stop() {
	s.logger.Info("Stopping syscall monitoring")

	if s.cancel != nil {
		s.cancel()
	}

	// Closing the reader unblocks the readLoop immediately.
	if s.reader != nil {
		_ = s.reader.Close()
	}

	s.wg.Wait()
	s.detachProbes()

	if s.objs != nil {
		_ = s.objs.Close()
	}

	s.logger.WithFields(logrus.Fields{
		"received": s.eventsReceived.Load(),
		"dropped":  s.eventsDropped.Load(),
		"emitted":  s.eventsEmitted.Load(),
	}).Info("Syscall collector stopped")
}

// ─── Probe attachment ─────────────────────────────────────────────────────────

type probeSpec struct {
	group   string
	name    string
	program *ebpf.Program
}

func (s *SyscallCollector) attachProbes() error {
	specs := []probeSpec{
		// Execution
		{"syscalls", "sys_enter_execve", s.objs.TraceExecveEnter},
		{"syscalls", "sys_exit_execve", s.objs.TraceExecveExit},
		{"syscalls", "sys_enter_execveat", s.objs.TraceExecveatEnter},
		// File access
		{"syscalls", "sys_enter_open", s.objs.TraceOpenEnter},
		{"syscalls", "sys_enter_openat", s.objs.TraceOpenatEnter},
		{"syscalls", "sys_enter_creat", s.objs.TraceCreatEnter},
		// File modification (sampled in BPF)
		{"syscalls", "sys_enter_write", s.objs.TraceWriteEnter},
		{"syscalls", "sys_enter_writev", s.objs.TraceWritevEnter},
		// Permission changes
		{"syscalls", "sys_enter_chmod", s.objs.TraceChmodEnter},
		{"syscalls", "sys_enter_fchmod", s.objs.TraceFchmodEnter},
		{"syscalls", "sys_enter_fchmodat", s.objs.TraceFchmodatEnter},
		{"syscalls", "sys_enter_chown", s.objs.TraceChownEnter},
		{"syscalls", "sys_enter_fchown", s.objs.TraceFchownEnter},
		{"syscalls", "sys_enter_lchown", s.objs.TraceLchownEnter},
		{"syscalls", "sys_enter_fchownat", s.objs.TraceFchownatEnter},
		// Network
		{"syscalls", "sys_enter_socket", s.objs.TraceSocketEnter},
		{"syscalls", "sys_enter_connect", s.objs.TraceConnectEnter},
		{"syscalls", "sys_enter_bind", s.objs.TraceBindEnter},
		{"syscalls", "sys_enter_listen", s.objs.TraceListenEnter},
		{"syscalls", "sys_enter_accept", s.objs.TraceAcceptEnter},
		{"syscalls", "sys_enter_accept4", s.objs.TraceAccept4Enter},
		// Process creation
		{"syscalls", "sys_enter_clone", s.objs.TraceCloneEnter},
		{"syscalls", "sys_enter_fork", s.objs.TraceForkEnter},
		{"syscalls", "sys_enter_vfork", s.objs.TraceVforkEnter},
		// Privilege changes
		{"syscalls", "sys_enter_setuid", s.objs.TraceSetuidEnter},
		{"syscalls", "sys_enter_setgid", s.objs.TraceSetgidEnter},
		{"syscalls", "sys_enter_setreuid", s.objs.TraceSetreuidEnter},
		{"syscalls", "sys_enter_setregid", s.objs.TraceSetregidEnter},
		{"syscalls", "sys_enter_setresuid", s.objs.TraceSetresuidEnter},
		{"syscalls", "sys_enter_setresgid", s.objs.TraceSetresgidEnter},
		// Capabilities
		{"syscalls", "sys_enter_capset", s.objs.TraceCapsetEnter},
	}

	for _, sp := range specs {
		if sp.program == nil {
			// Tracepoint absent on this architecture — skip silently.
			s.logger.Debugf("Skipping unavailable tracepoint: %s/%s", sp.group, sp.name)
			continue
		}
		l, err := link.Tracepoint(sp.group, sp.name, sp.program, nil)
		if err != nil {
			// Non-fatal: some tracepoints (e.g. sys_enter_open) don't exist on
			// newer kernels that only expose openat. Log and continue.
			s.logger.Warnf("Failed to attach tracepoint %s/%s: %v", sp.group, sp.name, err)
			continue
		}
		s.links = append(s.links, l)
	}

	s.logger.Infof("Attached %d syscall tracepoints", len(s.links))
	return nil
}

func (s *SyscallCollector) detachProbes() {
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil
}

// ─── I/O loops ────────────────────────────────────────────────────────────────

// readLoop reads raw bytes from the eBPF ring buffer and pushes them to rawCh.
func (s *SyscallCollector) readLoop(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.rawCh)

	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			s.logger.Warnf("Ring buffer read error: %v", err)
			continue
		}

		s.eventsReceived.Add(1)

		if len(record.RawSample) < int(unsafe.Sizeof(bpfSyscallEvent{})) {
			s.logger.Warnf("Short ring buffer record (%d bytes), skipping", len(record.RawSample))
			continue
		}

		var ev bpfSyscallEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			s.logger.Warnf("Failed to decode BPF event: %v", err)
			continue
		}

		select {
		case s.rawCh <- ev:
		default:
			s.eventsDropped.Add(1)
			s.logger.Debug("Event queue full — dropping event")
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// dispatchLoop enriches raw events and calls the EventCallback.
func (s *SyscallCollector) dispatchLoop(ctx context.Context) {
	defer s.wg.Done()

	flushTicker := time.NewTicker(time.Duration(s.cfg.FlushIntervalMS) * time.Millisecond)
	defer flushTicker.Stop()

	batch := make([]bpfSyscallEvent, 0, s.cfg.BatchSize)

	flush := func() {
		for _, raw := range batch {
			s.handleSyscallEvent(raw)
		}
		batch = batch[:0]
	}

	for {
		select {
		case raw, ok := <-s.rawCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, raw)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}

		case <-flushTicker.C:
			flush()

		case <-ctx.Done():
			flush()
			return
		}
	}
}

// ─── Event handling (matches the original stub's method name) ────────────────

// handleSyscallEvent enriches a raw BPF event and invokes the callback.
// Method name kept from the original stub.
func (s *SyscallCollector) handleSyscallEvent(raw bpfSyscallEvent) {
	syscallName := bpfNullStr(raw.SyscallName[:])

	// Apply the syscall filter from config (matches shouldMonitorSyscall logic).
	if !s.shouldMonitorSyscall(syscallName) {
		return
	}

	containerID := s.resolveContainerID(raw.PID, raw.ContainerID)

	// getProcessName: prefer the comm captured in-kernel (no /proc round-trip).
	// Fall back to the original stub's /proc/pid/comm method if empty.
	processName := bpfNullStr(raw.Comm[:])
	if processName == "" {
		processName = s.getProcessName(raw.PID)
	}

	payload := s.buildPayload(syscallName, raw, processName)

	s.callback(models.EventType(syscallName), payload, containerID)
	s.eventsEmitted.Add(1)
}

// shouldMonitorSyscall checks cfg.SyscallFilter.
// Method kept from the original stub.
func (s *SyscallCollector) shouldMonitorSyscall(syscallName string) bool {
	if len(s.cfg.SyscallFilter) == 0 {
		return true // no filter → monitor everything
	}
	for _, allowed := range s.cfg.SyscallFilter {
		if allowed == syscallName {
			return true
		}
	}
	return false
}

// getProcessName reads /proc/<pid>/comm.
// Method kept from the original stub.
func (s *SyscallCollector) getProcessName(pid uint32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// getContainerIDFromPID extracts a short Docker/k8s container ID from
// /proc/<pid>/cgroup. Method kept from the original stub.
func (s *SyscallCollector) getContainerIDFromPID(pid uint32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(cgroupPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "docker") && !strings.Contains(line, "kubepods") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		// Walk path segments from right → left looking for a hex ID.
		for _, seg := range reversedSegments(parts[2]) {
			seg = strings.TrimPrefix(seg, "docker-")
			seg = strings.TrimSuffix(seg, ".scope")
			if len(seg) >= 12 && containerIDRe.MatchString(seg) {
				return seg[:12]
			}
		}
	}
	return ""
}

var containerIDRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// ─── Container ID resolution with cache ──────────────────────────────────────

func (s *SyscallCollector) resolveContainerID(pid uint32, cgroupHint [bpfContainerIDLen]byte) string {
	// The BPF program stores the numeric cgroup ID in the first 8 bytes.
	cgroupID := *(*uint64)(unsafe.Pointer(&cgroupHint[0]))

	if cached, ok := s.cgroupCache.Load(cgroupID); ok {
		return cached.(string)
	}

	cid := s.getContainerIDFromPID(pid)
	s.cgroupCache.Store(cgroupID, cid)

	// Prevent unbounded cache growth.
	var count int
	s.cgroupCache.Range(func(_, _ interface{}) bool { count++; return true })
	if count > 8192 {
		s.cgroupCache.Range(func(k, _ interface{}) bool {
			s.cgroupCache.Delete(k)
			count--
			return count > 4096
		})
	}

	return cid
}

// ─── Payload construction ─────────────────────────────────────────────────────

// buildPayload returns the same map shape as the original stub's handleSyscallEvent:
//
//	"name", "pid", "uid", "gid", "args", "return_val", "process_name"
//
// plus syscall-specific parsed fields layered on top.
func (s *SyscallCollector) buildPayload(
	syscallName string,
	raw bpfSyscallEvent,
	processName string,
) map[string]interface{} {
	// Base fields — identical to the original stub.
	payload := map[string]interface{}{
		"name":         syscallName,
		"pid":          raw.PID,
		"uid":          raw.UID,
		"gid":          raw.GID,
		"return_val":   raw.Ret,
		"process_name": processName,
	}

	strArg0 := bpfNullStr(raw.StrArg0[:])
	strArg1 := bpfNullStr(raw.StrArg1[:])

	// Layer syscall-specific parsed fields on top of the base.
	s.parseArgs(payload, syscallName, raw, strArg0, strArg1)

	// args: human-readable slice matching the original stub's "args" key.
	payload["args"] = s.formatArgs(syscallName, raw, strArg0, strArg1)

	return payload
}

// parseArgs adds named fields for each supported syscall.
func (s *SyscallCollector) parseArgs(
	p map[string]interface{},
	name string,
	raw bpfSyscallEvent,
	strArg0, strArg1 string,
) {
	switch name {
	case "execve", "execve_ret":
		if strArg0 != "" {
			p["filename"] = strArg0
		}
		if strArg1 != "" {
			p["argv0"] = strArg1
		}

	case "execveat":
		p["dirfd"] = int32(raw.Args[0])
		p["pathname"] = strArg0
		p["flags"] = raw.Args[4]

	case "open":
		p["pathname"] = strArg0
		p["flags"] = parseOpenFlags(raw.Args[1])
		p["mode"] = fmt.Sprintf("%04o", raw.Args[2])

	case "openat":
		p["dirfd"] = int32(raw.Args[0])
		p["pathname"] = strArg0
		p["flags"] = parseOpenFlags(raw.Args[2])
		p["mode"] = fmt.Sprintf("%04o", raw.Args[3])

	case "creat":
		p["pathname"] = strArg0
		p["mode"] = fmt.Sprintf("%04o", raw.Args[1])

	case "write", "writev":
		p["fd"] = raw.Args[0]
		p["count"] = raw.Args[2]

	case "chmod":
		p["pathname"] = strArg0
		p["mode"] = fmt.Sprintf("%04o", raw.Args[1])

	case "fchmod":
		p["fd"] = raw.Args[0]
		p["mode"] = fmt.Sprintf("%04o", raw.Args[1])

	case "fchmodat":
		p["dirfd"] = int32(raw.Args[0])
		p["pathname"] = strArg0
		p["mode"] = fmt.Sprintf("%04o", raw.Args[2])

	case "chown", "lchown":
		p["pathname"] = strArg0
		p["owner"] = raw.Args[1]
		p["group"] = raw.Args[2]

	case "fchown":
		p["fd"] = raw.Args[0]
		p["owner"] = raw.Args[1]
		p["group"] = raw.Args[2]

	case "fchownat":
		p["dirfd"] = int32(raw.Args[0])
		p["pathname"] = strArg0
		p["owner"] = raw.Args[2]
		p["group"] = raw.Args[3]

	case "socket":
		p["domain"] = socketDomainName(raw.Args[0])
		p["type"] = socketTypeName(raw.Args[1])
		p["protocol"] = raw.Args[2]

	case "connect", "bind":
		p["sockfd"] = raw.Args[0]
		if addr, err := parseSockAddr(raw.StrArg0[:]); err == nil {
			p["addr"] = addr
		}

	case "listen":
		p["sockfd"] = raw.Args[0]
		p["backlog"] = raw.Args[1]

	case "accept", "accept4":
		p["sockfd"] = raw.Args[0]

	case "clone":
		p["clone_flags"] = fmt.Sprintf("0x%x", raw.Args[0])

	case "setuid", "setgid":
		p["id"] = raw.Args[0]

	case "setreuid", "setregid":
		p["real"] = int32(raw.Args[0])
		p["effective"] = int32(raw.Args[1])

	case "setresuid", "setresgid":
		p["real"] = int32(raw.Args[0])
		p["effective"] = int32(raw.Args[1])
		p["saved"] = int32(raw.Args[2])

	case "capset":
		p["header_ptr"] = raw.Args[0]
		p["data_ptr"] = raw.Args[1]
	}
}

// formatArgs produces the "args" slice that the original stub put in the payload
// so existing consumers (publisher, rules engine) are unaffected.
func (s *SyscallCollector) formatArgs(name string, raw bpfSyscallEvent, strArg0, strArg1 string) []string {
	switch name {
	case "execve":
		return []string{strArg0, strArg1}
	case "open", "creat":
		return []string{strArg0, fmt.Sprintf("0x%x", raw.Args[1])}
	case "openat":
		return []string{fmt.Sprintf("%d", int32(raw.Args[0])), strArg0, fmt.Sprintf("0x%x", raw.Args[2])}
	case "chmod", "fchmodat":
		return []string{strArg0, fmt.Sprintf("%04o", raw.Args[1])}
	case "connect", "bind":
		if addr, err := parseSockAddr(raw.StrArg0[:]); err == nil {
			return []string{fmt.Sprintf("%d", raw.Args[0]), addr}
		}
		return []string{fmt.Sprintf("%d", raw.Args[0])}
	default:
		out := make([]string, bpfMaxArgs)
		for i, a := range raw.Args {
			out[i] = fmt.Sprintf("0x%x", a)
		}
		return out
	}
}

// ─── Kernel helpers ───────────────────────────────────────────────────────────

func (s *SyscallCollector) checkKernelVersion(major, minor int) error {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	release := strings.TrimSpace(string(data))
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("cannot parse kernel version %q", release)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return err
	}
	// Strip everything after the first non-digit in minor component.
	minStr := parts[1]
	for i, c := range minStr {
		if c < '0' || c > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err := strconv.Atoi(minStr)
	if err != nil {
		return err
	}
	if maj < major || (maj == major && min < minor) {
		return fmt.Errorf("kernel %d.%d is below minimum %d.%d required for eBPF ring buffers",
			maj, min, major, minor)
	}
	return nil
}

// ─── Syscall argument helpers ─────────────────────────────────────────────────

func parseOpenFlags(flags uint64) []string {
	var result []string
	f := int(flags)
	switch f & 0x3 {
	case unix.O_RDONLY:
		result = append(result, "O_RDONLY")
	case unix.O_WRONLY:
		result = append(result, "O_WRONLY")
	case unix.O_RDWR:
		result = append(result, "O_RDWR")
	}
	bits := map[int]string{
		unix.O_CREAT:    "O_CREAT",
		unix.O_EXCL:     "O_EXCL",
		unix.O_TRUNC:    "O_TRUNC",
		unix.O_APPEND:   "O_APPEND",
		unix.O_NONBLOCK: "O_NONBLOCK",
		unix.O_SYNC:     "O_SYNC",
		unix.O_CLOEXEC:  "O_CLOEXEC",
		unix.O_TMPFILE:  "O_TMPFILE",
	}
	for bit, name := range bits {
		if f&bit != 0 {
			result = append(result, name)
		}
	}
	return result
}

func socketDomainName(d uint64) string {
	m := map[uint64]string{
		unix.AF_INET: "AF_INET", unix.AF_INET6: "AF_INET6",
		unix.AF_UNIX: "AF_UNIX", unix.AF_NETLINK: "AF_NETLINK",
	}
	if s, ok := m[d]; ok {
		return s
	}
	return strconv.FormatUint(d, 10)
}

func socketTypeName(t uint64) string {
	base := t &^ uint64(unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
	names := map[uint64]string{
		unix.SOCK_STREAM: "SOCK_STREAM", unix.SOCK_DGRAM: "SOCK_DGRAM",
		unix.SOCK_RAW: "SOCK_RAW", unix.SOCK_SEQPACKET: "SOCK_SEQPACKET",
	}
	name, ok := names[base]
	if !ok {
		name = strconv.FormatUint(base, 10)
	}
	if t&uint64(unix.SOCK_NONBLOCK) != 0 {
		name += "|SOCK_NONBLOCK"
	}
	if t&uint64(unix.SOCK_CLOEXEC) != 0 {
		name += "|SOCK_CLOEXEC"
	}
	return name
}

func parseSockAddr(raw []byte) (string, error) {
	if len(raw) < 2 {
		return "", errors.New("short sockaddr")
	}
	family := binary.LittleEndian.Uint16(raw[:2])
	switch family {
	case unix.AF_INET:
		if len(raw) < 8 {
			return "", errors.New("short AF_INET sockaddr")
		}
		port := binary.BigEndian.Uint16(raw[2:4])
		return fmt.Sprintf("%s:%d", net.IP(raw[4:8]), port), nil
	case unix.AF_INET6:
		if len(raw) < 28 {
			return "", errors.New("short AF_INET6 sockaddr")
		}
		port := binary.BigEndian.Uint16(raw[2:4])
		return fmt.Sprintf("[%s]:%d", net.IP(raw[8:24]), port), nil
	case unix.AF_UNIX:
		return fmt.Sprintf("unix:%s", bpfNullStr(raw[2:])), nil
	}
	return fmt.Sprintf("family=%d", family), nil
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func bpfNullStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func reversedSegments(path string) []string {
	segs := strings.Split(path, "/")
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	return segs
}
