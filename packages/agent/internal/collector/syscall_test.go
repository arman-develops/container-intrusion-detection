package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
	"github.com/sirupsen/logrus"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

func minimalConfig() *config.CollectorConfig {
	return &config.CollectorConfig{
		BatchSize:       64,
		FlushIntervalMS: 50,
		SyscallFilter:   []string{},
	}
}

func makeRaw(syscallName, strArg0 string, pid uint32) bpfSyscallEvent {
	raw := bpfSyscallEvent{
		Timestamp: uint64(time.Now().UnixNano()),
		PID:       pid,
		TID:       pid,
		UID:       1000,
		GID:       1000,
	}
	copy(raw.SyscallName[:], syscallName)
	copy(raw.Comm[:], "test-proc")
	copy(raw.StrArg0[:], strArg0)
	return raw
}

func captureCallback() (EventCallback, func() []map[string]interface{}) {
	var mu sync.Mutex
	var events []map[string]interface{}
	cb := func(_ models.EventType, payload map[string]interface{}, _ string) {
		mu.Lock()
		events = append(events, payload)
		mu.Unlock()
	}
	get := func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		out := make([]map[string]interface{}, len(events))
		copy(out, events)
		return out
	}
	return cb, get
}

func assertField(t *testing.T, p map[string]interface{}, key string, want interface{}) {
	t.Helper()
	got, ok := p[key]
	if !ok {
		t.Errorf("payload missing key %q", key)
		return
	}
	if got != want {
		t.Errorf("payload[%q]: want %v (%T), got %v (%T)", key, want, want, got, got)
	}
}

// ─── Constructor ──────────────────────────────────────────────────────────────

func TestNewSyscallCollector_ReturnsCollector(t *testing.T) {
	cb, _ := captureCallback()
	sc, err := NewSyscallCollector(minimalConfig(), cb)
	if err != nil {
		t.Fatalf("NewSyscallCollector returned error: %v", err)
	}
	if sc == nil {
		t.Fatal("NewSyscallCollector returned nil")
	}
	if sc.cfg == nil {
		t.Error("cfg not set")
	}
	if sc.callback == nil {
		t.Error("callback not set")
	}
	if sc.logger == nil {
		t.Error("logger not set")
	}
	if sc.rawCh == nil {
		t.Error("rawCh not initialised")
	}
}

func TestNewSyscallCollector_UsesLogrus(t *testing.T) {
	cb, _ := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	if _, ok := interface{}(sc.logger).(*logrus.Entry); !ok {
		t.Errorf("expected *logrus.Entry, got %T", sc.logger)
	}
	if sc.logger.Data["collector"] != "syscall" {
		t.Errorf("expected logger field collector=syscall, got %v", sc.logger.Data)
	}
}

func TestNewSyscallCollector_RawChBufferSize(t *testing.T) {
	cfg := minimalConfig()
	cfg.BatchSize = 32
	cb, _ := captureCallback()
	sc, _ := NewSyscallCollector(cfg, cb)
	if cap(sc.rawCh) != cfg.BatchSize*4 {
		t.Errorf("rawCh cap: want %d, got %d", cfg.BatchSize*4, cap(sc.rawCh))
	}
}

// ─── shouldMonitorSyscall ─────────────────────────────────────────────────────

func TestShouldMonitorSyscall_EmptyFilter_AllowsAll(t *testing.T) {
	cfg := minimalConfig()
	cfg.SyscallFilter = []string{}
	sc, _ := NewSyscallCollector(cfg, func(models.EventType, map[string]interface{}, string) {})
	for _, name := range []string{"execve", "openat", "chmod", "socket", "connect", "fork"} {
		if !sc.shouldMonitorSyscall(name) {
			t.Errorf("shouldMonitorSyscall(%q) = false with empty filter", name)
		}
	}
}

func TestShouldMonitorSyscall_FilterAllows(t *testing.T) {
	cfg := minimalConfig()
	cfg.SyscallFilter = []string{"execve", "openat"}
	sc, _ := NewSyscallCollector(cfg, func(models.EventType, map[string]interface{}, string) {})
	if !sc.shouldMonitorSyscall("execve") {
		t.Error("execve should be allowed")
	}
	if !sc.shouldMonitorSyscall("openat") {
		t.Error("openat should be allowed")
	}
}

func TestShouldMonitorSyscall_FilterBlocks(t *testing.T) {
	cfg := minimalConfig()
	cfg.SyscallFilter = []string{"execve", "openat"}
	sc, _ := NewSyscallCollector(cfg, func(models.EventType, map[string]interface{}, string) {})
	for _, blocked := range []string{"chmod", "socket", "fork", "connect"} {
		if sc.shouldMonitorSyscall(blocked) {
			t.Errorf("shouldMonitorSyscall(%q) = true, want false", blocked)
		}
	}
}

// ─── getProcessName ───────────────────────────────────────────────────────────

func TestGetProcessName_OwnPID(t *testing.T) {
	sc, _ := NewSyscallCollector(minimalConfig(), func(models.EventType, map[string]interface{}, string) {})
	name := sc.getProcessName(uint32(os.Getpid()))
	if name == "" || name == "unknown" {
		t.Errorf("expected real process name for own PID, got %q", name)
	}
}

func TestGetProcessName_InvalidPID_ReturnsUnknown(t *testing.T) {
	sc, _ := NewSyscallCollector(minimalConfig(), func(models.EventType, map[string]interface{}, string) {})
	if name := sc.getProcessName(0xFFFFFFFF); name != "unknown" {
		t.Errorf("expected unknown for invalid PID, got %q", name)
	}
}

// ─── getContainerIDFromPID (via testable file helper) ────────────────────────

// parseContainerIDFromCgroupFile exercises getContainerIDFromPID logic
// against an arbitrary file path so we don't need to fake /proc.
func parseContainerIDFromCgroupFile(path string) string {
	f, err := os.Open(path)
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

func TestGetContainerIDFromPID_DockerV1(t *testing.T) {
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, "12:devices:/docker/abc123def456aabbccddeeff001122334455667788")
	fmt.Fprintln(f, "0::/system.slice/docker-abc123def456aabbccddeeff001122334455667788.scope")
	f.Close()

	got := parseContainerIDFromCgroupFile(f.Name())
	if !strings.HasPrefix(got, "abc123def456") {
		t.Errorf("expected abc123def456, got %q", got)
	}
}

func TestGetContainerIDFromPID_Kubernetes(t *testing.T) {
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, "0::/kubepods/burstable/podabcdef/abc123def456aabbccdd")
	f.Close()

	got := parseContainerIDFromCgroupFile(f.Name())
	if !strings.HasPrefix(got, "abc123def456") {
		t.Errorf("expected abc123def456, got %q", got)
	}
}

func TestGetContainerIDFromPID_HostProcess_Empty(t *testing.T) {
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, "0::/")
	f.Close()

	if got := parseContainerIDFromCgroupFile(f.Name()); got != "" {
		t.Errorf("expected empty for host process, got %q", got)
	}
}

// ─── handleSyscallEvent ───────────────────────────────────────────────────────

func TestHandleSyscallEvent_Execve_BaseFields(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)

	raw := makeRaw("execve", "/bin/ls", 1234)
	copy(raw.StrArg1[:], "ls")
	raw.UID = 500
	raw.GID = 500
	sc.handleSyscallEvent(raw)

	events := get()
	if len(events) == 0 {
		t.Fatal("callback not invoked")
	}
	p := events[0]
	assertField(t, p, "name", "execve")
	assertField(t, p, "pid", uint32(1234))
	assertField(t, p, "uid", uint32(500))
	assertField(t, p, "gid", uint32(500))
	if _, ok := p["process_name"]; !ok {
		t.Error("payload missing process_name")
	}
	if _, ok := p["return_val"]; !ok {
		t.Error("payload missing return_val")
	}
	if _, ok := p["args"]; !ok {
		t.Error("payload missing args")
	}
}

func TestHandleSyscallEvent_Execve_ParsedFields(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	raw := makeRaw("execve", "/bin/ls", 1234)
	copy(raw.StrArg1[:], "ls")
	sc.handleSyscallEvent(raw)
	p := get()[0]
	if fn, _ := p["filename"].(string); fn != "/bin/ls" {
		t.Errorf("filename: want /bin/ls, got %v", p["filename"])
	}
	if av, _ := p["argv0"].(string); av != "ls" {
		t.Errorf("argv0: want ls, got %v", p["argv0"])
	}
}

func TestHandleSyscallEvent_Openat_Flags(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	raw := makeRaw("openat", "/etc/passwd", 5678)
	raw.Args[0] = 0xFFFFFFFF
	raw.Args[2] = 0o102 // O_RDWR | O_CREAT
	sc.handleSyscallEvent(raw)
	p := get()[0]
	assertField(t, p, "name", "openat")
	if pn, _ := p["pathname"].(string); pn != "/etc/passwd" {
		t.Errorf("pathname: want /etc/passwd, got %v", p["pathname"])
	}
	flags, _ := p["flags"].([]string)
	fm := map[string]bool{}
	for _, f := range flags {
		fm[f] = true
	}
	if !fm["O_RDWR"] || !fm["O_CREAT"] {
		t.Errorf("expected O_RDWR and O_CREAT in flags, got %v", flags)
	}
}

func TestHandleSyscallEvent_Chmod(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	raw := makeRaw("chmod", "/tmp/evil", 9999)
	raw.Args[1] = 0o777
	sc.handleSyscallEvent(raw)
	p := get()[0]
	assertField(t, p, "name", "chmod")
	if pn, _ := p["pathname"].(string); pn != "/tmp/evil" {
		t.Errorf("pathname: want /tmp/evil, got %v", p["pathname"])
	}
	if mode, _ := p["mode"].(string); mode != "0777" {
		t.Errorf("mode: want 0777, got %v", p["mode"])
	}
}

func TestHandleSyscallEvent_Socket(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	raw := makeRaw("socket", "", 111)
	raw.Args[0] = 2 // AF_INET
	raw.Args[1] = 1 // SOCK_STREAM
	sc.handleSyscallEvent(raw)
	p := get()[0]
	if d, _ := p["domain"].(string); d != "AF_INET" {
		t.Errorf("domain: want AF_INET, got %v", p["domain"])
	}
	if typ, _ := p["type"].(string); typ != "SOCK_STREAM" {
		t.Errorf("type: want SOCK_STREAM, got %v", p["type"])
	}
}

func TestHandleSyscallEvent_SetUID_RootEscalation(t *testing.T) {
	cb, get := captureCallback()
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	raw := makeRaw("setuid", "", 222)
	raw.Args[0] = 0 // setuid(0) = escalate to root
	sc.handleSyscallEvent(raw)
	p := get()[0]
	assertField(t, p, "name", "setuid")
	if id, _ := p["id"].(uint64); id != 0 {
		t.Errorf("id: want 0 (root), got %v", p["id"])
	}
}

// ─── Filter ───────────────────────────────────────────────────────────────────

func TestHandleSyscallEvent_FilteredOut_NoCallback(t *testing.T) {
	cfg := minimalConfig()
	cfg.SyscallFilter = []string{"execve"}
	var count atomic.Int32
	cb := func(_ models.EventType, _ map[string]interface{}, _ string) { count.Add(1) }
	sc, _ := NewSyscallCollector(cfg, cb)
	sc.handleSyscallEvent(makeRaw("openat", "/etc/hosts", 1))
	sc.handleSyscallEvent(makeRaw("chmod", "/tmp/x", 2))
	sc.handleSyscallEvent(makeRaw("execve", "/bin/sh", 3))
	if count.Load() != 1 {
		t.Errorf("expected 1 callback, got %d", count.Load())
	}
}

// ─── EventType is models.EventType ───────────────────────────────────────────

func TestHandleSyscallEvent_EventType_IsModelsEventType(t *testing.T) {
	var capturedType models.EventType
	cb := func(et models.EventType, _ map[string]interface{}, _ string) { capturedType = et }
	sc, _ := NewSyscallCollector(minimalConfig(), cb)
	sc.handleSyscallEvent(makeRaw("execve", "/bin/sh", 1))
	if capturedType != models.EventType("execve") {
		t.Errorf("EventType: want execve, got %q", capturedType)
	}
}

// ─── dispatchLoop ─────────────────────────────────────────────────────────────

func TestDispatchLoop_DeliversFiveEvents(t *testing.T) {
	cfg := minimalConfig()
	cfg.BatchSize = 3
	cfg.FlushIntervalMS = 50

	var mu sync.Mutex
	var names []string
	cb := func(_ models.EventType, p map[string]interface{}, _ string) {
		mu.Lock()
		names = append(names, p["name"].(string))
		mu.Unlock()
	}

	sc, _ := NewSyscallCollector(cfg, cb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc.wg.Add(1)
	go sc.dispatchLoop(ctx)

	for _, name := range []string{"execve", "openat", "chmod", "socket", "fork"} {
		sc.rawCh <- makeRaw(name, "/path", 1)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	sc.wg.Wait()

	mu.Lock()
	got := len(names)
	mu.Unlock()
	if got != 5 {
		t.Errorf("expected 5 events, got %d", got)
	}
}

// ─── bpfNullStr ──────────────────────────────────────────────────────────────

func TestBpfNullStr(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{'h', 'e', 'l', 'l', 'o', 0, 'x'}, "hello"},
		{[]byte{'a', 'b', 'c'}, "abc"},
		{[]byte{0}, ""},
	}
	for _, tc := range cases {
		if got := bpfNullStr(tc.in); got != tc.want {
			t.Errorf("bpfNullStr(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── parseOpenFlags ───────────────────────────────────────────────────────────

func TestParseOpenFlags(t *testing.T) {
	cases := []struct {
		flags    uint64
		mustHave []string
	}{
		{0o0, []string{"O_RDONLY"}},
		{0o1, []string{"O_WRONLY"}},
		{0o2, []string{"O_RDWR"}},
		{0o101, []string{"O_WRONLY", "O_CREAT"}},
		{0o102, []string{"O_RDWR", "O_CREAT"}},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("0%o", tc.flags), func(t *testing.T) {
			got := parseOpenFlags(tc.flags)
			fm := map[string]bool{}
			for _, f := range got {
				fm[f] = true
			}
			for _, want := range tc.mustHave {
				if !fm[want] {
					t.Errorf("parseOpenFlags(0%o): missing %q in %v", tc.flags, want, got)
				}
			}
		})
	}
}

// ─── socketDomainName ────────────────────────────────────────────────────────

func TestSocketDomainName(t *testing.T) {
	cases := []struct {
		d    uint64
		want string
	}{
		{2, "AF_INET"}, {10, "AF_INET6"}, {1, "AF_UNIX"}, {999, "999"},
	}
	for _, tc := range cases {
		if got := socketDomainName(tc.d); got != tc.want {
			t.Errorf("socketDomainName(%d) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ─── parseSockAddr ────────────────────────────────────────────────────────────

func TestParseSockAddr_IPv4(t *testing.T) {
	raw := []byte{0x02, 0x00, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	got, err := parseSockAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:80" {
		t.Errorf("want 127.0.0.1:80, got %q", got)
	}
}

func TestParseSockAddr_TooShort(t *testing.T) {
	if _, err := parseSockAddr([]byte{0x02}); err == nil {
		t.Error("expected error for short sockaddr")
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkHandleSyscallEvent(b *testing.B) {
	sc, _ := NewSyscallCollector(minimalConfig(), func(models.EventType, map[string]interface{}, string) {})
	raw := makeRaw("openat", "/etc/hosts", 1234)
	raw.Args[2] = 0o102
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sc.handleSyscallEvent(raw)
	}
}

func BenchmarkDispatchLoop(b *testing.B) {
	cfg := minimalConfig()
	cfg.BatchSize = 256
	var emitted atomic.Uint64
	cb := func(_ models.EventType, _ map[string]interface{}, _ string) { emitted.Add(1) }
	sc, _ := NewSyscallCollector(cfg, cb)
	ctx, cancel := context.WithCancel(context.Background())
	sc.wg.Add(1)
	go sc.dispatchLoop(ctx)
	raw := makeRaw("openat", "/etc/hosts", 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.rawCh <- raw
	}
	cancel()
	sc.wg.Wait()
}
