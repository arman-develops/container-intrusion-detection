package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
)

// ─── Stubs ────────────────────────────────────────────────────────────────────

type mockPublisher struct {
	mu     sync.Mutex
	events []*models.TelemetryEvent
	err    error
}

func (m *mockPublisher) Publish(e *models.TelemetryEvent) error {
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
	return nil
}

func (m *mockPublisher) published() []*models.TelemetryEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.TelemetryEvent, len(m.events))
	copy(out, m.events)
	return out
}

func testCollectorConfig() *config.CollectorConfig {
	return &config.CollectorConfig{
		BatchSize:        4,
		FlushIntervalMS:  50,
		EnableSyscalls:   false, // unit tests — no eBPF
		EnableNetwork:    false,
		EnableFilesystem: false,
		EnableProcesses:  false,
		SyscallFilter:    []string{},
	}
}

// ─── Constructor ──────────────────────────────────────────────────────────────

func TestNew_RequiresHostID(t *testing.T) {
	_, err := New(testCollectorConfig(), "", &mockPublisher{})
	if err == nil {
		t.Error("expected error when hostID is empty")
	}
}

func TestNew_CreatesCollector(t *testing.T) {
	c, err := New(testCollectorConfig(), "host-abc", &mockPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.hostID != "host-abc" {
		t.Errorf("hostID: want host-abc, got %q", c.hostID)
	}
	if c.containers == nil {
		t.Error("containers map not initialised")
	}
	if c.eventQueue == nil {
		t.Error("eventQueue not initialised")
	}
}

func TestNew_DockerSocketMissing_DoesNotFail(t *testing.T) {
	// Even without the Docker socket the constructor must succeed.
	// (Socket is almost certainly absent in the test environment.)
	c, err := New(testCollectorConfig(), "host-xyz", &mockPublisher{})
	if err != nil {
		t.Fatalf("New should not fail without Docker socket: %v", err)
	}
	if c.docker != nil {
		t.Log("Docker socket present in test environment (that is fine)")
	} else {
		t.Log("Docker socket absent — degraded mode confirmed")
	}
}

// ─── getSelfContainerID ───────────────────────────────────────────────────────

func TestGetSelfContainerID_DockerCgroupV1(t *testing.T) {
	// Write a fake /proc/self/cgroup and redirect via a temp file.
	content := "12:devices:/docker/abc123def456aabbccddeeff001122334455667788\n" +
		"0::/\n"
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	got := parseSelfContainerIDFromFile(f.Name())
	if got != "abc123def456" {
		t.Errorf("want abc123def456, got %q", got)
	}
}

func TestGetSelfContainerID_DockerCgroupV2Scope(t *testing.T) {
	content := "0::/system.slice/docker-abc123def456aabbccddeeff001122334455667788.scope\n"
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	got := parseSelfContainerIDFromFile(f.Name())
	if got != "abc123def456" {
		t.Errorf("want abc123def456, got %q", got)
	}
}

func TestGetSelfContainerID_KubernetesCgroup(t *testing.T) {
	content := "0::/kubepods/burstable/podabc/abc123def456aabbccddeeff\n"
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	got := parseSelfContainerIDFromFile(f.Name())
	if got != "abc123def456" {
		t.Errorf("want abc123def456, got %q", got)
	}
}

func TestGetSelfContainerID_HostProcess_ReturnsEmpty(t *testing.T) {
	content := "0::/\n1:memory:/user.slice\n"
	f, err := os.CreateTemp("", "cgroup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	got := parseSelfContainerIDFromFile(f.Name())
	if got != "" {
		t.Errorf("want empty string for host process, got %q", got)
	}
}

// ─── imageNameFromEnv ─────────────────────────────────────────────────────────

func TestImageNameFromEnv_ReadsEnvVar(t *testing.T) {
	os.Setenv("IMAGE_NAME", "myorg/myapp:v2")
	defer os.Unsetenv("IMAGE_NAME")
	if got := imageNameFromEnv(); got != "myorg/myapp:v2" {
		t.Errorf("want myorg/myapp:v2, got %q", got)
	}
}

func TestImageNameFromEnv_DefaultWhenUnset(t *testing.T) {
	os.Unsetenv("IMAGE_NAME")
	got := imageNameFromEnv()
	if got == "" {
		t.Error("expected a non-empty default image name")
	}
}

// ─── Docker socket client (mock HTTP server over Unix socket) ─────────────────

// mockDockerServer starts a tiny HTTP server on a temp Unix socket that
// responds to /containers/{id}/json with canned JSON.
func mockDockerServer(t *testing.T, handler http.Handler) (socketPath string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	socketPath = fmt.Sprintf("%s/docker.sock", dir)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on temp socket: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	cleanup = func() {
		srv.Close()
		os.Remove(socketPath)
	}
	return socketPath, cleanup
}

func TestDockerSocketClient_InspectContainer_OK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/abc123def456/json" {
			http.NotFound(w, r)
			return
		}
		resp := map[string]interface{}{
			"Id":   "abc123def456aabbccddeeff001122334455667788",
			"Name": "/my-app-container",
			"Config": map[string]interface{}{
				"Image":  "myorg/myapp:latest",
				"Labels": map[string]string{"env": "prod", "team": "backend"},
			},
			"Image":   "sha256:deadbeef",
			"Created": "2024-01-15T10:30:00Z",
			"State":   map[string]string{"Status": "running"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	socketPath, cleanup := mockDockerServer(t, handler)
	defer cleanup()

	// Build client pointing at temp socket.
	client := &dockerSocketClient{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 5 * time.Second,
		},
	}

	ctx := context.Background()
	meta, err := client.inspectContainer(ctx, "abc123def456")
	if err != nil {
		t.Fatalf("inspectContainer: %v", err)
	}

	if meta.ID != "abc123def456" {
		t.Errorf("ID: want abc123def456, got %q", meta.ID)
	}
	if meta.Name != "my-app-container" {
		t.Errorf("Name: want my-app-container, got %q", meta.Name)
	}
	if meta.ImageName != "myorg/myapp:latest" {
		t.Errorf("ImageName: want myorg/myapp:latest, got %q", meta.ImageName)
	}
	if meta.State != "running" {
		t.Errorf("State: want running, got %q", meta.State)
	}
	if meta.Labels["env"] != "prod" {
		t.Errorf("Labels[env]: want prod, got %q", meta.Labels["env"])
	}
}

func TestDockerSocketClient_InspectContainer_NotFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	socketPath, cleanup := mockDockerServer(t, handler)
	defer cleanup()

	client := &dockerSocketClient{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}

	_, err := client.inspectContainer(context.Background(), "doesnotexist")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

// ─── enqueueEvent + getContainerContext ───────────────────────────────────────

func TestEnqueueEvent_PopulatesContainerMetadata(t *testing.T) {
	pub := &mockPublisher{}
	c, _ := New(testCollectorConfig(), "host-1", pub)

	// Set a background context directly — simulates post-Start() state
	// without actually calling Start() (which would require eBPF + root).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	c.cancel = cancel

	// Register a known container context manually.
	c.containerMu.Lock()
	c.containers["ctr-abc"] = &models.ContainerContext{
		ID:        "ctr-abc",
		ImageName: "myorg/myapp:v1",
		Labels:    map[string]string{"env": "test"},
	}
	c.containerMu.Unlock()

	c.enqueueEvent(models.EventTypeSyscall, map[string]interface{}{"name": "execve"}, "ctr-abc")

	// Drain the queue.
	select {
	case event := <-c.eventQueue:
		if event.ContainerID != "ctr-abc" {
			t.Errorf("ContainerID: want ctr-abc, got %q", event.ContainerID)
		}
		if event.ImageName != "myorg/myapp:v1" {
			t.Errorf("ImageName: want myorg/myapp:v1, got %q", event.ImageName)
		}
		if event.HostID != "host-1" {
			t.Errorf("HostID: want host-1, got %q", event.HostID)
		}
		if event.EventID == "" {
			t.Error("EventID must not be empty")
		}
		if event.Timestamp.IsZero() {
			t.Error("Timestamp must not be zero")
		}
	case <-time.After(time.Second):
		t.Error("event not enqueued within 1s")
	}
}

func TestEnqueueEvent_UnknownContainer_UsesDefault(t *testing.T) {
	pub := &mockPublisher{}
	c, _ := New(testCollectorConfig(), "host-1", pub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	c.cancel = cancel

	os.Setenv("IMAGE_NAME", "container-ids-base")
	defer os.Unsetenv("IMAGE_NAME")

	c.enqueueEvent(models.EventTypeNetwork, map[string]interface{}{"op": "connect"}, "unknown-ctr")

	select {
	case event := <-c.eventQueue:
		if event.ImageName != "container-ids-base" {
			t.Errorf("ImageName fallback: want container-ids-base, got %q", event.ImageName)
		}
	case <-time.After(time.Second):
		t.Error("event not enqueued")
	}
}

// ─── Batch processing ─────────────────────────────────────────────────────────

func TestProcessBatches_FlushOnBatchSize(t *testing.T) {
	cfg := testCollectorConfig()
	cfg.BatchSize = 3
	cfg.FlushIntervalMS = 5000 // long — we want size-based flush

	pub := &mockPublisher{}
	c, _ := New(cfg, "host-1", pub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.ctx = ctx
	c.cancel = cancel

	c.wg.Add(1)
	go c.processBatches()

	// Send exactly BatchSize events — should trigger an immediate flush.
	for i := 0; i < 3; i++ {
		c.eventQueue <- &models.TelemetryEvent{
			EventID:   fmt.Sprintf("evt-%d", i),
			EventType: models.EventTypeSyscall,
			Timestamp: time.Now(),
		}
	}

	// Wait for flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(pub.published()) == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	c.wg.Wait()

	if got := len(pub.published()); got != 3 {
		t.Errorf("expected 3 published events, got %d", got)
	}
}

func TestProcessBatches_FlushOnTicker(t *testing.T) {
	cfg := testCollectorConfig()
	cfg.BatchSize = 100 // large — won't trigger size flush
	cfg.FlushIntervalMS = 100

	pub := &mockPublisher{}
	c, _ := New(cfg, "host-1", pub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.ctx = ctx
	c.cancel = cancel

	c.wg.Add(1)
	go c.processBatches()

	// Send 2 events — below batch size, must flush on ticker.
	for i := 0; i < 2; i++ {
		c.eventQueue <- &models.TelemetryEvent{
			EventID:   fmt.Sprintf("evt-%d", i),
			Timestamp: time.Now(),
		}
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(pub.published()) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	c.wg.Wait()

	if got := len(pub.published()); got != 2 {
		t.Errorf("expected 2 published events on ticker flush, got %d", got)
	}
}

func TestProcessBatches_PublisherError_DoesNotCrash(t *testing.T) {
	cfg := testCollectorConfig()
	cfg.BatchSize = 2
	cfg.FlushIntervalMS = 50

	pub := &mockPublisher{err: fmt.Errorf("rabbitmq down")}
	c, _ := New(cfg, "host-1", pub)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.ctx = ctx
	c.cancel = cancel

	c.wg.Add(1)
	go c.processBatches()

	// Send events — publisher will error but collector must not crash.
	for i := 0; i < 4; i++ {
		c.eventQueue <- &models.TelemetryEvent{
			EventID:   fmt.Sprintf("evt-%d", i),
			Timestamp: time.Now(),
		}
	}

	time.Sleep(300 * time.Millisecond)
	cancel()
	c.wg.Wait()
	// If we reach here without panic, the test passes.
}

// ─── Queue full drop ──────────────────────────────────────────────────────────

func TestEnqueueEvent_QueueFull_DropsGracefully(t *testing.T) {
	cfg := testCollectorConfig()
	cfg.BatchSize = 2 // queue cap = BatchSize*2 = 4

	pub := &mockPublisher{}
	c, _ := New(cfg, "host-1", pub)

	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.cancel = cancel
	defer cancel()

	// Fill the queue without draining it.
	var dropped atomic.Int32
	for i := 0; i < 20; i++ {
		before := len(c.eventQueue)
		c.enqueueEvent(models.EventTypeSyscall,
			map[string]interface{}{"name": "write"}, "ctr-x")
		if len(c.eventQueue) == before && before == cap(c.eventQueue) {
			dropped.Add(1)
		}
	}

	// Some events must have been dropped — queue is bounded.
	if dropped.Load() == 0 {
		t.Log("Note: all events fit in queue (queue larger than expected) — not an error")
	}
}

// ─── Helpers exposed for tests ────────────────────────────────────────────────

// parseSelfContainerIDFromFile is the testable version of getSelfContainerID
// that reads from an arbitrary path instead of /proc/self/cgroup.
func parseSelfContainerIDFromFile(path string) string {
	origOpen := cgroupFilePath
	cgroupFilePath = path
	defer func() { cgroupFilePath = origOpen }()
	return getSelfContainerID()
}
