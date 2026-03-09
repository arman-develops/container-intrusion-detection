package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Publisher interface for sending events
type Publisher interface {
	Publish(event *models.TelemetryEvent) error
}

// Collector aggregates events from various sources
type Collector struct {
	cfg       *config.CollectorConfig
	hostID    string
	publisher Publisher
	logger    *logrus.Entry

	// Event collectors
	syscallCollector    *SyscallCollector
	networkCollector    *NetworkCollector
	filesystemCollector *FilesystemCollector
	processCollector    *ProcessCollector

	// Batching
	eventQueue chan *models.TelemetryEvent
	batchMu    sync.Mutex
	batch      []*models.TelemetryEvent

	// Container tracking — agent knows about itself + any it discovers
	containers  map[string]*models.ContainerContext
	containerMu sync.RWMutex

	// Docker socket client (nil if socket not mounted)
	docker *dockerSocketClient

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new event collector
func New(cfg *config.CollectorConfig, hostID string, publisher Publisher) (*Collector, error) {
	if hostID == "" {
		return nil, fmt.Errorf("host ID is required")
	}

	c := &Collector{
		cfg:        cfg,
		hostID:     hostID,
		publisher:  publisher,
		logger:     logrus.WithField("component", "collector"),
		eventQueue: make(chan *models.TelemetryEvent, cfg.BatchSize*2),
		batch:      make([]*models.TelemetryEvent, 0, cfg.BatchSize),
		containers: make(map[string]*models.ContainerContext),
	}

	// Try to connect to Docker socket — non-fatal if not mounted.
	// The agent degrades gracefully: container ID still comes from cgroup,
	// but image name and labels won't be available.
	docker, err := newDockerSocketClient()
	if err != nil {
		c.logger.Warnf("Docker socket unavailable (%v) — container metadata will be limited", err)
	} else {
		c.docker = docker
		c.logger.Info("Docker socket connected — full container metadata available")
	}

	return c, nil
}

// Start begins collecting events
func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Discover own container context on startup.
	// This is self-discovery: the agent is inside the container it monitors.
	if err := c.discoverContainers(); err != nil {
		c.logger.Warnf("Initial container discovery failed: %v", err)
	}

	// Initialize syscall collector
	if c.cfg.EnableSyscalls {
		var err error
		c.syscallCollector, err = NewSyscallCollector(c.cfg, c.enqueueEvent)
		if err != nil {
			return fmt.Errorf("failed to initialize syscall collector: %w", err)
		}
		if err := c.syscallCollector.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start syscall collector: %w", err)
		}
		c.logger.Info("Syscall collector started")
	}

	// Initialize network collector
	if c.cfg.EnableNetwork {
		var err error
		c.networkCollector, err = NewNetworkCollector(c.cfg, c.enqueueEvent)
		if err != nil {
			return fmt.Errorf("failed to initialize network collector: %w", err)
		}
		if err := c.networkCollector.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start network collector: %w", err)
		}
		c.logger.Info("Network collector started")
	}

	// Initialize filesystem collector
	if c.cfg.EnableFilesystem {
		var err error
		c.filesystemCollector, err = NewFilesystemCollector(c.cfg, c.enqueueEvent)
		if err != nil {
			return fmt.Errorf("failed to initialize filesystem collector: %w", err)
		}
		if err := c.filesystemCollector.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start filesystem collector: %w", err)
		}
		c.logger.Info("Filesystem collector started")
	}

	// Initialize process collector
	if c.cfg.EnableProcesses {
		var err error
		c.processCollector, err = NewProcessCollector(c.cfg, c.enqueueEvent)
		if err != nil {
			return fmt.Errorf("failed to initialize process collector: %w", err)
		}
		if err := c.processCollector.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start process collector: %w", err)
		}
		c.logger.Info("Process collector started")
	}

	// Start batch processor
	c.wg.Add(1)
	go c.processBatches()

	// Periodically refresh own container metadata (image updates, label changes).
	c.wg.Add(1)
	go c.containerDiscoveryLoop()

	return nil
}

// Stop gracefully stops the collector
func (c *Collector) Stop() {
	c.logger.Info("Stopping collector")
	c.cancel()

	if c.syscallCollector != nil {
		c.syscallCollector.Stop()
	}
	if c.networkCollector != nil {
		c.networkCollector.Stop()
	}
	if c.filesystemCollector != nil {
		c.filesystemCollector.Stop()
	}
	if c.processCollector != nil {
		c.processCollector.Stop()
	}

	c.wg.Wait()
	c.flushBatch()
	close(c.eventQueue)
	c.logger.Info("Collector stopped")
}

// ─── Container Discovery ──────────────────────────────────────────────────────

// discoverContainers performs self-discovery: the agent is inside the container
// it monitors, so we find our own container ID then enrich with Docker metadata.
func (c *Collector) discoverContainers() error {
	c.logger.Debug("Discovering own container context")

	// Step 1: get own container ID from /proc/self/cgroup.
	selfID := getSelfContainerID()
	if selfID == "" {
		// Not inside a container (e.g. running in dev on bare metal).
		c.logger.Debug("No container ID found in /proc/self/cgroup — running on host")
		return nil
	}
	c.logger.Debugf("Self container ID: %s", selfID)

	// Step 2: try to enrich with Docker socket metadata.
	if c.docker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		meta, err := c.docker.inspectContainer(ctx, selfID)
		if err != nil {
			c.logger.Warnf("Docker inspect failed for %s: %v — using minimal context", selfID, err)
		} else {
			c.containerMu.Lock()
			c.containers[selfID] = meta
			c.containerMu.Unlock()
			c.logger.WithFields(logrus.Fields{
				"container_id": selfID,
				"image":        meta.ImageName,
				"name":         meta.Name,
			}).Info("Container context registered")
			return nil
		}
	}

	// Step 3: fallback — minimal context from environment.
	// The Dockerfile sets IMAGE_NAME at build time; the entrypoint sets HOST_ID.
	c.containerMu.Lock()
	c.containers[selfID] = &models.ContainerContext{
		ID:        selfID,
		Name:      os.Getenv("HOSTNAME"), // Docker sets HOSTNAME = container ID
		ImageName: imageNameFromEnv(),
		Labels:    make(map[string]string),
		State:     "running",
		Created:   time.Now(),
	}
	c.containerMu.Unlock()

	c.logger.WithFields(logrus.Fields{
		"container_id": selfID,
		"image":        c.containers[selfID].ImageName,
	}).Info("Container context registered (minimal — no Docker socket)")

	return nil
}

// containerDiscoveryLoop refreshes container metadata every 30s.
// Useful if the container is renamed, or labels change after start.
func (c *Collector) containerDiscoveryLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.discoverContainers(); err != nil {
				c.logger.Warnf("Container discovery refresh failed: %v", err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// cgroupFilePath is overridden in tests.
var cgroupFilePath = "/proc/self/cgroup"

// getSelfContainerID reads /proc/self/cgroup and extracts the Docker/k8s
// container ID of the process we are running in right now.
func getSelfContainerID() string {
	f, err := os.Open(cgroupFilePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	re := regexp.MustCompile(`^[0-9a-f]{12,64}$`)

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
		// Walk path segments right-to-left for the hex ID.
		segments := strings.Split(parts[2], "/")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := segments[i]
			seg = strings.TrimPrefix(seg, "docker-")
			seg = strings.TrimSuffix(seg, ".scope")
			if len(seg) >= 12 && re.MatchString(seg) {
				return seg[:12] // short ID — matches what Docker shows
			}
		}
	}
	return ""
}

// imageNameFromEnv returns the image name from environment variables.
// The Dockerfile should inject IMAGE_NAME at build time:
//
//	ARG IMAGE_NAME
//	ENV IMAGE_NAME=${IMAGE_NAME:-"container-ids-base"}
func imageNameFromEnv() string {
	if v := os.Getenv("IMAGE_NAME"); v != "" {
		return v
	}
	// Fallback: the description label we set in the Dockerfile
	return "container-ids-base"
}

// ─── Docker Socket Client ─────────────────────────────────────────────────────

const dockerSocketPath = "/var/run/docker.sock"

// dockerSocketClient talks to the Docker daemon over the Unix socket.
// We implement a minimal subset (inspect only) to avoid pulling in the full
// docker/docker SDK and its 50+ transitive dependencies.
type dockerSocketClient struct {
	http *http.Client
}

func newDockerSocketClient() (*dockerSocketClient, error) {
	if _, err := os.Stat(dockerSocketPath); err != nil {
		return nil, fmt.Errorf("docker socket not found at %s: %w", dockerSocketPath, err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dockerSocketPath)
		},
	}

	return &dockerSocketClient{
		http: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}, nil
}

// inspectContainer calls GET /containers/{id}/json and returns a ContainerContext.
func (d *dockerSocketClient) inspectContainer(ctx context.Context, containerID string) (*models.ContainerContext, error) {
	url := fmt.Sprintf("http://localhost/containers/%s/json", containerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("container %s not found", containerID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API returned %d", resp.StatusCode)
	}

	// Parse only the fields we need — avoids a full Docker SDK dependency.
	var raw struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		Image   string `json:"Image"` // image ID (sha256:...)
		Created string `json:"Created"`
		State   struct {
			Status string `json:"Status"` // running, paused, exited
		} `json:"State"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode docker inspect response: %w", err)
	}

	created, _ := time.Parse(time.RFC3339Nano, raw.Created)

	// Docker prepends "/" to container names — strip it.
	name := strings.TrimPrefix(raw.Name, "/")

	labels := raw.Config.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	return &models.ContainerContext{
		ID:        containerID,
		Name:      name,
		ImageName: raw.Config.Image,
		ImageID:   raw.Image,
		Labels:    labels,
		Created:   created,
		State:     raw.State.Status,
	}, nil
}

// ─── Event Enqueueing ─────────────────────────────────────────────────────────

// enqueueEvent adds an event to the processing queue.
// This is the EventCallback passed to every sub-collector.
func (c *Collector) enqueueEvent(eventType models.EventType, payload map[string]interface{}, containerID string) {
	// If the sub-collector didn't provide a container ID (e.g. it came from
	// /proc/self/cgroup inside the BPF handler) fall back to self-discovered ID.
	if containerID == "" {
		containerID = getSelfContainerID()
	}

	ctx := c.getContainerContext(containerID)

	event := &models.TelemetryEvent{
		EventID:     uuid.New().String(),
		EventType:   eventType,
		Timestamp:   time.Now(),
		HostID:      c.hostID,
		ContainerID: containerID,
		ImageName:   ctx.ImageName,
		Labels:      ctx.Labels,
		Payload:     payload,
	}

	// c.ctx is nil before Start() is called (e.g. in unit tests that call
	// enqueueEvent directly). Use a non-blocking send in that case so we
	// never dereference a nil context.
	if c.ctx != nil {
		select {
		case c.eventQueue <- event:
		case <-c.ctx.Done():
			return
		default:
			c.logger.Warn("Event queue full, dropping event")
		}
	} else {
		select {
		case c.eventQueue <- event:
		default:
			c.logger.Warn("Event queue full, dropping event")
		}
	}
}

// getContainerContext retrieves cached container metadata.
func (c *Collector) getContainerContext(containerID string) *models.ContainerContext {
	c.containerMu.RLock()
	defer c.containerMu.RUnlock()

	if ctx, ok := c.containers[containerID]; ok {
		return ctx
	}

	// Unknown container — return minimal context so the event is still published.
	return &models.ContainerContext{
		ID:        containerID,
		ImageName: imageNameFromEnv(),
		Labels:    make(map[string]string),
	}
}

// ─── Batch Processing ─────────────────────────────────────────────────────────

func (c *Collector) processBatches() {
	defer c.wg.Done()

	flushTicker := time.NewTicker(time.Duration(c.cfg.FlushIntervalMS) * time.Millisecond)
	defer flushTicker.Stop()

	for {
		select {
		case event := <-c.eventQueue:
			c.batchMu.Lock()
			c.batch = append(c.batch, event)
			if len(c.batch) >= c.cfg.BatchSize {
				c.flushBatchLocked()
			}
			c.batchMu.Unlock()

		case <-flushTicker.C:
			c.flushBatch()

		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Collector) flushBatch() {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()
	c.flushBatchLocked()
}

func (c *Collector) flushBatchLocked() {
	if len(c.batch) == 0 {
		return
	}
	c.logger.Debugf("Flushing batch of %d events", len(c.batch))
	for _, event := range c.batch {
		if err := c.publisher.Publish(event); err != nil {
			c.logger.Errorf("Failed to publish event %s: %v", event.EventID, err)
		}
	}
	c.batch = c.batch[:0]
}
