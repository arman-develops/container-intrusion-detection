package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arman-develops/container-intrusion-detection/agent/internal/config"
	"github.com/arman-develops/container-intrusion-detection/agent/internal/models"
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

	// Container tracking
	containers  map[string]*models.ContainerContext
	containerMu sync.RWMutex

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

	return c, nil
}

// Start begins collecting events
func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Discover existing containers
	if err := c.discoverContainers(); err != nil {
		c.logger.Warnf("Failed to discover containers: %v", err)
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

	// Start container discovery loop
	c.wg.Add(1)
	go c.containerDiscoveryLoop()

	return nil
}

// Stop gracefully stops the collector
func (c *Collector) Stop() {
	c.logger.Info("Stopping collector")
	c.cancel()

	// Stop individual collectors
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

	// Wait for goroutines to finish
	c.wg.Wait()

	// Flush remaining events
	c.flushBatch()

	close(c.eventQueue)
	c.logger.Info("Collector stopped")
}

// enqueueEvent adds an event to the processing queue
func (c *Collector) enqueueEvent(eventType models.EventType, payload map[string]interface{}, containerID string) {
	// Get container context
	containerCtx := c.getContainerContext(containerID)

	event := &models.TelemetryEvent{
		EventID:     uuid.New().String(),
		EventType:   eventType,
		Timestamp:   time.Now(),
		HostID:      c.hostID,
		ContainerID: containerID,
		ImageName:   containerCtx.ImageName,
		Labels:      containerCtx.Labels,
		Payload:     payload,
	}

	select {
	case c.eventQueue <- event:
	case <-c.ctx.Done():
		return
	default:
		c.logger.Warn("Event queue full, dropping event")
	}
}

// processBatches handles batching and flushing events
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

// flushBatch sends accumulated events to the publisher
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
			c.logger.Errorf("Failed to publish event: %v", err)
		}
	}

	// Clear batch
	c.batch = c.batch[:0]
}

// getContainerContext retrieves container metadata
func (c *Collector) getContainerContext(containerID string) *models.ContainerContext {
	c.containerMu.RLock()
	defer c.containerMu.RUnlock()

	if ctx, ok := c.containers[containerID]; ok {
		return ctx
	}

	// Return minimal context for unknown containers
	return &models.ContainerContext{
		ID:        containerID,
		ImageName: "unknown",
		Labels:    make(map[string]string),
	}
}

// containerDiscoveryLoop periodically discovers new containers
func (c *Collector) containerDiscoveryLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.discoverContainers(); err != nil {
				c.logger.Warnf("Container discovery failed: %v", err)
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// discoverContainers finds running Docker containers
func (c *Collector) discoverContainers() error {
	// This is a simplified version - in production, use Docker API
	// For now, we'll parse /proc to find container processes

	c.logger.Debug("Discovering containers")

	// TODO: Implement actual container discovery using:
	// - Docker socket API
	// - Parse cgroup information
	// - Read container metadata

	return nil
}
