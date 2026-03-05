package collector

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/arman-develops/container-intrusion-detection/agent/internal/config"
	"github.com/arman-develops/container-intrusion-detection/agent/internal/models"
	"github.com/sirupsen/logrus"
)

// EventCallback is called when an event is collected
type EventCallback func(eventType models.EventType, payload map[string]interface{}, containerID string)

// SyscallCollector monitors system calls
type SyscallCollector struct {
	cfg      *config.CollectorConfig
	callback EventCallback
	logger   *logrus.Entry
	cancel   context.CancelFunc
}

// NewSyscallCollector creates a new syscall collector
func NewSyscallCollector(cfg *config.CollectorConfig, callback EventCallback) (*SyscallCollector, error) {
	return &SyscallCollector{
		cfg:      cfg,
		callback: callback,
		logger:   logrus.WithField("collector", "syscall"),
	}, nil
}

// Start begins syscall monitoring
func (s *SyscallCollector) Start(ctx context.Context) error {
	// Check if running as root (required for eBPF)
	if os.Geteuid() != 0 {
		return fmt.Errorf("syscall collector requires root privileges")
	}

	ctx, s.cancel = context.WithCancel(ctx)

	s.logger.Info("Starting syscall monitoring")

	// In a production implementation, this would:
	// 1. Load eBPF programs using cilium/ebpf
	// 2. Attach to kernel tracepoints/kprobes for syscalls
	// 3. Read events from perf/ring buffer
	// 4. Parse and enrich events with container context

	// For MVP, we'll simulate syscall collection
	go s.simulateCollection(ctx)

	return nil
}

// Stop stops syscall monitoring
func (s *SyscallCollector) Stop() {
	s.logger.Info("Stopping syscall monitoring")
	if s.cancel != nil {
		s.cancel()
	}
}

// simulateCollection simulates syscall events for testing
// In production, replace with actual eBPF implementation
func (s *SyscallCollector) simulateCollection(ctx context.Context) {
	s.logger.Warn("Running in simulation mode - implement eBPF for production")

	// This is a placeholder that generates sample events
	// Real implementation would read from eBPF ring buffer

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// In real implementation, this would be triggered by actual syscalls
			// For now, just log that we're ready to collect
			s.logger.Debug("Syscall collector ready (simulation mode)")
			return
		}
	}
}

// handleSyscallEvent processes a syscall event from eBPF
func (s *SyscallCollector) handleSyscallEvent(
	syscallName string,
	pid uint32,
	uid uint32,
	gid uint32,
	args []string,
	returnVal int64,
	containerID string,
) {
	// Check if this syscall is in our filter
	if !s.shouldMonitorSyscall(syscallName) {
		return
	}

	// Get process name from /proc
	processName := s.getProcessName(pid)

	payload := map[string]interface{}{
		"name":         syscallName,
		"pid":          pid,
		"uid":          uid,
		"gid":          gid,
		"args":         args,
		"return_val":   returnVal,
		"process_name": processName,
	}

	s.callback(models.EventTypeSyscall, payload, containerID)
}

// shouldMonitorSyscall checks if a syscall should be monitored
func (s *SyscallCollector) shouldMonitorSyscall(syscallName string) bool {
	if len(s.cfg.SyscallFilter) == 0 {
		return true // Monitor all if no filter
	}

	for _, allowed := range s.cfg.SyscallFilter {
		if allowed == syscallName {
			return true
		}
	}
	return false
}

// getProcessName retrieves process name from /proc
func (s *SyscallCollector) getProcessName(pid uint32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// getContainerIDFromPID extracts container ID from process cgroup
func (s *SyscallCollector) getContainerIDFromPID(pid uint32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") {
			// Extract container ID from cgroup path
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				containerID := parts[len(parts)-1]
				// Clean up container ID (remove .scope suffix, etc.)
				containerID = strings.TrimSuffix(containerID, ".scope")
				if len(containerID) >= 12 {
					return containerID[:12] // Return short ID
				}
				return containerID
			}
		}
	}

	return ""
}
