package collector

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
	"github.com/sirupsen/logrus"
)

// FilesystemCollector monitors file operations
type FilesystemCollector struct {
	cfg      *config.CollectorConfig
	callback EventCallback
	logger   *logrus.Entry
	cancel   context.CancelFunc
}

// NewFilesystemCollector creates a new filesystem collector
func NewFilesystemCollector(cfg *config.CollectorConfig, callback EventCallback) (*FilesystemCollector, error) {
	return &FilesystemCollector{
		cfg:      cfg,
		callback: callback,
		logger:   logrus.WithField("collector", "filesystem"),
	}, nil
}

// Start begins filesystem monitoring
func (f *FilesystemCollector) Start(ctx context.Context) error {
	ctx, f.cancel = context.WithCancel(ctx)

	f.logger.Info("Starting filesystem monitoring")

	// In production, this would:
	// 1. Attach eBPF programs to VFS operations
	// 2. Monitor open, read, write, chmod, chown syscalls
	// 3. Track access to sensitive paths
	// 4. Detect suspicious permission changes

	go f.simulateCollection(ctx)

	return nil
}

// Stop stops filesystem monitoring
func (f *FilesystemCollector) Stop() {
	f.logger.Info("Stopping filesystem monitoring")
	if f.cancel != nil {
		f.cancel()
	}
}

// simulateCollection simulates filesystem events
func (f *FilesystemCollector) simulateCollection(ctx context.Context) {
	f.logger.Warn("Running in simulation mode - implement eBPF for production")

	<-ctx.Done()
}

// handleFilesystemEvent processes a filesystem event from eBPF
func (f *FilesystemCollector) handleFilesystemEvent(
	operation string,
	filePath string,
	permissions uint32,
	uid uint32,
	gid uint32,
	pid uint32,
	processName string,
	flags int32,
	containerID string,
) {
	// Check if this path should be monitored
	if !f.shouldMonitorPath(filePath) {
		return
	}

	payload := map[string]interface{}{
		"operation":    operation,
		"file_path":    filePath,
		"permissions":  permissions,
		"uid":          uid,
		"gid":          gid,
		"pid":          pid,
		"process_name": processName,
		"flags":        flags,
		"is_sensitive": f.isSensitivePath(filePath),
	}

	f.callback(models.EventTypeFilesystem, payload, containerID)
}

// shouldMonitorPath determines if a path should be monitored
func (f *FilesystemCollector) shouldMonitorPath(path string) bool {
	// Always monitor sensitive paths
	if f.isSensitivePath(path) {
		return true
	}

	// Skip common noisy paths
	noisyPaths := []string{
		"/proc/",
		"/sys/fs/cgroup/",
		"/dev/pts/",
		"/tmp/.X11-unix/",
	}

	for _, noisy := range noisyPaths {
		if strings.HasPrefix(path, noisy) {
			return false
		}
	}

	return true
}

// isSensitivePath checks if a path is sensitive
func (f *FilesystemCollector) isSensitivePath(path string) bool {
	for _, sensitivePath := range f.cfg.SensitivePaths {
		// Check if path is under sensitive directory
		if strings.HasPrefix(path, sensitivePath) {
			return true
		}

		// Check for exact match or glob pattern
		matched, _ := filepath.Match(sensitivePath, path)
		if matched {
			return true
		}
	}

	// Additional sensitive file patterns
	sensitivePatterns := []string{
		"*.key",
		"*.pem",
		"*.crt",
		"*secret*",
		"*password*",
		"*token*",
		".env",
		".credentials",
	}

	basename := filepath.Base(path)
	for _, pattern := range sensitivePatterns {
		matched, _ := filepath.Match(pattern, basename)
		if matched {
			return true
		}
	}

	return false
}

// isSuspiciousOperation detects suspicious file operations
func (f *FilesystemCollector) isSuspiciousOperation(operation string, path string, permissions uint32) bool {
	// Suspicious patterns:
	// - Writing to /etc/ or system directories
	// - Changing permissions on executables
	// - Accessing SSH keys or credentials
	// - Creating files in unusual locations

	if operation == "write" || operation == "chmod" {
		if strings.HasPrefix(path, "/etc/") ||
			strings.HasPrefix(path, "/usr/bin/") ||
			strings.HasPrefix(path, "/usr/sbin/") {
			return true
		}
	}

	// Detect permission escalation attempts
	if operation == "chmod" && permissions&0111 != 0 {
		// Setting execute bit
		return true
	}

	return false
}
