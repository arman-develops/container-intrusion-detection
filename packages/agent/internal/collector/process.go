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

// ProcessCollector monitors process lifecycle events
type ProcessCollector struct {
	cfg      *config.CollectorConfig
	callback EventCallback
	logger   *logrus.Entry
	cancel   context.CancelFunc
}

// NewProcessCollector creates a new process collector
func NewProcessCollector(cfg *config.CollectorConfig, callback EventCallback) (*ProcessCollector, error) {
	return &ProcessCollector{
		cfg:      cfg,
		callback: callback,
		logger:   logrus.WithField("collector", "process"),
	}, nil
}

// Start begins process monitoring
func (p *ProcessCollector) Start(ctx context.Context) error {
	ctx, p.cancel = context.WithCancel(ctx)

	p.logger.Info("Starting process monitoring")

	// In production, this would:
	// 1. Monitor process creation (clone, fork, execve)
	// 2. Track process termination
	// 3. Detect privilege escalation (setuid, setgid, capability changes)
	// 4. Monitor namespace transitions

	go p.simulateCollection(ctx)

	return nil
}

// Stop stops process monitoring
func (p *ProcessCollector) Stop() {
	p.logger.Info("Stopping process monitoring")
	if p.cancel != nil {
		p.cancel()
	}
}

// simulateCollection simulates process events
func (p *ProcessCollector) simulateCollection(ctx context.Context) {
	p.logger.Warn("Running in simulation mode - implement eBPF for production")

	<-ctx.Done()
}

// handleProcessEvent processes a process event from eBPF
func (p *ProcessCollector) handleProcessEvent(
	operation string,
	pid uint32,
	ppid uint32,
	processName string,
	cmdline string,
	uid uint32,
	gid uint32,
	capabilities []string,
	namespace string,
	containerID string,
) {
	// Check for suspicious patterns
	suspicious := p.isSuspiciousProcess(operation, processName, cmdline, capabilities)

	payload := map[string]interface{}{
		"operation":     operation,
		"pid":           pid,
		"ppid":          ppid,
		"process_name":  processName,
		"cmdline":       cmdline,
		"uid":           uid,
		"gid":           gid,
		"capabilities":  capabilities,
		"namespace":     namespace,
		"is_suspicious": suspicious,
	}

	p.callback(models.EventTypeProcess, payload, containerID)
}

// isSuspiciousProcess detects suspicious process patterns
func (p *ProcessCollector) isSuspiciousProcess(
	operation string,
	processName string,
	cmdline string,
	capabilities []string,
) bool {
	// Suspicious process patterns
	suspiciousNames := []string{
		"nc", "netcat", "ncat", // Network tools
		"nmap", "masscan", // Scanners
		"python", "perl", "ruby", // Interpreters (context-dependent)
		"curl", "wget", // Download tools (context-dependent)
		"bash", "sh", "zsh", // Shells spawned unexpectedly
		"docker", "kubectl", // Container escape tools
	}

	// Check process name
	for _, suspicious := range suspiciousNames {
		if strings.Contains(processName, suspicious) {
			return true
		}
	}

	// Suspicious command line patterns
	suspiciousCmdPatterns := []string{
		"/dev/tcp/",              // Bash reverse shell
		">/dev/null 2>&1",        // Output redirection
		"base64 -d",              // Decoding payloads
		"chmod +x",               // Making files executable
		"curl.*|sh", "wget.*|sh", // Piping downloads to shell
		"nc.*-e", "nc.*-c", // Netcat with command execution
		"python -c", "perl -e", // Inline scripts
		"/proc/self/exe", // Self-modification
	}

	cmdlineLower := strings.ToLower(cmdline)
	for _, pattern := range suspiciousCmdPatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for privilege escalation
	if operation == "privilege_change" {
		privilegedCaps := []string{
			"CAP_SYS_ADMIN",
			"CAP_SYS_MODULE",
			"CAP_DAC_OVERRIDE",
			"CAP_SETUID",
			"CAP_SETGID",
		}

		for _, cap := range capabilities {
			for _, privCap := range privilegedCaps {
				if cap == privCap {
					return true
				}
			}
		}
	}

	return false
}

// getProcessCapabilities reads process capabilities from /proc
func (p *ProcessCollector) getProcessCapabilities(pid uint32) []string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return []string{}
	}

	var capabilities []string
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			// Parse effective capabilities
			// This is a simplified version - real implementation would decode the hex value
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				capHex := parts[1]
				// TODO: Decode capability bits to names
				_ = capHex
			}
		}
	}

	return capabilities
}

// getProcessCmdline reads full command line from /proc
func (p *ProcessCollector) getProcessCmdline(pid uint32) string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return ""
	}

	// Replace null bytes with spaces
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline)
}
