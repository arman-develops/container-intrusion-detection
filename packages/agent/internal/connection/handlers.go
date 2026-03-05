package connection

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// InfoResponse contains container and agent information
type InfoResponse struct {
	ContainerID string            `json:"container_id"`
	Hostname    string            `json:"hostname"`
	Platform    string            `json:"platform"`
	Arch        string            `json:"arch"`
	GoVersion   string            `json:"go_version"`
	Uptime      float64           `json:"uptime_seconds"`
	Environment map[string]string `json:"environment"`
}

// MetricsResponse contains basic system metrics
type MetricsResponse struct {
	Timestamp       time.Time `json:"timestamp"`
	CPUCount        int       `json:"cpu_count"`
	MemoryMB        uint64    `json:"memory_mb"`
	GoRoutines      int       `json:"goroutines"`
	ConnectionsOpen int       `json:"connections_open"`
}

// ExecRequest represents a command execution request
type ExecRequest struct {
	Command string   `json:"command" binding:"required"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout_seconds"`
}

// ExecResponse contains command execution results
type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// LogsRequest specifies log retrieval parameters
type LogsRequest struct {
	Path  string `json:"path" binding:"required"`
	Lines int    `json:"lines"`
}

// FileRequest for file operations
type FileRequest struct {
	Path      string `json:"path" binding:"required"`
	Operation string `json:"operation" binding:"required,oneof=read list stat"`
}

// FileInfo represents file metadata
type FileInfo struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time,omitempty"`
}

var startTime = time.Now()

// handleHealth returns basic health status
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	})
}

// handleInfo returns container and system information
func (s *Server) handleInfo(c *gin.Context) {
	hostname, _ := os.Hostname()
	containerID := getContainerID()

	c.JSON(http.StatusOK, InfoResponse{
		ContainerID: containerID,
		Hostname:    hostname,
		Platform:    runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		Uptime:      time.Since(startTime).Seconds(),
		Environment: getFilteredEnv(),
	})
}

// handleMetrics returns basic system metrics
func (s *Server) handleMetrics(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, MetricsResponse{
		Timestamp:       time.Now(),
		CPUCount:        runtime.NumCPU(),
		MemoryMB:        m.Alloc / 1024 / 1024,
		GoRoutines:      runtime.NumGoroutine(),
		ConnectionsOpen: 1,
	})
}

// handleExec executes commands inside the container
func (s *Server) handleExec(c *gin.Context) {
	var req ExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default timeout
	if req.Timeout == 0 {
		req.Timeout = 30
	}

	s.logger.Infof("Executing command: %s %v", req.Command, req.Args)

	cmd := exec.Command(req.Command, req.Args...)

	// Capture output
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		response := ExecResponse{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: 0,
		}

		if cmd.ProcessState != nil {
			response.ExitCode = cmd.ProcessState.ExitCode()
		}

		if err != nil {
			response.Error = err.Error()
		}

		c.JSON(http.StatusOK, response)

	case <-time.After(time.Duration(req.Timeout) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		c.JSON(http.StatusRequestTimeout, gin.H{
			"error": "command execution timeout",
		})
	}
}

// handleLogs retrieves container logs
func (s *Server) handleLogs(c *gin.Context) {
	var req LogsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Security: Validate path to prevent directory traversal
	if !isValidPath(req.Path) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid log path"})
		return
	}

	// Default to last 100 lines
	if req.Lines == 0 {
		req.Lines = 100
	}

	// Use tail command to get last N lines
	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", req.Lines), req.Path)
	output, err := cmd.Output()
	if err != nil {
		s.logger.Errorf("Failed to read logs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read logs"})
		return
	}

	c.Data(http.StatusOK, "text/plain", output)
}

// handleFiles performs file operations
func (s *Server) handleFiles(c *gin.Context) {
	var req FileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !isValidPath(req.Path) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file path"})
		return
	}

	switch req.Operation {
	case "read":
		s.handleFileRead(c, req.Path)
	case "list":
		s.handleFileList(c, req.Path)
	case "stat":
		s.handleFileStat(c, req.Path)
	}
}

func (s *Server) handleFileRead(c *gin.Context, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}

	c.Data(http.StatusOK, "application/octet-stream", data)
}

func (s *Server) handleFileList(c *gin.Context, path string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list directory"})
		return
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, _ := entry.Info()
		files = append(files, FileInfo{
			Name:  entry.Name(),
			IsDir: entry.IsDir(),
			Size:  info.Size(),
			Mode:  info.Mode().String(),
		})
	}

	c.JSON(http.StatusOK, files)
}

func (s *Server) handleFileStat(c *gin.Context, path string) {
	info, err := os.Stat(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to stat file"})
		return
	}

	c.JSON(http.StatusOK, FileInfo{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	})
}

// Helper functions

func getContainerID() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "docker") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				id := parts[len(parts)-1]
				if len(id) >= 12 {
					return id[:12]
				}
				return id
			}
		}
	}

	return "unknown"
}

func getFilteredEnv() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			key := pair[0]
			keyLower := strings.ToLower(key)
			// Filter sensitive env vars
			if !strings.Contains(keyLower, "secret") &&
				!strings.Contains(keyLower, "password") &&
				!strings.Contains(keyLower, "token") &&
				!strings.Contains(keyLower, "key") {
				env[key] = pair[1]
			}
		}
	}
	return env
}

func isValidPath(path string) bool {
	cleanPath := filepath.Clean(path)

	// Reject paths with ".."
	if strings.Contains(cleanPath, "..") {
		return false
	}

	// Must be absolute path
	if !filepath.IsAbs(cleanPath) {
		return false
	}

	return true
}
