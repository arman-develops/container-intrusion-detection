package models

import "time"

// EventType represents the category of event
type EventType string

const (
	EventTypeSyscall    EventType = "syscall"
	EventTypeNetwork    EventType = "network"
	EventTypeFilesystem EventType = "filesystem"
	EventTypeProcess    EventType = "process"
)

// TelemetryEvent is the base event structure sent to the platform
type TelemetryEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   EventType              `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	HostID      string                 `json:"host_id"`
	ContainerID string                 `json:"container_id"`
	ImageName   string                 `json:"image_name"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Payload     map[string]interface{} `json:"payload"`
}

// SyscallEvent represents a system call event
type SyscallEvent struct {
	Name        string   `json:"name"`       // Syscall name (e.g., "execve")
	PID         uint32   `json:"pid"`        // Process ID
	UID         uint32   `json:"uid"`        // User ID
	GID         uint32   `json:"gid"`        // Group ID
	Args        []string `json:"args"`       // Syscall arguments
	ReturnVal   int64    `json:"return_val"` // Return value
	ProcessName string   `json:"process_name"`
}

// NetworkEvent represents a network activity event
type NetworkEvent struct {
	Operation   string `json:"operation"` // connect, bind, listen, accept
	Protocol    string `json:"protocol"`  // tcp, udp
	SourceIP    string `json:"source_ip"`
	SourcePort  uint16 `json:"source_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    uint16 `json:"dest_port"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PID         uint32 `json:"pid"`
	ProcessName string `json:"process_name"`
}

// FilesystemEvent represents a file operation event
type FilesystemEvent struct {
	Operation   string `json:"operation"` // open, read, write, chmod, etc.
	FilePath    string `json:"file_path"`
	Permissions uint32 `json:"permissions"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	PID         uint32 `json:"pid"`
	ProcessName string `json:"process_name"`
	Flags       int32  `json:"flags"` // Open flags
}

// ProcessEvent represents a process lifecycle event
type ProcessEvent struct {
	Operation    string   `json:"operation"` // create, terminate, privilege_change
	PID          uint32   `json:"pid"`
	PPID         uint32   `json:"ppid"` // Parent PID
	ProcessName  string   `json:"process_name"`
	Cmdline      string   `json:"cmdline"` // Full command line
	UID          uint32   `json:"uid"`
	GID          uint32   `json:"gid"`
	Capabilities []string `json:"capabilities"` // Linux capabilities
	Namespace    string   `json:"namespace"`    // Container namespace
}

// ContainerContext holds container metadata
type ContainerContext struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	ImageName string            `json:"image_name"`
	ImageID   string            `json:"image_id"`
	Labels    map[string]string `json:"labels"`
	Created   time.Time         `json:"created"`
	State     string            `json:"state"` // running, paused, stopped
}
