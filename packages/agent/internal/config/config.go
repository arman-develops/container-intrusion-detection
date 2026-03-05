package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the agent configuration
type Config struct {
	Agent      AgentConfig      `yaml:"agent"`
	Connection ConnectionConfig `yaml:"connection"`
	RabbitMQ   RabbitMQConfig   `yaml:"rabbitmq"`
	Collector  CollectorConfig  `yaml:"collector"`
}

// AgentConfig contains agent-level settings
type AgentConfig struct {
	APIKey      string `yaml:"api_key"`     // Platform API key
	HostID      string `yaml:"host_id"`     // Unique host identifier
	Environment string `yaml:"environment"` // dev/staging/prod
	LogLevel    string `yaml:"log_level"`   // debug/info/warn/error
}

// ConnectionConfig for the remote connection service
type ConnectionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Port     int    `yaml:"port"`
	TLS      bool   `yaml:"tls"`
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// RabbitMQConfig for telemetry streaming
type RabbitMQConfig struct {
	URL          string `yaml:"url"`
	Exchange     string `yaml:"exchange"`
	RoutingKey   string `yaml:"routing_key"`
	ExchangeType string `yaml:"exchange_type"`
	Durable      bool   `yaml:"durable"`
}

// CollectorConfig for event collection settings
type CollectorConfig struct {
	EnableSyscalls   bool `yaml:"enable_syscalls"`
	EnableNetwork    bool `yaml:"enable_network"`
	EnableFilesystem bool `yaml:"enable_filesystem"`
	EnableProcesses  bool `yaml:"enable_processes"`

	// Filtering
	SyscallFilter  []string `yaml:"syscall_filter"`  // Specific syscalls to monitor
	SensitivePaths []string `yaml:"sensitive_paths"` // Paths to watch closely

	// Performance
	BatchSize       int `yaml:"batch_size"`        // Events before flush
	FlushIntervalMS int `yaml:"flush_interval_ms"` // Max time before flush
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply environment variable overrides
	if apiKey := os.Getenv("AGENT_API_KEY"); apiKey != "" {
		cfg.Agent.APIKey = apiKey
	}
	if rmqURL := os.Getenv("RABBITMQ_URL"); rmqURL != "" {
		cfg.RabbitMQ.URL = rmqURL
	}

	return &cfg, nil
}

// Default returns a default configuration
func Default() *Config {
	return &Config{
		Agent: AgentConfig{
			APIKey:      "",
			Environment: "production",
			LogLevel:    "info",
		},
		Connection: ConnectionConfig{
			Enabled: true,
			Port:    8443,
			TLS:     true,
		},
		RabbitMQ: RabbitMQConfig{
			URL:          "amqp://guest:guest@localhost:5672/",
			Exchange:     "container-ids",
			RoutingKey:   "telemetry",
			ExchangeType: "topic",
			Durable:      true,
		},
		Collector: CollectorConfig{
			EnableSyscalls:   true,
			EnableNetwork:    true,
			EnableFilesystem: true,
			EnableProcesses:  true,
			SyscallFilter: []string{
				"execve", "open", "openat", "read", "write",
				"socket", "connect", "bind", "listen", "accept",
				"clone", "fork", "chmod", "chown", "setuid", "setgid",
			},
			SensitivePaths: []string{
				"/etc/", "/root/", "/var/", "/proc/", "/sys/",
			},
			BatchSize:       100,
			FlushIntervalMS: 1000,
		},
	}
}
