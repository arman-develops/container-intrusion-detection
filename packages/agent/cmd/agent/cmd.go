package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arman-develops/container-intrusion-detection/internal/collector"
	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/connection"
	"github.com/arman-develops/container-intrusion-detection/internal/publisher"
	"github.com/sirupsen/logrus"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/container-ids/agent.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Container IDS Agent\nVersion: %s\nBuild Time: %s\n", version, buildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logger
	setupLogger(cfg.Agent.LogLevel)

	logrus.WithFields(logrus.Fields{
		"version": version,
		"host_id": cfg.Agent.HostID,
		"env":     cfg.Agent.Environment,
	}).Info("Starting Container IDS Agent")

	// Validate API key
	if cfg.Agent.APIKey == "" {
		logrus.Fatal("API key is required. Set AGENT_API_KEY environment variable or provide in config.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize RabbitMQ publisher
	pub, err := publisher.New(&cfg.RabbitMQ)
	if err != nil {
		logrus.Fatalf("Failed to initialize publisher: %v", err)
	}
	defer pub.Close()

	logrus.Info("Connected to RabbitMQ")

	// Initialize collector
	col, err := collector.New(&cfg.Collector, cfg.Agent.HostID, pub)
	if err != nil {
		logrus.Fatalf("Failed to initialize collector: %v", err)
	}

	// Start collector
	if err := col.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start collector: %v", err)
	}
	logrus.Info("Event collector started")

	// Start connection service if enabled
	var connSvc *connection.Server
	if cfg.Connection.Enabled {
		connSvc, err = connection.NewServer(&cfg.Connection, cfg.Agent.APIKey)
		if err != nil {
			logrus.Fatalf("Failed to initialize connection service: %v", err)
		}

		go func() {
			if err := connSvc.Start(); err != nil {
				logrus.Errorf("Connection service error: %v", err)
			}
		}()
		logrus.Infof("Connection service listening on port %d", cfg.Connection.Port)
	}

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	logrus.Info("Received shutdown signal, gracefully stopping...")

	// Cleanup
	cancel()
	col.Stop()
	if connSvc != nil {
		connSvc.Stop()
	}

	logrus.Info("Agent stopped")
}

func loadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.Warnf("Config file not found at %s, using defaults", path)
		return config.Default(), nil
	}
	return config.Load(path)
}

func setupLogger(level string) {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	switch level {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}
