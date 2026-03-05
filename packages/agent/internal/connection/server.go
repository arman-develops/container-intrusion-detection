package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/arman-develops/container-intrusion-detection/agent/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Server provides remote connection capabilities to the container
type Server struct {
	cfg    *config.ConnectionConfig
	apiKey string
	router *gin.Engine
	server *http.Server
	logger *logrus.Entry
}

// NewServer creates a new connection server using Gin
func NewServer(cfg *config.ConnectionConfig, apiKey string) (*Server, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required for connection service")
	}

	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(ginLogger())

	srv := &Server{
		cfg:    cfg,
		apiKey: apiKey,
		router: router,
		logger: logrus.WithField("component", "connection-service"),
	}

	// Register routes
	srv.registerRoutes()

	// Configure HTTP server
	srv.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS if enabled
	if cfg.TLS {
		if cfg.CertPath == "" || cfg.KeyPath == "" {
			return nil, fmt.Errorf("TLS enabled but cert/key paths not provided")
		}

		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
		}

		srv.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return srv, nil
}

// Start begins listening for connections
func (s *Server) Start() error {
	s.logger.Infof("Starting connection service on port %d (TLS: %v)", s.cfg.Port, s.cfg.TLS)

	if s.cfg.TLS {
		return s.server.ListenAndServeTLS("", "")
	}
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.logger.Info("Shutting down connection service")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// registerRoutes sets up HTTP endpoints
func (s *Server) registerRoutes() {
	// Public routes (no auth required)
	public := s.router.Group("/")
	{
		public.GET("/health", s.handleHealth)
	}

	// Protected routes (require API key)
	api := s.router.Group("/")
	api.Use(s.authMiddleware())
	{
		api.GET("/info", s.handleInfo)
		api.GET("/metrics", s.handleMetrics)
		api.POST("/exec", s.handleExec)
		api.POST("/logs", s.handleLogs)
		api.POST("/files", s.handleFiles)
	}
}

// authMiddleware validates API key on protected routes
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			s.logger.Warn("Missing Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			c.Abort()
			return
		}

		// Expected format: "Bearer <api-key>"
		const prefix = "Bearer "
		if len(authHeader) < len(prefix) || authHeader[:len(prefix)] != prefix {
			s.logger.Warn("Invalid Authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization format",
			})
			c.Abort()
			return
		}

		apiKey := authHeader[len(prefix):]
		if apiKey != s.apiKey {
			s.logger.Warn("Invalid API key")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid api key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ginLogger creates a custom Gin logger middleware
func ginLogger() gin.HandlerFunc {
	logger := logrus.WithField("component", "http")

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()

		if raw != "" {
			path = path + "?" + raw
		}

		logger.WithFields(logrus.Fields{
			"status":     statusCode,
			"method":     method,
			"path":       path,
			"ip":         clientIP,
			"latency_ms": latency.Milliseconds(),
		}).Info("HTTP request")
	}
}
