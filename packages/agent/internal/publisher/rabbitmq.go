package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/arman-develops/container-intrusion-detection/internal/config"
	"github.com/arman-develops/container-intrusion-detection/internal/models"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sirupsen/logrus"
)

// RabbitMQPublisher publishes events to RabbitMQ in real-time
type RabbitMQPublisher struct {
	cfg     *config.RabbitMQConfig
	conn    *amqp.Connection
	channel *amqp.Channel
	logger  *logrus.Entry

	// Connection management
	connMu      sync.RWMutex
	isConnected bool
	reconnectCh chan struct{}
	closeCh     chan struct{}

	// Metrics
	publishedCount uint64
	errorCount     uint64
	metricsMu      sync.RWMutex
}

// New creates a new RabbitMQ publisher
func New(cfg *config.RabbitMQConfig) (*RabbitMQPublisher, error) {
	p := &RabbitMQPublisher{
		cfg:         cfg,
		logger:      logrus.WithField("component", "rabbitmq-publisher"),
		reconnectCh: make(chan struct{}, 1),
		closeCh:     make(chan struct{}),
	}

	// Establish initial connection
	if err := p.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	// Start connection monitor
	go p.monitorConnection()

	return p, nil
}

// connect establishes connection to RabbitMQ
func (p *RabbitMQPublisher) connect() error {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	p.logger.Infof("Connecting to RabbitMQ: %s", maskURL(p.cfg.URL))

	// Establish connection
	conn, err := amqp.Dial(p.cfg.URL)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	// Open channel
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("channel open failed: %w", err)
	}

	// Declare exchange
	err = ch.ExchangeDeclare(
		p.cfg.Exchange,     // name
		p.cfg.ExchangeType, // type
		p.cfg.Durable,      // durable
		false,              // auto-deleted
		false,              // internal
		false,              // no-wait
		nil,                // arguments
	)
	if err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("exchange declare failed: %w", err)
	}

	// Enable publisher confirms for reliability
	if err := ch.Confirm(false); err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("confirm mode failed: %w", err)
	}

	p.conn = conn
	p.channel = ch
	p.isConnected = true

	p.logger.Info("Connected to RabbitMQ successfully")

	// Monitor connection closures
	go p.handleConnectionClose(conn.NotifyClose(make(chan *amqp.Error)))

	return nil
}

// handleConnectionClose handles connection closure events
func (p *RabbitMQPublisher) handleConnectionClose(closeCh chan *amqp.Error) {
	err := <-closeCh
	if err != nil {
		p.logger.Errorf("RabbitMQ connection closed: %v", err)
	}

	p.connMu.Lock()
	p.isConnected = false
	p.connMu.Unlock()

	// Trigger reconnection
	select {
	case p.reconnectCh <- struct{}{}:
	default:
	}
}

// monitorConnection handles automatic reconnection
func (p *RabbitMQPublisher) monitorConnection() {
	for {
		select {
		case <-p.reconnectCh:
			p.logger.Info("Attempting to reconnect to RabbitMQ...")

			for {
				err := p.connect()
				if err == nil {
					break
				}

				p.logger.Errorf("Reconnection failed: %v, retrying in 5s", err)
				time.Sleep(5 * time.Second)
			}

		case <-p.closeCh:
			return
		}
	}
}

// Publish sends a telemetry event to RabbitMQ in real-time
func (p *RabbitMQPublisher) Publish(event *models.TelemetryEvent) error {
	p.connMu.RLock()
	if !p.isConnected {
		p.connMu.RUnlock()
		return fmt.Errorf("not connected to RabbitMQ")
	}
	ch := p.channel
	p.connMu.RUnlock()

	// Serialize event to JSON
	body, err := json.Marshal(event)
	if err != nil {
		p.incrementErrorCount()
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create publishing context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Publish with confirmation
	confirms := ch.NotifyPublish(make(chan amqp.Confirmation, 1))

	err = ch.PublishWithContext(
		ctx,
		p.cfg.Exchange,   // exchange
		p.cfg.RoutingKey, // routing key
		false,            // mandatory
		false,            // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent, // Persist messages
			Timestamp:    event.Timestamp,
			MessageId:    event.EventID,
			Body:         body,
			Headers: amqp.Table{
				"event_type":   string(event.EventType),
				"host_id":      event.HostID,
				"container_id": event.ContainerID,
			},
		},
	)

	if err != nil {
		p.incrementErrorCount()
		return fmt.Errorf("publish failed: %w", err)
	}

	// Wait for confirmation
	select {
	case confirm := <-confirms:
		if !confirm.Ack {
			p.incrementErrorCount()
			return fmt.Errorf("publish not acknowledged")
		}
		p.incrementPublishedCount()

		p.logger.WithFields(logrus.Fields{
			"event_id":     event.EventID,
			"event_type":   event.EventType,
			"container_id": event.ContainerID,
		}).Debug("Event published successfully")

	case <-ctx.Done():
		p.incrementErrorCount()
		return fmt.Errorf("publish confirmation timeout")
	}

	return nil
}

// Close gracefully closes the publisher
func (p *RabbitMQPublisher) Close() error {
	p.logger.Info("Closing RabbitMQ publisher")

	close(p.closeCh)

	p.connMu.Lock()
	defer p.connMu.Unlock()

	var errs []error

	if p.channel != nil {
		if err := p.channel.Close(); err != nil {
			errs = append(errs, fmt.Errorf("channel close: %w", err))
		}
	}

	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("connection close: %w", err))
		}
	}

	p.isConnected = false

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	p.logger.Info("RabbitMQ publisher closed")
	return nil
}

// GetMetrics returns publisher metrics
func (p *RabbitMQPublisher) GetMetrics() map[string]uint64 {
	p.metricsMu.RLock()
	defer p.metricsMu.RUnlock()

	return map[string]uint64{
		"published_count": p.publishedCount,
		"error_count":     p.errorCount,
	}
}

// IsConnected returns connection status
func (p *RabbitMQPublisher) IsConnected() bool {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	return p.isConnected
}

// Helper methods

func (p *RabbitMQPublisher) incrementPublishedCount() {
	p.metricsMu.Lock()
	p.publishedCount++
	p.metricsMu.Unlock()
}

func (p *RabbitMQPublisher) incrementErrorCount() {
	p.metricsMu.Lock()
	p.errorCount++
	p.metricsMu.Unlock()
}

// maskURL hides credentials in URL for logging
func maskURL(url string) string {
	// Simple masking - in production, use proper URL parsing
	if len(url) > 20 {
		return url[:10] + "***" + url[len(url)-10:]
	}
	return "***"
}
