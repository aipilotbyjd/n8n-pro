package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/segmentio/kafka-go"
)

// Producer represents a Kafka message producer
type Producer struct {
	writer  *kafka.Writer
	config  *config.KafkaConfig
	logger  logger.Logger
	metrics *metrics.Metrics
}

// Consumer represents a Kafka message consumer
type Consumer struct {
	reader  *kafka.Reader
	config  *config.KafkaConfig
	logger  logger.Logger
	metrics *metrics.Metrics
}

// Message represents a Kafka message
type Message struct {
	Key       string
	Value     []byte
	Headers   map[string]string
	Timestamp time.Time
	Topic     string
	Partition int
	Offset    int64
}

// NewKafkaProducer creates a new Kafka producer
func NewKafkaProducer(config *config.KafkaConfig) (*Producer, error) {
	if config == nil {
		return nil, errors.ValidationError(errors.CodeMissingField, "Kafka config is required")
	}

	if len(config.Brokers) == 0 {
		return nil, errors.ValidationError(errors.CodeMissingField, "at least one Kafka broker is required")
	}

	logger := logger.New("kafka-producer")

	writer := &kafka.Writer{
		Addr:         kafka.TCP(config.Brokers...),
		Topic:        config.Topic,
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		RequiredAcks: kafka.RequireOne,
		MaxAttempts:  config.ProducerRetryMax,
		BatchSize:    100,
		BatchBytes:   1048576, // 1MB
		BatchTimeout: config.ProducerFlushFrequency,
		Compression:  kafka.Snappy,
	}

	// Configure SASL if enabled
	if config.EnableSASL {
		// Note: SASL configuration would be handled differently in kafka-go
		// For now, we'll skip this configuration as it requires more complex setup
	}

	// Configure TLS if enabled
	if config.EnableTLS {
		// Note: TLS configuration would be handled differently in kafka-go
		// For now, we'll skip this configuration as it requires more complex setup
	}

	producer := &Producer{
		writer:  writer,
		config:  config,
		logger:  logger,
		metrics: metrics.GetGlobal(),
	}

	return producer, nil
}

// NewKafkaReader creates a new Kafka consumer/reader
func NewKafkaReader(config *config.KafkaConfig) (*Consumer, error) {
	if config == nil {
		return nil, errors.ValidationError(errors.CodeMissingField, "Kafka config is required")
	}

	if len(config.Brokers) == 0 {
		return nil, errors.ValidationError(errors.CodeMissingField, "at least one Kafka broker is required")
	}

	logger := logger.New("kafka-consumer")

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  config.Brokers,
		Topic:    config.Topic,
		GroupID:  config.GroupID,
		MinBytes: int(config.ConsumerFetchMin),
		MaxBytes: int(config.ConsumerFetchDefault),
		MaxWait:  config.ConsumerMaxWaitTime,

		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
		Partition:      0,
	})

	consumer := &Consumer{
		reader:  reader,
		config:  config,
		logger:  logger,
		metrics: metrics.GetGlobal(),
	}

	return consumer, nil
}

// SendMessage sends a message to Kafka
func (p *Producer) SendMessage(ctx context.Context, key string, value interface{}) error {
	return p.SendMessageToTopic(ctx, p.config.Topic, key, value)
}

// SendMessageToTopic sends a message to a specific topic
func (p *Producer) SendMessageToTopic(ctx context.Context, topic, key string, value interface{}) error {
	// Serialize value to JSON
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize message value")
	}

	message := kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: valueBytes,
		Time:  time.Now(),
	}

	// Add headers
	message.Headers = []kafka.Header{
		{Key: "content-type", Value: []byte("application/json")},
		{Key: "producer", Value: []byte("n8n-pro")},
		{Key: "timestamp", Value: []byte(time.Now().Format(time.RFC3339))},
	}

	start := time.Now()
	err = p.writer.WriteMessages(ctx, message)
	duration := time.Since(start)

	if err != nil {
		p.logger.Error("Failed to send message to Kafka",
			"error", err,
			"topic", topic,
			"key", key,
			"duration", duration,
		)
		p.metrics.RecordQueueMessage(topic, "error")
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to send message to Kafka")
	}

	p.logger.Debug("Message sent to Kafka",
		"topic", topic,
		"key", key,
		"size", len(valueBytes),
		"duration", duration,
	)

	p.metrics.RecordQueueMessage(topic, "success")
	return nil
}

// SendBatch sends multiple messages in a batch
func (p *Producer) SendBatch(ctx context.Context, messages []kafka.Message) error {
	if len(messages) == 0 {
		return nil
	}

	start := time.Now()
	err := p.writer.WriteMessages(ctx, messages...)
	duration := time.Since(start)

	if err != nil {
		p.logger.Error("Failed to send batch to Kafka",
			"error", err,
			"batch_size", len(messages),
			"duration", duration,
		)
		p.metrics.RecordQueueMessage(p.config.Topic, "batch_error")
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to send batch to Kafka")
	}

	p.logger.Debug("Batch sent to Kafka",
		"batch_size", len(messages),
		"duration", duration,
	)

	p.metrics.RecordQueueMessage(p.config.Topic, "batch_success")
	return nil
}

// ReadMessage reads a single message from Kafka
func (c *Consumer) ReadMessage(ctx context.Context) (*Message, error) {
	kafkaMsg, err := c.reader.ReadMessage(ctx)
	if err != nil {
		if err == context.DeadlineExceeded || err == context.Canceled {
			return nil, err
		}

		c.logger.Error("Failed to read message from Kafka", "error", err)
		c.metrics.RecordQueueMessage(c.config.Topic, "read_error")
		return nil, errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to read message from Kafka")
	}

	// Convert headers
	headers := make(map[string]string)
	for _, header := range kafkaMsg.Headers {
		headers[header.Key] = string(header.Value)
	}

	message := &Message{
		Key:       string(kafkaMsg.Key),
		Value:     kafkaMsg.Value,
		Headers:   headers,
		Timestamp: kafkaMsg.Time,
		Topic:     kafkaMsg.Topic,
		Partition: kafkaMsg.Partition,
		Offset:    kafkaMsg.Offset,
	}

	c.logger.Debug("Message read from Kafka",
		"topic", message.Topic,
		"partition", message.Partition,
		"offset", message.Offset,
		"key", message.Key,
		"size", len(message.Value),
	)

	c.metrics.RecordQueueMessage(c.config.Topic, "read_success")
	return message, nil
}

// CommitMessages commits the given messages
func (c *Consumer) CommitMessages(ctx context.Context, messages ...kafka.Message) error {
	if len(messages) == 0 {
		return nil
	}

	err := c.reader.CommitMessages(ctx, messages...)
	if err != nil {
		c.logger.Error("Failed to commit messages", "error", err, "count", len(messages))
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to commit messages")
	}

	c.logger.Debug("Messages committed", "count", len(messages))
	return nil
}

// SetOffset sets the offset for the consumer
func (c *Consumer) SetOffset(offset int64) error {
	err := c.reader.SetOffset(offset)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to set offset")
	}
	return nil
}

// Stats returns consumer statistics
func (c *Consumer) Stats() kafka.ReaderStats {
	return c.reader.Stats()
}

// Close closes the producer
func (p *Producer) Close() error {
	if p.writer != nil {
		return p.writer.Close()
	}
	return nil
}

// Close closes the consumer
func (c *Consumer) Close() error {
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}

// Health checks the health of the Kafka connection
func (p *Producer) Health(ctx context.Context) error {
	// Try to get metadata to check connectivity
	conn, err := kafka.Dial("tcp", p.config.Brokers[0])
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to connect to Kafka broker")
	}
	defer conn.Close()

	_, err = conn.ReadPartitions()
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to read Kafka partitions")
	}

	return nil
}

// WorkflowExecutionJob represents a workflow execution job for Kafka
type WorkflowExecutionJob struct {
	ID          string                 `json:"id"`
	WorkflowID  string                 `json:"workflow_id"`
	TriggerData map[string]interface{} `json:"trigger_data"`
	UserID      string                 `json:"user_id"`
	TeamID      string                 `json:"team_id"`
	Mode        string                 `json:"mode"`
	Priority    int                    `json:"priority"`
	ScheduledAt time.Time              `json:"scheduled_at"`
	Retry       int                    `json:"retry"`
	MaxRetries  int                    `json:"max_retries"`
}

// PublishWorkflowJob publishes a workflow execution job to Kafka
func (p *Producer) PublishWorkflowJob(ctx context.Context, job *WorkflowExecutionJob) error {
	key := fmt.Sprintf("workflow_%s_%s", job.WorkflowID, job.ID)
	return p.SendMessage(ctx, key, job)
}

// ConsumeWorkflowJobs consumes workflow execution jobs from Kafka
func (c *Consumer) ConsumeWorkflowJobs(ctx context.Context, handler func(*WorkflowExecutionJob) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			message, err := c.ReadMessage(ctx)
			if err != nil {
				if err == context.DeadlineExceeded {
					continue
				}
				return err
			}

			var job WorkflowExecutionJob
			if err := json.Unmarshal(message.Value, &job); err != nil {
				c.logger.Error("Failed to unmarshal workflow job",
					"error", err,
					"message", string(message.Value),
				)
				continue
			}

			if err := handler(&job); err != nil {
				c.logger.Error("Failed to handle workflow job",
					"error", err,
					"job_id", job.ID,
					"workflow_id", job.WorkflowID,
				)
				continue
			}
		}
	}
}

// PublishWorkflowEvent publishes a workflow event (for backward compatibility)
func PublishWorkflowEvent(ctx context.Context, key string, value []byte) error {
	// This is a simplified version for backward compatibility
	// In a real implementation, you'd use a configured producer
	config, err := config.Load()
	if err != nil {
		return err
	}

	producer, err := NewKafkaProducer(config.Kafka)
	if err != nil {
		return err
	}
	defer producer.Close()

	message := kafka.Message{
		Key:   []byte(key),
		Value: value,
	}

	return producer.writer.WriteMessages(ctx, message)
}

// InitKafka initializes Kafka with configuration
func InitKafka(cfg *config.Config) error {
	// This function can be used for global initialization if needed
	// For now, it's a placeholder
	return nil
}
