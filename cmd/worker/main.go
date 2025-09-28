package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/domain/workflow"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/segmentio/kafka-go"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// WorkflowJob represents a workflow execution job
type WorkflowJob struct {
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

// Worker represents the workflow execution worker
type Worker struct {
	config      *config.Config
	logger      logger.Logger
	db          *postgres.DB
	workflowSvc *workflows.Service
	reader      *kafka.Reader
	metrics     *metrics.Metrics
	ctx         context.Context
	cancel      context.CancelFunc
}

func main() {
	// Initialize logger
	log := logger.New("worker")

	log.Info("Starting n8n Pro Worker",
		"version", version,
		"build_time", buildTime,
		"git_commit", gitCommit,
	)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration", "error", err)
	}

	// Initialize metrics
	metrics.Initialize(cfg.Metrics)

	// Initialize database
	db, err := postgres.New(cfg.Database)
	if err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Initialize repositories and services
	workflowRepo := workflows.NewPostgresRepository(db)
	workflowSvc := workflows.NewService(
		workflowRepo,
		db,
		cfg,
		nil, // validator - will be implemented
		nil, // executor - will be implemented
		nil, // template service - will be implemented
		nil, // credential service - will be implemented
	)

	// Create worker
	worker, err := NewWorker(cfg, log, db, workflowSvc)
	if err != nil {
		log.Fatal("Failed to create worker", "error", err)
	}
	defer worker.Close()

	// Start health check server if enabled
	if cfg.Worker.EnableHealthCheck {
		go startHealthCheckServer(cfg.Worker.HealthCheckPort, log)
	}

	// Start worker
	if err := worker.Start(); err != nil {
		log.Fatal("Failed to start worker", "error", err)
	}

	log.Info("Worker started successfully",
		"concurrency", cfg.Worker.Concurrency,
		"queue_name", cfg.Worker.QueueName,
	)

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down worker...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Worker.ShutdownTimeout)
	defer cancel()

	if err := worker.Stop(shutdownCtx); err != nil {
		log.Error("Error during worker shutdown", "error", err)
	}

	log.Info("Worker shutdown completed")
}

// NewWorker creates a new worker instance
func NewWorker(cfg *config.Config, logger logger.Logger, db *postgres.DB, workflowSvc *workflows.Service) (*Worker, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create Kafka reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        cfg.Kafka.Brokers,
		Topic:          cfg.Kafka.Topic,
		GroupID:        cfg.Kafka.GroupID,
		MinBytes:       int(cfg.Kafka.ConsumerFetchMin),
		MaxBytes:       int(cfg.Kafka.ConsumerFetchDefault),
		MaxWait:        cfg.Kafka.ConsumerMaxWaitTime,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
	})

	worker := &Worker{
		config:      cfg,
		logger:      logger,
		db:          db,
		workflowSvc: workflowSvc,
		reader:      reader,
		metrics:     metrics.GetGlobal(),
		ctx:         ctx,
		cancel:      cancel,
	}

	return worker, nil
}

// Start starts the worker
func (w *Worker) Start() error {
	// Start worker goroutines based on concurrency setting
	for i := 0; i < w.config.Worker.Concurrency; i++ {
		go w.workerLoop(i)
	}

	return nil
}

// Stop stops the worker gracefully
func (w *Worker) Stop(ctx context.Context) error {
	w.logger.Info("Stopping worker...")

	// Cancel worker context
	w.cancel()

	// Close Kafka reader
	if err := w.reader.Close(); err != nil {
		w.logger.Error("Error closing Kafka reader", "error", err)
		return err
	}

	w.logger.Info("Worker stopped")
	return nil
}

// Close closes the worker resources
func (w *Worker) Close() {
	if w.reader != nil {
		w.reader.Close()
	}
}

// workerLoop is the main worker loop for processing jobs
func (w *Worker) workerLoop(workerID int) {
	w.logger.Info("Starting worker loop", "worker_id", workerID)

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Worker loop stopping", "worker_id", workerID)
			return
		default:
			// Process next message
			if err := w.processNextMessage(workerID); err != nil {
				w.logger.Error("Error processing message", "worker_id", workerID, "error", err)
				// Add backoff delay on error
				time.Sleep(w.config.Worker.RetryDelay)
			}
		}
	}
}

// processNextMessage processes the next message from the queue
func (w *Worker) processNextMessage(workerID int) error {
	// Set read deadline
	ctx, cancel := context.WithTimeout(w.ctx, w.config.Worker.PollInterval)
	defer cancel()

	// Read message from Kafka
	message, err := w.reader.ReadMessage(ctx)
	if err != nil {
		if err == context.DeadlineExceeded {
			// Normal timeout, continue
			return nil
		}
		return fmt.Errorf("failed to read message: %w", err)
	}

	w.logger.Debug("Received message",
		"worker_id", workerID,
		"partition", message.Partition,
		"offset", message.Offset,
		"key", string(message.Key),
	)

	// Parse job from message
	var job WorkflowJob
	if err := json.Unmarshal(message.Value, &job); err != nil {
		w.logger.Error("Failed to parse job message", "error", err, "message", string(message.Value))
		return nil // Skip invalid messages
	}

	// Process the job
	if err := w.processJob(ctx, &job, workerID); err != nil {
		w.logger.Error("Failed to process job",
			"error", err,
			"job_id", job.ID,
			"workflow_id", job.WorkflowID,
			"worker_id", workerID,
		)

		// Handle retry logic
		if job.Retry < job.MaxRetries {
			w.logger.Info("Retrying job",
				"job_id", job.ID,
				"retry", job.Retry+1,
				"max_retries", job.MaxRetries,
			)
			// TODO: Implement retry by republishing to queue
		}

		return err
	}

	w.logger.Info("Successfully processed job",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
		"worker_id", workerID,
	)

	return nil
}

// processJob processes a single workflow job
func (w *Worker) processJob(ctx context.Context, job *WorkflowJob, workerID int) error {
	startTime := time.Now()

	w.logger.Info("Processing workflow job",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
		"mode", job.Mode,
		"worker_id", workerID,
	)

	// Update metrics
	w.metrics.RecordWorkflowExecution(job.WorkflowID, "", "started", job.TeamID, 0)

	// Execute workflow (simplified - in real implementation this would be more complex)
	execution, err := w.workflowSvc.Execute(ctx, job.WorkflowID, job.TriggerData, job.UserID, job.Mode)
	if err != nil {
		w.metrics.RecordWorkflowExecution(job.WorkflowID, "", "failed", job.TeamID, time.Since(startTime))
		return fmt.Errorf("failed to execute workflow: %w", err)
	}

	// Record successful execution
	duration := time.Since(startTime)
	w.metrics.RecordWorkflowExecution(job.WorkflowID, "", "completed", job.TeamID, duration)

	w.logger.Info("Workflow execution completed",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
		"execution_id", execution.ID,
		"duration", duration,
		"worker_id", workerID,
	)

	return nil
}

// startHealthCheckServer starts a simple health check HTTP server
func startHealthCheckServer(port int, log logger.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{
			"status": "healthy",
			"service": "worker",
			"timestamp": "%s",
			"version": "%s"
		}`, time.Now().UTC().Format(time.RFC3339), version)
		w.Write([]byte(response))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	log.Info("Starting health check server", "port", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("Health check server failed", "error", err)
	}
}
