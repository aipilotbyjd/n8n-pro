package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/messaging"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/robfig/cron/v3"
)

// Service represents the scheduler service
type Service struct {
	config      *config.SchedulerConfig
	db          *postgres.DB
	workflowSvc *workflows.Service
	producer    *messaging.Producer
	logger      logger.Logger
	metrics     *metrics.Metrics
	cron        *cron.Cron
	jobs        map[string]*ScheduledJob
	mutex       sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	running     bool
}

// ScheduledJob represents a scheduled workflow job
type ScheduledJob struct {
	ID             string                 `json:"id" db:"id"`
	WorkflowID     string                 `json:"workflow_id" db:"workflow_id"`
	TeamID         string                 `json:"team_id" db:"team_id"`
	Name           string                 `json:"name" db:"name"`
	CronExpression string                 `json:"cron_expression" db:"cron_expression"`
	Timezone       string                 `json:"timezone" db:"timezone"`
	Enabled        bool                   `json:"enabled" db:"enabled"`
	NextRunTime    *time.Time             `json:"next_run_time,omitempty" db:"next_run_time"`
	LastRunTime    *time.Time             `json:"last_run_time,omitempty" db:"last_run_time"`
	LastRunStatus  string                 `json:"last_run_status" db:"last_run_status"`
	RunCount       int64                  `json:"run_count" db:"run_count"`
	FailureCount   int64                  `json:"failure_count" db:"failure_count"`
	Parameters     map[string]interface{} `json:"parameters" db:"parameters"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy      string                 `json:"created_by" db:"created_by"`
	CronJobID      cron.EntryID           `json:"-"`
}

// JobExecution represents a scheduled job execution
type JobExecution struct {
	ID          string                 `json:"id"`
	JobID       string                 `json:"job_id"`
	WorkflowID  string                 `json:"workflow_id"`
	TeamID      string                 `json:"team_id"`
	Status      string                 `json:"status"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    *time.Duration         `json:"duration,omitempty"`
	Error       string                 `json:"error,omitempty"`
	TriggerData map[string]interface{} `json:"trigger_data"`
	CreatedAt   time.Time              `json:"created_at"`
}

// NewService creates a new scheduler service
func NewService(
	config *config.SchedulerConfig,
	db *postgres.DB,
	workflowSvc *workflows.Service,
	producer *messaging.Producer,
) *Service {
	logger := logger.New("scheduler")

	// Create cron scheduler with second precision
	cronOptions := []cron.Option{
		cron.WithSeconds(),
		cron.WithChain(
			cron.Recover(cron.DefaultLogger),
			cron.SkipIfStillRunning(cron.DefaultLogger),
		),
	}

	c := cron.New(cronOptions...)

	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		config:      config,
		db:          db,
		workflowSvc: workflowSvc,
		producer:    producer,
		logger:      logger,
		metrics:     metrics.GetGlobal(),
		cron:        c,
		jobs:        make(map[string]*ScheduledJob),
		ctx:         ctx,
		cancel:      cancel,
		running:     false,
	}
}

// Start starts the scheduler service
func (s *Service) Start(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.config.Enabled {
		s.logger.Info("Scheduler is disabled")
		return nil
	}

	if s.running {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "scheduler is already running")
	}

	s.logger.Info("Starting scheduler service")

	// Load existing scheduled jobs from database
	if err := s.loadScheduledJobs(ctx); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to load scheduled jobs")
	}

	// Start cron scheduler
	s.cron.Start()

	// Start cleanup routine
	go s.cleanupRoutine()

	// Start health monitoring
	go s.healthMonitoring()

	s.running = true
	s.logger.Info("Scheduler service started successfully",
		"jobs_count", len(s.jobs),
		"check_interval", s.config.CheckInterval,
	)

	return nil
}

// Stop stops the scheduler service
func (s *Service) Stop(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Stopping scheduler service")

	// Stop accepting new jobs
	s.cancel()

	// Stop cron scheduler
	cronCtx := s.cron.Stop()

	// Wait for running jobs to complete with timeout
	select {
	case <-cronCtx.Done():
		s.logger.Info("All scheduled jobs completed")
	case <-time.After(s.config.LockTimeout):
		s.logger.Warn("Timeout waiting for scheduled jobs to complete")
	}

	s.running = false
	s.logger.Info("Scheduler service stopped")

	return nil
}

// CreateScheduledJob creates a new scheduled job
func (s *Service) CreateScheduledJob(ctx context.Context, job *ScheduledJob) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate cron expression
	if _, err := cron.ParseStandard(job.CronExpression); err != nil {
		return errors.Wrap(err, errors.ErrorTypeValidation, errors.CodeInvalidInput,
			"invalid cron expression")
	}

	// Set defaults
	if job.ID == "" {
		job.ID = workflows.GenerateID()
	}
	if job.Timezone == "" {
		job.Timezone = "UTC"
	}
	job.CreatedAt = time.Now()
	job.UpdatedAt = time.Now()

	// Save to database
	if err := s.saveScheduledJob(ctx, job); err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to save scheduled job")
	}

	// Add to cron if enabled
	if job.Enabled && s.running {
		if err := s.addJobToCron(job); err != nil {
			s.logger.Error("Failed to add job to cron scheduler",
				"job_id", job.ID,
				"error", err,
			)
		}
	}

	s.jobs[job.ID] = job
	s.logger.Info("Scheduled job created",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
		"cron_expression", job.CronExpression,
	)

	return nil
}

// UpdateScheduledJob updates an existing scheduled job
func (s *Service) UpdateScheduledJob(ctx context.Context, job *ScheduledJob) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	existingJob, exists := s.jobs[job.ID]
	if !exists {
		return errors.NotFoundError("scheduled job")
	}

	// Validate cron expression if changed
	if job.CronExpression != existingJob.CronExpression {
		if _, err := cron.ParseStandard(job.CronExpression); err != nil {
			return errors.Wrap(err, errors.ErrorTypeValidation, errors.CodeInvalidInput,
				"invalid cron expression")
		}
	}

	// Remove from cron if currently scheduled
	if existingJob.CronJobID != 0 {
		s.cron.Remove(existingJob.CronJobID)
	}

	// Update fields
	job.UpdatedAt = time.Now()

	// Save to database
	if err := s.updateScheduledJob(ctx, job); err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to update scheduled job")
	}

	// Add back to cron if enabled
	if job.Enabled && s.running {
		if err := s.addJobToCron(job); err != nil {
			s.logger.Error("Failed to re-add job to cron scheduler",
				"job_id", job.ID,
				"error", err,
			)
		}
	}

	s.jobs[job.ID] = job
	s.logger.Info("Scheduled job updated",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
	)

	return nil
}

// DeleteScheduledJob deletes a scheduled job
func (s *Service) DeleteScheduledJob(ctx context.Context, jobID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return errors.NotFoundError("scheduled job")
	}

	// Remove from cron
	if job.CronJobID != 0 {
		s.cron.Remove(job.CronJobID)
	}

	// Delete from database
	if err := s.deleteScheduledJob(ctx, jobID); err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to delete scheduled job")
	}

	delete(s.jobs, jobID)
	s.logger.Info("Scheduled job deleted", "job_id", jobID)

	return nil
}

// GetScheduledJob retrieves a scheduled job by ID
func (s *Service) GetScheduledJob(ctx context.Context, jobID string) (*ScheduledJob, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return nil, errors.NotFoundError("scheduled job")
	}

	return job, nil
}

// ListScheduledJobs lists all scheduled jobs for a team
func (s *Service) ListScheduledJobs(ctx context.Context, teamID string) ([]*ScheduledJob, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var jobs []*ScheduledJob
	for _, job := range s.jobs {
		if teamID == "" || job.TeamID == teamID {
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// ExecuteJobNow executes a scheduled job immediately
func (s *Service) ExecuteJobNow(ctx context.Context, jobID string) (*JobExecution, error) {
	job, err := s.GetScheduledJob(ctx, jobID)
	if err != nil {
		return nil, err
	}

	return s.executeJob(ctx, job)
}

// addJobToCron adds a job to the cron scheduler
func (s *Service) addJobToCron(job *ScheduledJob) error {
	cronJob := func() {
		ctx, cancel := context.WithTimeout(s.ctx, s.config.JobTimeout)
		defer cancel()

		execution, err := s.executeJob(ctx, job)
		if err != nil {
			s.logger.Error("Scheduled job execution failed",
				"job_id", job.ID,
				"workflow_id", job.WorkflowID,
				"error", err,
			)
			s.updateJobStats(job.ID, "failed", err.Error())
			return
		}

		s.logger.Info("Scheduled job executed successfully",
			"job_id", job.ID,
			"workflow_id", job.WorkflowID,
			"execution_id", execution.ID,
		)
		s.updateJobStats(job.ID, "success", "")
	}

	entryID, err := s.cron.AddFunc(job.CronExpression, cronJob)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to add job to cron")
	}

	job.CronJobID = entryID
	return nil
}

// executeJob executes a scheduled job
func (s *Service) executeJob(ctx context.Context, job *ScheduledJob) (*JobExecution, error) {
	s.logger.Info("Executing scheduled job",
		"job_id", job.ID,
		"workflow_id", job.WorkflowID,
		"team_id", job.TeamID,
	)

	// Create job execution record
	execution := &JobExecution{
		ID:         workflows.GenerateID(),
		JobID:      job.ID,
		WorkflowID: job.WorkflowID,
		TeamID:     job.TeamID,
		Status:     "running",
		StartTime:  time.Now(),
		TriggerData: map[string]interface{}{
			"trigger_type":    "schedule",
			"job_id":          job.ID,
			"job_name":        job.Name,
			"cron_expression": job.CronExpression,
			"scheduled_time":  time.Now(),
			"parameters":      job.Parameters,
		},
		CreatedAt: time.Now(),
	}

	// Save execution record
	if err := s.saveJobExecution(ctx, execution); err != nil {
		s.logger.Error("Failed to save job execution", "error", err)
	}

	// Publish workflow execution job to Kafka
	workflowJob := &messaging.WorkflowExecutionJob{
		ID:          workflows.GenerateID(),
		WorkflowID:  job.WorkflowID,
		TriggerData: execution.TriggerData,
		UserID:      job.CreatedBy, // Use job creator as user
		TeamID:      job.TeamID,
		Mode:        "schedule",
		Priority:    5,
		ScheduledAt: time.Now(),
		Retry:       0,
		MaxRetries:  3,
	}

	if err := s.producer.PublishWorkflowJob(ctx, workflowJob); err != nil {
		execution.Status = "failed"
		execution.Error = err.Error()
		endTime := time.Now()
		execution.EndTime = &endTime
		duration := endTime.Sub(execution.StartTime)
		execution.Duration = &duration

		s.updateJobExecution(ctx, execution)
		return execution, errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to publish workflow job")
	}

	// Update execution as queued
	execution.Status = "queued"
	s.updateJobExecution(ctx, execution)

	// Record metrics
	s.metrics.RecordWorkflowExecution(job.WorkflowID, job.Name, "scheduled", job.TeamID, 0)

	return execution, nil
}

// updateJobStats updates job execution statistics
func (s *Service) updateJobStats(jobID, status, errorMsg string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return
	}

	now := time.Now()
	job.LastRunTime = &now
	job.LastRunStatus = status
	job.RunCount++

	if status == "failed" {
		job.FailureCount++
	}

	job.UpdatedAt = now

	// Update in database (async)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.updateScheduledJob(ctx, job)
	}()
}

// loadScheduledJobs loads all scheduled jobs from database
func (s *Service) loadScheduledJobs(ctx context.Context) error {
	query := `
		SELECT id, workflow_id, team_id, name, cron_expression, timezone, enabled,
			   next_run_time, last_run_time, last_run_status, run_count, failure_count,
			   parameters, created_at, updated_at, created_by
		FROM scheduled_jobs
		WHERE deleted_at IS NULL`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var job ScheduledJob
		var parametersJSON []byte

		err := rows.Scan(
			&job.ID, &job.WorkflowID, &job.TeamID, &job.Name, &job.CronExpression,
			&job.Timezone, &job.Enabled, &job.NextRunTime, &job.LastRunTime,
			&job.LastRunStatus, &job.RunCount, &job.FailureCount,
			&parametersJSON, &job.CreatedAt, &job.UpdatedAt, &job.CreatedBy,
		)
		if err != nil {
			s.logger.Error("Failed to scan scheduled job", "error", err)
			continue
		}

		// Deserialize parameters
		if err := json.Unmarshal(parametersJSON, &job.Parameters); err != nil {
			s.logger.Error("Failed to deserialize job parameters", "job_id", job.ID, "error", err)
			job.Parameters = make(map[string]interface{})
		}

		// Add to cron if enabled
		if job.Enabled {
			if err := s.addJobToCron(&job); err != nil {
				s.logger.Error("Failed to add job to cron scheduler",
					"job_id", job.ID,
					"error", err,
				)
				continue
			}
		}

		s.jobs[job.ID] = &job
	}

	s.logger.Info("Loaded scheduled jobs", "count", len(s.jobs))
	return nil
}

// cleanupRoutine performs periodic cleanup tasks
func (s *Service) cleanupRoutine() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.performCleanup()
		}
	}
}

// performCleanup cleans up old job executions
func (s *Service) performCleanup() {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()

	// Clean up completed job executions older than retention period
	completedCutoff := time.Now().Add(-s.config.RetainCompletedJobs)
	failedCutoff := time.Now().Add(-s.config.RetainFailedJobs)

	query := `
		DELETE FROM job_executions
		WHERE (status IN ('completed', 'success') AND created_at < $1)
		   OR (status IN ('failed', 'error') AND created_at < $2)`

	result, err := s.db.Exec(ctx, query, completedCutoff, failedCutoff)
	if err != nil {
		s.logger.Error("Failed to cleanup job executions", "error", err)
		return
	}

	if result.RowsAffected() > 0 {
		s.logger.Info("Cleaned up job executions", "rows_deleted", result.RowsAffected())
	}
}

// healthMonitoring monitors scheduler health
func (s *Service) healthMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkHealth()
		}
	}
}

// checkHealth performs health checks
func (s *Service) checkHealth() {
	s.mutex.RLock()
	jobCount := len(s.jobs)
	s.mutex.RUnlock()

	// Update metrics
	s.metrics.SetQueueDepth("scheduler", "jobs", float64(jobCount))

	// Log stats
	s.logger.Debug("Scheduler health check",
		"jobs_count", jobCount,
		"cron_entries", len(s.cron.Entries()),
		"running", s.running,
	)
}

// Database operations (simplified implementations)

func (s *Service) saveScheduledJob(ctx context.Context, job *ScheduledJob) error {
	parametersJSON, _ := json.Marshal(job.Parameters)

	query := `
		INSERT INTO scheduled_jobs (
			id, workflow_id, team_id, name, cron_expression, timezone, enabled,
			parameters, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := s.db.Exec(ctx, query,
		job.ID, job.WorkflowID, job.TeamID, job.Name, job.CronExpression,
		job.Timezone, job.Enabled, parametersJSON, job.CreatedAt,
		job.UpdatedAt, job.CreatedBy,
	)

	return err
}

func (s *Service) updateScheduledJob(ctx context.Context, job *ScheduledJob) error {
	parametersJSON, _ := json.Marshal(job.Parameters)

	query := `
		UPDATE scheduled_jobs SET
			name = $2, cron_expression = $3, timezone = $4, enabled = $5,
			last_run_time = $6, last_run_status = $7, run_count = $8,
			failure_count = $9, parameters = $10, updated_at = $11
		WHERE id = $1`

	_, err := s.db.Exec(ctx, query,
		job.ID, job.Name, job.CronExpression, job.Timezone, job.Enabled,
		job.LastRunTime, job.LastRunStatus, job.RunCount, job.FailureCount,
		parametersJSON, job.UpdatedAt,
	)

	return err
}

func (s *Service) deleteScheduledJob(ctx context.Context, jobID string) error {
	query := `UPDATE scheduled_jobs SET deleted_at = $2 WHERE id = $1`
	_, err := s.db.Exec(ctx, query, jobID, time.Now())
	return err
}

func (s *Service) saveJobExecution(ctx context.Context, execution *JobExecution) error {
	triggerDataJSON, _ := json.Marshal(execution.TriggerData)

	query := `
		INSERT INTO job_executions (
			id, job_id, workflow_id, team_id, status, start_time, end_time,
			duration, error, trigger_data, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	var durationMs *int64
	if execution.Duration != nil {
		ms := execution.Duration.Milliseconds()
		durationMs = &ms
	}

	_, err := s.db.Exec(ctx, query,
		execution.ID, execution.JobID, execution.WorkflowID, execution.TeamID,
		execution.Status, execution.StartTime, execution.EndTime, durationMs,
		execution.Error, triggerDataJSON, execution.CreatedAt,
	)

	return err
}

func (s *Service) updateJobExecution(ctx context.Context, execution *JobExecution) error {
	query := `
		UPDATE job_executions SET
			status = $2, end_time = $3, duration = $4, error = $5
		WHERE id = $1`

	var durationMs *int64
	if execution.Duration != nil {
		ms := execution.Duration.Milliseconds()
		durationMs = &ms
	}

	_, err := s.db.Exec(ctx, query,
		execution.ID, execution.Status, execution.EndTime, durationMs, execution.Error,
	)

	return err
}

// Health returns the health status of the scheduler
func (s *Service) Health() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"running":          s.running,
		"jobs_count":       len(s.jobs),
		"cron_entries":     len(s.cron.Entries()),
		"enabled":          s.config.Enabled,
		"distributed_mode": s.config.EnableDistributedMode,
		"max_concurrent":   s.config.MaxConcurrentJobs,
		"check_interval":   s.config.CheckInterval.String(),
	}
}
