package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// JobFunc represents a scheduled job function
type JobFunc func(ctx context.Context, payload json.RawMessage) error

// Scheduler manages scheduled jobs
type Scheduler struct {
	cron      *cron.Cron
	db        *gorm.DB
	logger    *zap.Logger
	jobs      map[string]JobFunc
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
}

// ScheduledJob represents a scheduled job in the database
type ScheduledJob struct {
	ID             uint            `gorm:"primaryKey"`
	Name           string          `gorm:"uniqueIndex;not null"`
	Description    string          
	CronExpression string          `gorm:"not null"`
	Handler        string          `gorm:"not null"`
	Payload        json.RawMessage `gorm:"type:jsonb"`
	Enabled        bool            `gorm:"default:true"`
	LastRun        *time.Time
	NextRun        *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// JobExecution represents a job execution log
type JobExecution struct {
	ID          uint            `gorm:"primaryKey"`
	JobID       uint            `gorm:"not null"`
	JobName     string          `gorm:"not null"`
	StartTime   time.Time       `gorm:"not null"`
	EndTime     *time.Time
	Status      string          `gorm:"not null"` // pending, running, success, failed
	Error       string
	Duration    int64           // in milliseconds
	Payload     json.RawMessage `gorm:"type:jsonb"`
	CreatedAt   time.Time
}

// Config holds scheduler configuration
type Config struct {
	DB              *gorm.DB
	Logger          *zap.Logger
	CheckInterval   time.Duration
	MaxConcurrency  int
	EnableMetrics   bool
}

// NewScheduler creates a new scheduler instance
func NewScheduler(cfg Config) (*Scheduler, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("database is required")
	}
	
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scheduler{
		cron:   cron.New(cron.WithSeconds()),
		db:     cfg.DB,
		logger: cfg.Logger,
		jobs:   make(map[string]JobFunc),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// RegisterJob registers a job handler
func (s *Scheduler) RegisterJob(name string, fn JobFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.jobs[name] = fn
	s.logger.Info("Registered job handler", 
		zap.String("handler", name))
}

// Start starts the scheduler
func (s *Scheduler) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	s.running = true
	s.mu.Unlock()
	
	// Register default jobs
	s.registerDefaultJobs()
	
	// Load jobs from database
	if err := s.loadJobs(); err != nil {
		return fmt.Errorf("failed to load jobs: %w", err)
	}
	
	// Start cron scheduler
	s.cron.Start()
	
	s.logger.Info("Scheduler started",
		zap.Int("jobs", len(s.cron.Entries())))
	
	// Start job reloader
	go s.jobReloader()
	
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler not running")
	}
	s.running = false
	s.mu.Unlock()
	
	// Cancel context
	s.cancel()
	
	// Stop cron scheduler
	ctx := s.cron.Stop()
	
	// Wait for running jobs to complete
	select {
	case <-ctx.Done():
		s.logger.Info("All scheduled jobs completed")
	case <-time.After(30 * time.Second):
		s.logger.Warn("Timeout waiting for jobs to complete")
	}
	
	s.logger.Info("Scheduler stopped")
	return nil
}

// loadJobs loads jobs from database
func (s *Scheduler) loadJobs() error {
	var jobs []ScheduledJob
	
	if err := s.db.Where("enabled = ?", true).Find(&jobs).Error; err != nil {
		return fmt.Errorf("failed to fetch jobs: %w", err)
	}
	
	for _, job := range jobs {
		if err := s.scheduleJob(job); err != nil {
			s.logger.Error("Failed to schedule job",
				zap.String("job", job.Name),
				zap.Error(err))
			continue
		}
	}
	
	s.logger.Info("Loaded scheduled jobs",
		zap.Int("count", len(jobs)))
	
	return nil
}

// scheduleJob schedules a single job
func (s *Scheduler) scheduleJob(job ScheduledJob) error {
	s.mu.RLock()
	handler, exists := s.jobs[job.Handler]
	s.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("handler not found: %s", job.Handler)
	}
	
	// Create job wrapper
	jobFunc := func() {
		s.executeJob(job, handler)
	}
	
	// Add to cron
	entryID, err := s.cron.AddFunc(job.CronExpression, jobFunc)
	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}
	
	// Update next run time
	entry := s.cron.Entry(entryID)
	nextRun := entry.Next
	
	if err := s.db.Model(&job).Update("next_run", nextRun).Error; err != nil {
		s.logger.Error("Failed to update next run",
			zap.String("job", job.Name),
			zap.Error(err))
	}
	
	s.logger.Info("Scheduled job",
		zap.String("job", job.Name),
		zap.String("cron", job.CronExpression),
		zap.Time("next_run", nextRun))
	
	return nil
}

// executeJob executes a scheduled job
func (s *Scheduler) executeJob(job ScheduledJob, handler JobFunc) {
	execution := &JobExecution{
		JobID:     job.ID,
		JobName:   job.Name,
		StartTime: time.Now(),
		Status:    "running",
		Payload:   job.Payload,
	}
	
	// Create execution record
	if err := s.db.Create(execution).Error; err != nil {
		s.logger.Error("Failed to create execution record",
			zap.String("job", job.Name),
			zap.Error(err))
	}
	
	s.logger.Info("Executing job",
		zap.String("job", job.Name),
		zap.Uint("execution_id", execution.ID))
	
	// Execute job
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()
	
	err := handler(ctx, job.Payload)
	
	// Update execution record
	endTime := time.Now()
	execution.EndTime = &endTime
	execution.Duration = endTime.Sub(execution.StartTime).Milliseconds()
	
	if err != nil {
		execution.Status = "failed"
		execution.Error = err.Error()
		
		s.logger.Error("Job execution failed",
			zap.String("job", job.Name),
			zap.Uint("execution_id", execution.ID),
			zap.Error(err))
	} else {
		execution.Status = "success"
		
		s.logger.Info("Job execution completed",
			zap.String("job", job.Name),
			zap.Uint("execution_id", execution.ID),
			zap.Int64("duration_ms", execution.Duration))
	}
	
	// Update execution and job records
	if err := s.db.Save(execution).Error; err != nil {
		s.logger.Error("Failed to update execution record",
			zap.Uint("execution_id", execution.ID),
			zap.Error(err))
	}
	
	// Update last run time
	now := time.Now()
	if err := s.db.Model(&job).Update("last_run", now).Error; err != nil {
		s.logger.Error("Failed to update last run",
			zap.String("job", job.Name),
			zap.Error(err))
	}
}

// jobReloader periodically reloads jobs from database
func (s *Scheduler) jobReloader() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			if !s.running {
				s.mu.RUnlock()
				return
			}
			s.mu.RUnlock()
			
			// Reload jobs
			s.reloadJobs()
		}
	}
}

// reloadJobs reloads jobs from database
func (s *Scheduler) reloadJobs() {
	// Stop current cron
	s.cron.Stop()
	
	// Create new cron
	s.cron = cron.New(cron.WithSeconds())
	
	// Load jobs
	if err := s.loadJobs(); err != nil {
		s.logger.Error("Failed to reload jobs", zap.Error(err))
		return
	}
	
	// Start cron
	s.cron.Start()
	
	s.logger.Debug("Jobs reloaded",
		zap.Int("count", len(s.cron.Entries())))
}

// registerDefaultJobs registers default system jobs
func (s *Scheduler) registerDefaultJobs() {
	// Cleanup old sessions
	s.RegisterJob("cleanup_sessions", func(ctx context.Context, payload json.RawMessage) error {
		var config struct {
			Days int `json:"days"`
		}
		
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &config); err != nil {
				return err
			}
		}
		
		if config.Days == 0 {
			config.Days = 30
		}
		
		cutoff := time.Now().AddDate(0, 0, -config.Days)
		
		result := s.db.Where("updated_at < ?", cutoff).Delete(&AuthSession{})
		if result.Error != nil {
			return result.Error
		}
		
		s.logger.Info("Cleaned up old sessions",
			zap.Int64("deleted", result.RowsAffected),
			zap.Int("days", config.Days))
		
		return nil
	})
	
	// Cleanup old job executions
	s.RegisterJob("cleanup_executions", func(ctx context.Context, payload json.RawMessage) error {
		var config struct {
			Days int `json:"days"`
		}
		
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &config); err != nil {
				return err
			}
		}
		
		if config.Days == 0 {
			config.Days = 7
		}
		
		cutoff := time.Now().AddDate(0, 0, -config.Days)
		
		result := s.db.Where("created_at < ? AND status IN ?", cutoff, []string{"success", "failed"}).
			Delete(&JobExecution{})
		if result.Error != nil {
			return result.Error
		}
		
		s.logger.Info("Cleaned up old job executions",
			zap.Int64("deleted", result.RowsAffected),
			zap.Int("days", config.Days))
		
		return nil
	})
	
	// Database vacuum (PostgreSQL specific)
	s.RegisterJob("database_vacuum", func(ctx context.Context, payload json.RawMessage) error {
		// Run VACUUM ANALYZE
		if err := s.db.Exec("VACUUM ANALYZE").Error; err != nil {
			return fmt.Errorf("vacuum failed: %w", err)
		}
		
		s.logger.Info("Database vacuum completed")
		return nil
	})
	
	// Health check job
	s.RegisterJob("health_check", func(ctx context.Context, payload json.RawMessage) error {
		// Check database connection
		var result int
		if err := s.db.Raw("SELECT 1").Scan(&result).Error; err != nil {
			return fmt.Errorf("database health check failed: %w", err)
		}
		
		s.logger.Info("Health check completed successfully")
		return nil
	})
}

// GetJobStatus returns the status of a job
func (s *Scheduler) GetJobStatus(jobName string) (*ScheduledJob, error) {
	var job ScheduledJob
	if err := s.db.Where("name = ?", jobName).First(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// GetJobExecutions returns recent executions for a job
func (s *Scheduler) GetJobExecutions(jobName string, limit int) ([]JobExecution, error) {
	var executions []JobExecution
	
	query := s.db.Where("job_name = ?", jobName).
		Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	
	if err := query.Find(&executions).Error; err != nil {
		return nil, err
	}
	
	return executions, nil
}

// CreateJob creates a new scheduled job
func (s *Scheduler) CreateJob(job *ScheduledJob) error {
	// Validate cron expression
	if _, err := cron.ParseStandard(job.CronExpression); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}
	
	// Check if handler exists
	s.mu.RLock()
	_, exists := s.jobs[job.Handler]
	s.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("handler not found: %s", job.Handler)
	}
	
	// Create job in database
	if err := s.db.Create(job).Error; err != nil {
		return err
	}
	
	// Schedule job if enabled
	if job.Enabled {
		if err := s.scheduleJob(*job); err != nil {
			s.logger.Error("Failed to schedule new job",
				zap.String("job", job.Name),
				zap.Error(err))
		}
	}
	
	return nil
}

// UpdateJob updates an existing scheduled job
func (s *Scheduler) UpdateJob(jobName string, updates map[string]interface{}) error {
	var job ScheduledJob
	
	if err := s.db.Where("name = ?", jobName).First(&job).Error; err != nil {
		return err
	}
	
	// Validate cron expression if provided
	if cron, ok := updates["cron_expression"].(string); ok {
		if _, err := cron.ParseStandard(cron); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
	}
	
	// Update job in database
	if err := s.db.Model(&job).Updates(updates).Error; err != nil {
		return err
	}
	
	// Reload jobs to apply changes
	s.reloadJobs()
	
	return nil
}

// DeleteJob deletes a scheduled job
func (s *Scheduler) DeleteJob(jobName string) error {
	if err := s.db.Where("name = ?", jobName).Delete(&ScheduledJob{}).Error; err != nil {
		return err
	}
	
	// Reload jobs to remove from scheduler
	s.reloadJobs()
	
	return nil
}

// Temporary struct for AuthSession - should be imported from models
type AuthSession struct {
	ID        uint      `gorm:"primaryKey"`
	UpdatedAt time.Time
}