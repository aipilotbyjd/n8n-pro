package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/messaging"
	"n8n-pro/internal/scheduler"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/logger"
)

func main() {
	// Initialize logger
	log := logger.New("scheduler")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config", "error", err)
	}

	// Initialize database
	db, err := postgres.New(cfg.Database)
	if err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Initialize messaging
	producer, err := messaging.NewKafkaProducer(cfg.Kafka)
	if err != nil {
		log.Fatal("Failed to create Kafka producer", "error", err)
	}
	defer producer.Close()

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
	schedulerSvc := scheduler.NewService(cfg.Scheduler, db, workflowSvc, producer)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler
	if err := schedulerSvc.Start(ctx); err != nil {
		log.Fatal("Failed to start scheduler", "error", err)
	}

	log.Info("Scheduler started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Received shutdown signal, stopping scheduler...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := schedulerSvc.Stop(shutdownCtx); err != nil {
		log.Error("Error during scheduler shutdown", "error", err)
	}

	log.Info("Scheduler stopped")
}
