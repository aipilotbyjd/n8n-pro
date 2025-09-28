package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/infrastructure/messaging"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/webhooks"
	"n8n-pro/internal/domain/workflow"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	// Initialize logger
	log := logger.New("webhook")

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

	webhookRepo := webhooks.NewPostgresRepository(db)
	webhookSvc := webhooks.NewService(cfg.Webhook, webhookRepo, db, workflowSvc, producer, log)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Webhook endpoints
	r.Route("/webhook", func(r chi.Router) {
		r.Post("/{workflowId}", webhookSvc.HandleWebhook)
		r.Post("/{workflowId}/{nodeId}", webhookSvc.HandleNodeWebhook)
		r.Get("/{workflowId}", webhookSvc.HandleWebhookGET)
	})

	// Generic webhook endpoint for custom integrations
	r.Route("/hooks", func(r chi.Router) {
		r.Post("/{hookId}", webhookSvc.HandleGenericWebhook)
		r.Get("/{hookId}", webhookSvc.HandleGenericWebhookGET)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Webhook.Port),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting webhook server", "port", cfg.Webhook.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start webhook server", "error", err)
		}
	}()

	log.Info("Webhook server started successfully", "port", cfg.Webhook.Port)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Received shutdown signal, stopping webhook server...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("Error during server shutdown", "error", err)
	}

	log.Info("Webhook server stopped")
}
