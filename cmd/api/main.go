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
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Initialize logger
	log := logger.New("api")

	log.Info("Starting n8n Pro API Server",
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

	// Create HTTP server
	server := createServer(cfg, workflowSvc, log)

	// Start metrics server
	if cfg.Metrics.Enabled {
		go func() {
			metricsAddr := fmt.Sprintf("%s:%d", cfg.Metrics.Host, cfg.Metrics.Port)
			log.Info("Starting metrics server", "addr", metricsAddr)
			http.ListenAndServe(metricsAddr, metrics.GetGlobal().Handler())
		}()
	}

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port)
		log.Info("Starting API server", "addr", addr)

		if cfg.API.TLSEnabled {
			if err := server.ListenAndServeTLS(cfg.API.TLSCertFile, cfg.API.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatal("Failed to start HTTPS server", "error", err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal("Failed to start HTTP server", "error", err)
			}
		}
	}()

	log.Info("API server started successfully",
		"port", cfg.API.Port,
		"tls_enabled", cfg.API.TLSEnabled,
	)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Server exited")
}

func createServer(cfg *config.Config, workflowSvc *workflows.Service, log logger.Logger) *http.Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Timeout middleware
	r.Use(middleware.Timeout(cfg.API.ReadTimeout))

	// CORS middleware
	if cfg.API.EnableCORS {
		corsOptions := cors.Options{
			AllowedOrigins:   cfg.API.CORSAllowedOrigins,
			AllowedMethods:   cfg.API.CORSAllowedMethods,
			AllowedHeaders:   cfg.API.CORSAllowedHeaders,
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300,
		}
		r.Use(cors.Handler(corsOptions))
	}

	// Compression middleware
	if cfg.API.EnableGzip {
		r.Use(middleware.Compress(5))
	}

	// Rate limiting middleware (placeholder)
	if cfg.API.EnableRateLimit {
		// TODO: Implement rate limiting
	}

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"api","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// Version endpoint
	r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{
			"version":"%s",
			"build_time":"%s",
			"git_commit":"%s",
			"go_version":"%s"
		}`, version, buildTime, gitCommit, "go1.23")
		w.Write([]byte(response))
	})

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Workflows
		r.Route("/workflows", func(r chi.Router) {
			r.Get("/", handleListWorkflows(workflowSvc, log))
			r.Post("/", handleCreateWorkflow(workflowSvc, log))
			r.Get("/{id}", handleGetWorkflow(workflowSvc, log))
			r.Put("/{id}", handleUpdateWorkflow(workflowSvc, log))
			r.Delete("/{id}", handleDeleteWorkflow(workflowSvc, log))
			r.Post("/{id}/execute", handleExecuteWorkflow(workflowSvc, log))
		})

		// Executions
		r.Route("/executions", func(r chi.Router) {
			r.Get("/", handleListExecutions(workflowSvc, log))
			r.Get("/{id}", handleGetExecution(workflowSvc, log))
			r.Delete("/{id}/cancel", handleCancelExecution(workflowSvc, log))
			r.Post("/{id}/retry", handleRetryExecution(workflowSvc, log))
		})

		// Metrics
		r.Get("/metrics/{workflowId}", handleGetWorkflowMetrics(workflowSvc, log))
	})

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port),
		Handler:      r,
		ReadTimeout:  cfg.API.ReadTimeout,
		WriteTimeout: cfg.API.WriteTimeout,
		IdleTimeout:  cfg.API.IdleTimeout,
	}
}

// Handler functions (simplified implementations)

func handleListWorkflows(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement authentication and extract user ID
		userID := "demo-user" // Placeholder

		filter := &workflows.WorkflowListFilter{
			Limit:  50,
			Offset: 0,
		}

		workflows, total, err := svc.List(r.Context(), filter, userID)
		if err != nil {
			log.Error("Failed to list workflows", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
		w.WriteHeader(http.StatusOK)

		// Simple JSON response (in production, use proper JSON marshaling)
		response := fmt.Sprintf(`{"workflows":%d,"total":%d}`, len(workflows), total)
		w.Write([]byte(response))
	}
}

func handleCreateWorkflow(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement request parsing and workflow creation
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message":"Workflow creation not implemented yet"}`))
	}
}

func handleGetWorkflow(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		workflowID := chi.URLParam(r, "id")
		userID := "demo-user" // Placeholder

		workflow, err := svc.GetByID(r.Context(), workflowID, userID)
		if err != nil {
			log.Error("Failed to get workflow", "error", err, "workflow_id", workflowID)
			http.Error(w, "Workflow not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"id":"%s","name":"%s"}`, workflow.ID, workflow.Name)
		w.Write([]byte(response))
	}
}

func handleUpdateWorkflow(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Workflow update not implemented yet"}`))
	}
}

func handleDeleteWorkflow(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		workflowID := chi.URLParam(r, "id")
		userID := "demo-user" // Placeholder

		err := svc.Delete(r.Context(), workflowID, userID)
		if err != nil {
			log.Error("Failed to delete workflow", "error", err, "workflow_id", workflowID)
			http.Error(w, "Failed to delete workflow", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleExecuteWorkflow(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"message":"Workflow execution not implemented yet"}`))
	}
}

func handleListExecutions(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"executions":[],"total":0}`))
	}
}

func handleGetExecution(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Get execution not implemented yet"}`))
	}
}

func handleCancelExecution(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Cancel execution not implemented yet"}`))
	}
}

func handleRetryExecution(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Retry execution not implemented yet"}`))
	}
}

func handleGetWorkflowMetrics(svc *workflows.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Metrics not implemented yet"}`))
	}
}
