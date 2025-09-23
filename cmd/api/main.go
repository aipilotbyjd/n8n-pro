package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n8n-pro/internal/api/handlers"
	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/config"
	"n8n-pro/internal/credentials"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
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
	
	// Initialize credential management
	credentialStore := credentials.NewStore(db, log)
	credentialManager, err := credentials.NewManager(credentialStore, &credentials.Config{
		EncryptionKey: cfg.Auth.JWTSecret, // Use JWT secret as encryption key for now
	}, log)
	if err != nil {
		log.Fatal("Failed to initialize credential manager", "error", err)
	}
	
	workflowSvc := workflows.NewService(
		workflowRepo,
		db,
		cfg,
		nil, // validator - will be implemented
		nil, // executor - will be implemented
		nil, // template service - will be implemented
		credentialManager,
	)

	// Initialize auth services
	authRepo := auth.NewPostgresRepository(db)
	authSvc := auth.NewService(authRepo)
	jwtSvc := jwt.New(&jwt.Config{
		Secret:               cfg.Auth.JWTSecret,
		AccessTokenDuration:  cfg.Auth.JWTExpiration,
		RefreshTokenDuration: cfg.Auth.RefreshTokenExpiration,
		Issuer:               "n8n-pro",
		Audience:             "n8n-pro-api",
	})

	// Create HTTP server
	server := createServer(cfg, workflowSvc, authSvc, jwtSvc, credentialManager, log)

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

func createServer(cfg *config.Config, workflowSvc *workflows.Service, authSvc *auth.Service, jwtSvc *jwt.Service, credentialManager *credentials.Manager, log logger.Logger) *http.Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

	// Timeout middleware
	r.Use(chimiddleware.Timeout(cfg.API.ReadTimeout))

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
		r.Use(chimiddleware.Compress(5))
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

	// Initialize handlers
	workflowHandler := handlers.NewWorkflowHandler(workflowSvc)
	authHandler := handlers.NewAuthHandler(authSvc, jwtSvc, log)
	userHandler := handlers.NewUserHandler(authSvc, log)
	executionHandler := handlers.NewExecutionHandler(workflowSvc, log)
	metricsHandler := handlers.NewMetricsHandler(workflowSvc, metrics.GetGlobal(), log)
	credentialHandler := handlers.NewCredentialHandler(credentialManager, log)

	// Authentication middleware
	authMiddleware := middleware.AuthMiddleware(&middleware.AuthConfig{
		JWTSecret:      cfg.Auth.JWTSecret,
		RequiredScopes: []string{},
		SkipPaths: []string{
			"/health",
			"/version",
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/auth/refresh",
			"/api/v1/auth/forgot-password",
			"/api/v1/auth/reset-password",
			"/api/v1/auth/verify-email",
		},
	}, jwtSvc, log)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Auth endpoints (no auth required)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", authHandler.Login)
			r.Post("/register", authHandler.Register)
			r.Post("/refresh", authHandler.RefreshToken)
			r.Post("/logout", authHandler.Logout)
			r.Post("/forgot-password", authHandler.ForgotPassword)
			r.Post("/reset-password", authHandler.ResetPassword)
			r.Post("/verify-email", authHandler.VerifyEmail)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)

			// User profile endpoints
			r.Route("/profile", func(r chi.Router) {
				r.Get("/", authHandler.GetCurrentUser)
				r.Put("/", authHandler.UpdateProfile)
				r.Post("/send-verification", authHandler.SendVerificationEmail)
			})

			// Workflows
			r.Route("/workflows", func(r chi.Router) {
				r.Get("/", workflowHandler.ListWorkflows)
				r.Post("/", workflowHandler.CreateWorkflow)
				r.Get("/{id}", workflowHandler.GetWorkflow)
				r.Put("/{id}", workflowHandler.UpdateWorkflow)
				r.Delete("/{id}", workflowHandler.DeleteWorkflow)
				r.Post("/{id}/execute", executionHandler.ExecuteWorkflow)
			})

			// Executions
			r.Route("/executions", func(r chi.Router) {
				r.Get("/", executionHandler.ListExecutions)
				r.Get("/{id}", executionHandler.GetExecution)
				r.Delete("/{id}/cancel", executionHandler.CancelExecution)
				r.Post("/{id}/retry", executionHandler.RetryExecution)
			})

			// Users (legacy endpoints for backwards compatibility)
			r.Route("/users", func(r chi.Router) {
				r.Get("/me", userHandler.GetCurrentUser)
				r.Put("/me", userHandler.UpdateCurrentUser)
				r.Post("/me/change-password", userHandler.ChangePassword)
				r.Delete("/me", userHandler.DeleteAccount)
			})

			// Metrics
			r.Route("/metrics", func(r chi.Router) {
				r.Get("/workflows/{workflowId}", metricsHandler.GetWorkflowMetrics)
				r.Get("/team", metricsHandler.GetTeamMetrics)
				r.Get("/system", metricsHandler.GetSystemMetrics)
				r.Get("/health", metricsHandler.GetHealthMetrics)
			})

			// Credentials
			r.Route("/credentials", func(r chi.Router) {
				r.Get("/", credentialHandler.ListCredentials)
				r.Post("/", credentialHandler.CreateCredential)
				r.Get("/types", credentialHandler.GetCredentialTypes)
				r.Get("/stats", credentialHandler.GetCredentialStats)
				r.Get("/{id}", credentialHandler.GetCredential)
				r.Put("/{id}", credentialHandler.UpdateCredential)
				r.Delete("/{id}", credentialHandler.DeleteCredential)
				r.Post("/{id}/test", credentialHandler.TestCredential)
				r.Get("/{id}/data", credentialHandler.GetDecryptedCredential)
			})
		})
	})

	// Prometheus metrics endpoint (admin only)
	r.Get("/metrics", metricsHandler.GetPrometheusMetrics)

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port),
		Handler:      r,
		ReadTimeout:  cfg.API.ReadTimeout,
		WriteTimeout: cfg.API.WriteTimeout,
		IdleTimeout:  cfg.API.IdleTimeout,
	}
}
