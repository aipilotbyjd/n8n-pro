package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/api/routes"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/config"
	"n8n-pro/internal/database"
	"n8n-pro/internal/nodes"
	"n8n-pro/internal/teams"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"gorm.io/gorm"
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
	db, err := database.Initialize(cfg.Database)
	if err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// TODO: Re-enable these services once they're updated to use GORM
	// Initialize repositories and services
	// workflowRepo := workflows.NewPostgresRepository(db)
	// 
	// // Initialize credential management
	// credentialStore := credentials.NewStore(db.GetPool(), log)
	// credentialManager, err := credentials.NewManager(credentialStore, &credentials.Config{
	// 	EncryptionKey: cfg.Auth.JWTSecret, // Use JWT secret as encryption key for now
	// }, log)
	// if err != nil {
	// 	log.Fatal("Failed to initialize credential manager", "error", err)
	// }
	// 
	// workflowSvc := workflows.NewService(
	// 	workflowRepo,
	// 	db,
	// 	cfg,
	// 	nil, // validator - will be implemented
	// 	nil, // executor - will be implemented
	// 	nil, // template service - will be implemented
	// 	credentialManager,
	// )

	// Initialize services
	authRepo := auth.NewPostgresRepository(db.DB)
	authSvc := auth.NewService(authRepo)
	
	// TODO: Re-enable workflow-related services
	// Create adapter for workflows.UserService
	// userServiceAdapter := &userServiceAdapter{authService: authSvc}
	// validator := workflows.NewDefaultValidator(userServiceAdapter)
	// 
	// // Initialize executor
	// executor := workflows.NewDefaultExecutor(workflowRepo)
	// 
	// // Initialize template service
	// templateSvc := workflows.NewDefaultTemplateService(workflowRepo, log)
	// 
	// // Initialize credential service
	// credSvc := workflows.NewDefaultCredentialService(credentialManager)
	
	// Initialize other services
	teamRepo := teams.NewPostgresRepository(db.DB)
	teamSvc := teams.NewService(teamRepo)
	// TODO: Re-enable webhook service
	// webhookRepo := webhooks.NewPostgresRepository(db)
	// webhookSvc := webhooks.NewService(nil, webhookRepo, db, workflowSvc, nil, log)
	nodeRegistry := nodes.NewRegistry(log)
	jwtSvc := jwt.New(&jwt.Config{
		Secret:               cfg.Auth.JWTSecret,
		AccessTokenDuration:  cfg.Auth.JWTExpiration,
		RefreshTokenDuration: cfg.Auth.RefreshTokenExpiration,
		Issuer:               "n8n-pro",
		Audience:             "n8n-pro-api",
	})

	// TODO: Re-enable workflow service updates
	// Update workflow service with real implementations
	// workflowSvc.Validator = validator
	// workflowSvc.Executor = executor
	// workflowSvc.TemplateSvc = templateSvc
	// workflowSvc.CredSvc = credSvc

	// Create HTTP server
	server := createServer(cfg, db.DB, authSvc, jwtSvc, teamSvc, nodeRegistry, log)

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

func createServer(cfg *config.Config, db *gorm.DB, authSvc *auth.Service, jwtSvc *jwt.Service, teamSvc *teams.Service, nodeRegistry *nodes.Registry, log logger.Logger) *http.Server {
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
			"version": "%s",
			"build_time": "%s",
			"git_commit": "%s",
			"go_version": "%s"
		}`, version, buildTime, gitCommit, runtime.Version())
		w.Write([]byte(response))
	})

	// API discovery endpoint
	r.Get("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"name": "n8n-pro API",
			"version": "v1",
			"description": "Enterprise Workflow Automation Platform API",
			"endpoints": {
				"authentication": {
					"login": "POST /api/v1/auth/login",
					"register": "POST /api/v1/auth/register",
					"refresh": "POST /api/v1/auth/refresh",
					"logout": "POST /api/v1/users/logout"
				},
				"users": {
					"profile": "GET /api/v1/users/me",
					"update_profile": "PUT /api/v1/users/me",
					"change_password": "PUT /api/v1/users/me/password"
				},
				"workflows": {
					"list": "GET /api/v1/workflows",
					"create": "POST /api/v1/workflows",
					"get": "GET /api/v1/workflows/{id}",
					"update": "PUT /api/v1/workflows/{id}",
					"delete": "DELETE /api/v1/workflows/{id}"
				},
				"teams": {
					"my_teams": "GET /api/v1/teams/my",
					"list": "GET /api/v1/teams",
					"create": "POST /api/v1/teams",
					"get": "GET /api/v1/teams/{id}"
				}
			},
			"public_endpoints": {
				"health": "GET /health",
				"version": "GET /version",
				"metrics": "GET /metrics",
				"api_info": "GET /api/v1"
			}
		}`
		w.Write([]byte(response))
	})

	// Setup simple auth routes (bypass complex auth package)
	routes.SetupSimpleAuthRoutes(r, db, jwtSvc, log)

	// TODO: Initialize handlers once services are ready
	// Initialize handlers
	// workflowHandler := handlers.NewWorkflowHandler(workflowSvc)
	// authHandler := handlers.NewAuthHandler(authSvc, jwtSvc, log) // Comment out broken handler
	// userHandler := handlers.NewUserHandler(authSvc, log)
	// executionHandler := handlers.NewExecutionHandler(workflowSvc, log)
	// metricsHandler := handlers.NewMetricsHandler(workflowSvc, metrics.GetGlobal(), log)
	// credentialHandler := handlers.NewCredentialHandler(credentialManager, log)
	// teamsHandler := handlers.NewTeamsHandler(teamSvc, log)
	// webhooksHandler := handlers.NewWebhooksHandler(webhookSvc, log)
	// nodesHandler := handlers.NewNodesHandler(nodeRegistry, log)
	// settingsHandler := handlers.NewSettingsHandler(log)
	// templatesHandler := handlers.NewTemplatesHandler(log)

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
		// Note: Auth endpoints are handled by SetupSimpleAuthRoutes above
		// 		// Auth endpoints (no auth required)
		// 		r.Route("/auth", func(r chi.Router) {
		// 			r.Post("/login", authHandler.Login)
		// 			r.Post("/register", authHandler.Register)
		// 			r.Post("/refresh", authHandler.RefreshToken)
		// 			r.Post("/logout", authHandler.Logout)
		// 			r.Post("/forgot-password", authHandler.ForgotPassword)
		// 			r.Post("/reset-password", authHandler.ResetPassword)
		// 			r.Post("/verify-email", authHandler.VerifyEmail)
		// 		})

		// TODO: Re-enable protected routes once handlers are available
		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)

			// Basic health check route for authenticated users
			r.Get("/auth-test", func(w http.ResponseWriter, r *http.Request) {
				user := middleware.GetUserFromContext(r.Context())
				if user != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					response := fmt.Sprintf(`{"status":"authenticated","user_id":"%s","email":"%s"}`, user.ID, user.Email)
					w.Write([]byte(response))
				} else {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error":"not authenticated"}`))
				}
			})

			// TODO: Add back all the route definitions once handlers are implemented:
			// - Workflows: /workflows/*
			// - Executions: /executions/*
			// - Users: /users/*
			// - Metrics: /metrics/*
			// - Credentials: /credentials/*
			// - Teams: /teams/*
			// - Webhooks: /webhooks/*
			// - Nodes: /nodes/*
			// - Templates: /templates/*
			// - Settings: /settings/*
		})
	})

	// TODO: Re-enable metrics endpoint
	// Prometheus metrics endpoint (admin only)
	// r.Get("/metrics", metricsHandler.GetPrometheusMetrics)

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port),
		Handler:      r,
		ReadTimeout:  cfg.API.ReadTimeout,
		WriteTimeout: cfg.API.WriteTimeout,
		IdleTimeout:  cfg.API.IdleTimeout,
	}
}

// TODO: Re-enable user service adapter when needed
// userServiceAdapter adapts auth.Service to workflows.UserService interface
// type userServiceAdapter struct {
// 	authService *auth.Service
// }

// func (u *userServiceAdapter) GetUserByID(ctx context.Context, userID string) (*workflows.User, error) {
// 	authUser, err := u.authService.GetUserByID(ctx, userID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	
// 	// Convert auth.User to workflows.User
// 	return &workflows.User{
// 		ID:     authUser.ID,
// 		Email:  authUser.Email,
// 		Role:   authUser.Role,
// 		TeamID: authUser.OrganizationID, // Use OrganizationID instead of TeamID
// 		Active: !authUser.DeletedAt.Valid, // User is active if not deleted
// 	}, nil
// }
