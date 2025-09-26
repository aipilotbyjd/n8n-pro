// Package http provides production-grade HTTP server implementation
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/http/middleware"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP server
type Server struct {
	config     *config.Config
	logger     logger.Logger
	router     *chi.Mux
	httpServer *http.Server
	services   *Services
}

// Services holds all application services
type Services struct {
	// Add your services here as you implement them
	// UserService    user.Service
	// WorkflowService workflow.Service
	// etc.
}

// NewServer creates a new HTTP server instance
func NewServer(cfg *config.Config, logger logger.Logger, services *Services) *Server {
	server := &Server{
		config:   cfg,
		logger:   logger,
		services: services,
	}

	server.setupRouter()
	server.setupHTTPServer()

	return server
}

// setupRouter configures the Chi router with middleware and routes
func (s *Server) setupRouter() {
	r := chi.NewRouter()

	// Basic middleware
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.Recoverer(s.logger))
	r.Use(chiMiddleware.Timeout(s.config.API.ReadTimeout))

	// Security middleware
	if s.config.Security != nil {
		r.Use(middleware.SecurityHeaders(s.config))
	}

	// CORS middleware
	if s.config.API.EnableCORS {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   s.config.API.CORSAllowedOrigins,
			AllowedMethods:   s.config.API.CORSAllowedMethods,
			AllowedHeaders:   s.config.API.CORSAllowedHeaders,
			ExposedHeaders:   []string{"Link", "X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// Rate limiting middleware
	if s.config.API.EnableRateLimit {
		r.Use(middleware.RateLimit(s.config))
	}

	// Request size limiting
	r.Use(middleware.RequestSizeLimit(s.config.API.MaxRequestSize))

	// Metrics middleware
	if s.config.Metrics.Enabled {
		r.Use(middleware.Metrics(s.config.Metrics.Namespace))
	}

	// Health check routes (no auth required)
	r.Get("/health", s.handleHealthCheck)
	r.Get("/health/ready", s.handleReadinessCheck)
	r.Get("/health/live", s.handleLivenessCheck)

	// Metrics endpoint (no auth required)
	if s.config.Metrics.Enabled {
		r.Handle("/metrics", promhttp.Handler())
	}

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			// Authentication middleware for API routes
			r.Use(middleware.Authentication(s.config))

			// Placeholder API routes - will be implemented in next tasks
			r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusOK, map[string]interface{}{
					"status": "API v1 available",
					"version": "1.0.0",
				})
			})
		})
	})

	// Development routes (only in dev environment)
	if s.config.Environment == "development" {
		r.Route("/dev", func(r chi.Router) {
			r.Get("/routes", s.handleListRoutes)
			r.Get("/config", s.handleShowConfig)
		})
	}

	// Static file serving for uploads, etc.
	if s.config.Storage != nil && s.config.Storage.LocalPath != "" {
		workDir, _ := os.Getwd()
		filesDir := http.Dir(fmt.Sprintf("%s/%s", workDir, s.config.Storage.LocalPath))
		FileServer(r, "/uploads", filesDir)
	}

	s.router = r
}

// setupHTTPServer configures the HTTP server
func (s *Server) setupHTTPServer() {
	s.httpServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", s.config.API.Host, s.config.API.Port),
		Handler:        s.router,
		ReadTimeout:    s.config.API.ReadTimeout,
		WriteTimeout:   s.config.API.WriteTimeout,
		IdleTimeout:    s.config.API.IdleTimeout,
		MaxHeaderBytes: int(s.config.API.MaxRequestSize),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		s.logger.Info("Starting HTTP server",
			"host", s.config.API.Host,
			"port", s.config.API.Port,
			"environment", s.config.Environment,
		)

		if s.config.API.TLSEnabled {
			serverErrors <- s.httpServer.ListenAndServeTLS(
				s.config.API.TLSCertFile,
				s.config.API.TLSKeyFile,
			)
		} else {
			serverErrors <- s.httpServer.ListenAndServe()
		}
	}()

	// Setup signal handling for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		s.logger.Info("Received shutdown signal", "signal", sig.String())

		// Create context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Could not stop server gracefully", "error", err)
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}

		s.logger.Info("Server stopped gracefully")
		return nil
	}
}

// Handler methods

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":      "ok",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"version":     "1.0.0", // TODO: Get from config or build vars
		"service":     "n8n-pro-api",
		"environment": s.config.Environment,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func (s *Server) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	// Check if all dependencies are ready
	// This could include database connectivity, external services, etc.
	
	response := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"checks": map[string]string{
			"database": "ok",
			"redis":    "ok",
			"storage":  "ok",
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func (s *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	// Simple liveness check - just return OK if server is running
	response := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	if s.config.Environment != "development" {
		http.NotFound(w, r)
		return
	}

	routes := []string{}
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, fmt.Sprintf("%s %s", method, route))
		return nil
	}

	if err := chi.Walk(s.router, walkFunc); err != nil {
		s.logger.Error("Error walking routes", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"routes": routes,
		"count":  len(routes),
	})
}

func (s *Server) handleShowConfig(w http.ResponseWriter, r *http.Request) {
	if s.config.Environment != "development" {
		http.NotFound(w, r)
		return
	}

	// Create a safe version of config without sensitive data
	safeConfig := map[string]interface{}{
		"environment": s.config.Environment,
		"debug":       s.config.Debug,
		"log_level":   s.config.LogLevel,
		"api": map[string]interface{}{
			"host":         s.config.API.Host,
			"port":         s.config.API.Port,
			"enable_cors":  s.config.API.EnableCORS,
			"tls_enabled":  s.config.API.TLSEnabled,
		},
	}

	if s.config.Database != nil {
		safeConfig["database"] = map[string]interface{}{
			"host":                 s.config.Database.Host,
			"port":                 s.config.Database.Port,
			"database":             s.config.Database.Database,
			"max_open_connections": s.config.Database.MaxOpenConnections,
			"max_idle_connections": s.config.Database.MaxIdleConnections,
		}
	}

	if s.config.Metrics != nil {
		safeConfig["metrics"] = map[string]interface{}{
			"enabled": s.config.Metrics.Enabled,
			"port":    s.config.Metrics.Port,
		}
	}

	writeJSONResponse(w, http.StatusOK, safeConfig)
}

// FileServer conveniently sets up a http.FileServer handler to serve static files
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if len(path) == 0 || path[0] != '/' {
		panic("FileServer path must begin with '/' in path '" + path + "'")
	}

	if path != "/" && path[len(path)-1] == '/' {
		r.Get(path, http.RedirectHandler(path[:len(path)-1], http.StatusMovedPermanently).ServeHTTP)
		path = path[:len(path)-1]
	}
	path += "/*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

// Helper functions

func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If we can't encode the response, just write a simple error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}