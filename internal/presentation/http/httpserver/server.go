package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Config holds HTTP server configuration
type Config struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	TLSEnabled   bool
	TLSCertFile  string
	TLSKeyFile   string
	EnableCORS   bool
	CORSOrigins  []string
	EnableGzip   bool
	EnableRecovery bool
	EnableLogger bool
}

// Server provides HTTP server functionality
type Server struct {
	config *Config
	router *chi.Mux
	logger logger.Logger
	server *http.Server
}

// New creates a new HTTP server
func New(config *Config, logger logger.Logger) *Server {
	if logger == nil {
		logger = logger.New("http-server")
	}

	if config == nil {
		config = DefaultConfig()
	}

	router := chi.NewRouter()

	server := &Server{
		config: config,
		router: router,
		logger: logger,
	}

	server.setupMiddleware()

	return server
}

// DefaultConfig returns default server configuration
func DefaultConfig() *Config {
	return &Config{
		Host:           "0.0.0.0",
		Port:           8080,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		TLSEnabled:     false,
		EnableCORS:     true,
		CORSOrigins:    []string{"*"},
		EnableGzip:     true,
		EnableRecovery: true,
		EnableLogger:   true,
	}
}

// setupMiddleware sets up the server middleware
func (s *Server) setupMiddleware() {
	if s.config.EnableRecovery {
		s.router.Use(middleware.Recoverer)
	}

	if s.config.EnableLogger {
		s.router.Use(middleware.Logger)
	}

	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	
	// Timeout middleware
	s.router.Use(middleware.Timeout(s.config.ReadTimeout))

	// Compression middleware
	if s.config.EnableGzip {
		s.router.Use(middleware.Compress(5))
	}

	// CORS middleware
	if s.config.EnableCORS {
		s.router.Use(s.corsMiddleware())
	}
}

// corsMiddleware provides CORS handling
func (s *Server) corsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", s.config.CORSOrigins[0])
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-User-ID, X-Team-ID, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AddRoute adds a route to the server
func (s *Server) AddRoute(method, pattern string, handler http.HandlerFunc) {
	s.router.MethodFunc(method, pattern, handler)
}

// AddRoutes adds multiple routes using chi's route grouping
func (s *Server) AddRoutes(fn func(r chi.Router)) {
	s.router.Route("/", fn)
}

// SetRouter sets a custom router
func (s *Server) SetRouter(router chi.Router) {
	s.router = router.(*chi.Mux)
}

// GetRouter returns the chi router
func (s *Server) GetRouter() chi.Router {
	return s.router
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	s.server = srv

	s.logger.Info("Starting HTTP server", "addr", addr)

	if s.config.TLSEnabled {
		if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but certificate or key file not provided")
		}
		return srv.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}

	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down HTTP server")
		
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Failed to shutdown HTTP server", "error", err)
		}
	}()

	return srv.ListenAndServe()
}

// Stop stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.logger.Info("Stopping HTTP server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return s.server.Shutdown(shutdownCtx)
}

// HealthHandler provides a health check endpoint
func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"http-server","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
}

// RegisterHealthCheck registers the health check endpoint
func (s *Server) RegisterHealthCheck() {
	s.AddRoute("GET", "/health", s.HealthHandler)
}

// RegisterPProf registers pprof endpoints for debugging (in development only)
func (s *Server) RegisterPProf() {
	// Only register in development
	// In a real implementation, you'd check the environment
	// For now, we'll comment this out
	// _ = pprof
}

// GetAddr returns the server address
func (s *Server) GetAddr() string {
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// Middleware adds middleware to the server
func (s *Server) Middleware(middlewareFunc func(http.Handler) http.Handler) {
	s.router.Use(middlewareFunc)
}

// Use adds middleware to the server
func (s *Server) Use(middlewareFunc ...func(http.Handler) http.Handler) {
	s.router.Use(middlewareFunc...)
}

// GetLogger returns the server logger
func (s *Server) GetLogger() logger.Logger {
	return s.logger
}

// GetConfig returns the server configuration
func (s *Server) GetConfig() *Config {
	return s.config
}

// AddMiddleware adds a middleware function
func (s *Server) AddMiddleware(middleware func(http.Handler) http.Handler) {
	s.router.Use(middleware)
}

// ConfigureStatic serves static files
func (s *Server) ConfigureStatic(urlPath, rootDir string) {
	fs := http.StripPrefix(urlPath, http.FileServer(http.Dir(rootDir)))
	s.router.Get(urlPath+"*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

// RegisterDefaultRoutes registers common routes like health, metrics, etc.
func (s *Server) RegisterDefaultRoutes() {
	s.router.Get("/health", s.HealthHandler)
	s.router.Get("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","uptime":"unknown"}`))
	})
}