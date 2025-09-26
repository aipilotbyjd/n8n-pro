// Package middleware provides HTTP middleware for the n8n-pro application
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"n8n-pro/internal/config"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
)

// Logger provides structured logging middleware
func Logger(logger interface{}) func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  logger,
		NoColor: true,
	})
}

// Recoverer recovers from panics and logs them
func Recoverer(logger interface{}) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					if rvr == http.ErrAbortHandler {
						panic(rvr)
					}

					// Log the panic
					logEntry := map[string]interface{}{
						"method":     r.Method,
						"url":        r.URL.String(),
						"remote_ip":  r.RemoteAddr,
						"user_agent": r.Header.Get("User-Agent"),
						"panic":      fmt.Sprintf("%+v", rvr),
						"stack":      string(debug.Stack()),
					}

					// Log based on logger type (simplified for this example)
					fmt.Printf("PANIC: %+v\n", logEntry)

					// Return 500 error
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":   "Internal Server Error",
						"code":    "INTERNAL_ERROR",
						"message": "An unexpected error occurred",
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders(cfg *config.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			
			if cfg.Security.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", cfg.Security.ContentSecurityPolicy)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit implements token bucket rate limiting
func RateLimit(cfg *config.Config) func(next http.Handler) http.Handler {
	// Create a rate limiter for the configured rate
	limiter := rate.NewLimiter(
		rate.Limit(cfg.Security.RateLimitRequests)/rate.Limit(cfg.Security.RateLimitWindow.Seconds()),
		cfg.Security.RateLimitRequests,
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "Rate limit exceeded",
					"code":    "RATE_LIMIT_EXCEEDED",
					"message": "Too many requests. Please try again later.",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestSizeLimit limits the size of request bodies
func RequestSizeLimit(maxSize int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}

// Metrics provides Prometheus metrics middleware
func Metrics(namespace string) func(next http.Handler) http.Handler {
	// Create metrics
	requestsTotal := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	requestDuration := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	activeRequests := promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "http_requests_active",
			Help:      "Number of active HTTP requests",
		},
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			activeRequests.Inc()
			defer activeRequests.Dec()

			// Wrap response writer to capture status code
			ww := &responseWriter{ResponseWriter: w, statusCode: 200}

			next.ServeHTTP(ww, r)

			// Record metrics
			duration := time.Since(start).Seconds()
			endpoint := getEndpoint(r)
			
			requestsTotal.WithLabelValues(r.Method, endpoint, strconv.Itoa(ww.statusCode)).Inc()
			requestDuration.WithLabelValues(r.Method, endpoint).Observe(duration)
		})
	}
}

// Authentication middleware for JWT token validation
func Authentication(cfg *config.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health checks and metrics
			if strings.HasPrefix(r.URL.Path, "/health") || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeUnauthorizedResponse(w, "Missing authorization header")
				return
			}

			// Check if it's a Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				writeUnauthorizedResponse(w, "Invalid authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				writeUnauthorizedResponse(w, "Missing token")
				return
			}

			// TODO: Implement actual JWT validation here
			// For now, we'll accept any non-empty token in development
			if cfg.App.Environment == "development" && token != "" {
				// Add user context (mock for development)
				ctx := context.WithValue(r.Context(), "user_id", "dev-user-id")
				ctx = context.WithValue(ctx, "organization_id", "dev-org-id")
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}

			// In production, validate JWT token properly
			// userID, orgID, err := validateJWTToken(token, cfg.JWT.Secret)
			// if err != nil {
			//     writeUnauthorizedResponse(w, "Invalid token")
			//     return
			// }

			// ctx := context.WithValue(r.Context(), "user_id", userID)
			// ctx = context.WithValue(ctx, "organization_id", orgID)
			// r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// CORS middleware (using go-chi/cors, but here's a custom implementation)
func CORS(origins []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range origins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, X-Request-ID")
				w.Header().Set("Access-Control-Max-Age", "300")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestID adds a unique request ID to each request
func RequestID() func(next http.Handler) http.Handler {
	return middleware.RequestID
}

// Timeout wraps a handler with a timeout
func Timeout(timeout time.Duration) func(next http.Handler) http.Handler {
	return middleware.Timeout(timeout)
}

// Helper types and functions

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getEndpoint(r *http.Request) string {
	// Simplify the endpoint path for metrics
	path := r.URL.Path
	
	// Replace common ID patterns with placeholders
	path = strings.ReplaceAll(path, "/api/v1/users/", "/api/v1/users/{id}/")
	path = strings.ReplaceAll(path, "/api/v1/workflows/", "/api/v1/workflows/{id}/")
	path = strings.ReplaceAll(path, "/api/v1/organizations/", "/api/v1/organizations/{id}/")
	path = strings.ReplaceAll(path, "/api/v1/teams/", "/api/v1/teams/{id}/")
	
	return path
}

func writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "Unauthorized",
		"code":    "UNAUTHORIZED",
		"message": message,
	})
}

// Context helpers

// GetUserID extracts user ID from request context
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value("user_id").(string)
	return userID, ok
}

// GetOrganizationID extracts organization ID from request context
func GetOrganizationID(ctx context.Context) (string, bool) {
	orgID, ok := ctx.Value("organization_id").(string)
	return orgID, ok
}

// RequireUser ensures user is authenticated
func RequireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r.Context())
		if !ok || userID == "" {
			writeUnauthorizedResponse(w, "User authentication required")
			return
		}
		next.ServeHTTP(w, r)
	}
}

// RequireRole ensures user has required role
func RequireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// TODO: Implement role checking
			// For now, just require user authentication
			userID, ok := GetUserID(r.Context())
			if !ok || userID == "" {
				writeUnauthorizedResponse(w, "Authentication required")
				return
			}
			
			// In a real implementation, you'd check the user's role here
			// userRole := getUserRole(userID)
			// if !contains(roles, userRole) {
			//     writeForbiddenResponse(w, "Insufficient permissions")
			//     return
			// }
			
			next.ServeHTTP(w, r)
		}
	}
}