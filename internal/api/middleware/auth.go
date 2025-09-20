package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5/middleware"
)

const (
	// AuthorizationHeader is the header key for authorization
	AuthorizationHeader = "Authorization"
	// BearerPrefix is the prefix for bearer tokens
	BearerPrefix = "Bearer "
	// UserContextKey is the context key for user information
	UserContextKey = "user"
	// TeamContextKey is the context key for team information
	TeamContextKey = "team"
	// RequestIDContextKey is the context key for request ID
	RequestIDContextKey = "request_id"
)

// AuthConfig holds authentication middleware configuration
type AuthConfig struct {
	JWTSecret         string
	RequiredScopes    []string
	SkipPaths         []string
	EnableRateLimit   bool
	RateLimitRequests int
	RateLimitWindow   time.Duration
}

// AuthMiddleware handles authentication for API requests
func AuthMiddleware(config *AuthConfig, jwtService *jwt.Service, log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Add request ID if not present
			if requestID := middleware.GetReqID(ctx); requestID != "" {
				ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
			}

			// Check if path should skip authentication
			if shouldSkipAuth(r.URL.Path, config.SkipPaths) {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Extract and validate token
			token, err := extractBearerToken(r)
			if err != nil {
				log.Warn("Failed to extract bearer token", "error", err, "path", r.URL.Path)
				writeErrorResponse(w, errors.NewUnauthorizedError("Missing or invalid authorization header"))
				return
			}

			// Validate JWT token
			claims, err := jwtService.ValidateToken(token)
			if err != nil {
				log.Warn("Failed to validate JWT token", "error", err, "path", r.URL.Path)
				writeErrorResponse(w, errors.NewUnauthorizedError("Invalid or expired token"))
				return
			}

			// Check token expiration
			if claims.IsExpired() {
				log.Warn("JWT token expired", "user_id", claims.UserID, "exp", claims.ExpiresAt)
				writeErrorResponse(w, errors.NewUnauthorizedError("Token has expired"))
				return
			}

			// Check required scopes if specified
			if len(config.RequiredScopes) > 0 && !hasRequiredScopes(claims.Scopes, config.RequiredScopes) {
				log.Warn("Insufficient scopes", "user_id", claims.UserID, "required", config.RequiredScopes, "actual", claims.Scopes)
				writeErrorResponse(w, errors.NewForbiddenError("Insufficient permissions"))
				return
			}

			// Create user context
			user := &common.User{
				ID:       claims.UserID,
				Email:    claims.Email,
				Role:     claims.Role,
				TeamID:   claims.TeamID,
				Scopes:   claims.Scopes,
				IsActive: true,
			}

			// Add user to context
			ctx = context.WithValue(ctx, UserContextKey, user)

			// Add team information if available
			if claims.TeamID != "" {
				team := &common.Team{
					ID:   claims.TeamID,
					Name: claims.TeamName,
					Plan: claims.TeamPlan,
				}
				ctx = context.WithValue(ctx, TeamContextKey, team)
			}

			// Log successful authentication
			log.Info("Request authenticated",
				"user_id", user.ID,
				"team_id", user.TeamID,
				"method", r.Method,
				"path", r.URL.Path,
				"user_agent", r.UserAgent(),
				"ip", getClientIP(r),
			)

			// Continue to next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth middleware that requires authentication for all requests
func RequireAuth(jwtService *jwt.Service, log logger.Logger) func(http.Handler) http.Handler {
	config := &AuthConfig{
		RequiredScopes: []string{},
		SkipPaths:      []string{},
	}
	return AuthMiddleware(config, jwtService, log)
}

// RequireRole middleware that requires specific role
func RequireRole(role string, jwtService *jwt.Service, log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAuth(jwtService, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
				return
			}

			if user.Role != role && user.Role != "admin" { // admin can access everything
				log.Warn("Insufficient role", "user_id", user.ID, "required_role", role, "actual_role", user.Role)
				writeErrorResponse(w, errors.NewForbiddenError("Insufficient role permissions"))
				return
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// RequireScopes middleware that requires specific scopes
func RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
				return
			}

			if !hasRequiredScopes(user.Scopes, scopes) {
				writeErrorResponse(w, errors.NewForbiddenError("Insufficient scope permissions"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// APIKeyMiddleware handles API key authentication
func APIKeyMiddleware(validateAPIKey func(string) (*common.User, error), log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check for API key in header
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				// Check query parameter as fallback
				apiKey = r.URL.Query().Get("api_key")
			}

			if apiKey == "" {
				writeErrorResponse(w, errors.NewUnauthorizedError("API key required"))
				return
			}

			// Validate API key
			user, err := validateAPIKey(apiKey)
			if err != nil {
				log.Warn("Invalid API key", "error", err, "ip", getClientIP(r))
				writeErrorResponse(w, errors.NewUnauthorizedError("Invalid API key"))
				return
			}

			// Add user to context
			ctx = context.WithValue(ctx, UserContextKey, user)

			log.Info("API key authentication successful",
				"user_id", user.ID,
				"method", r.Method,
				"path", r.URL.Path,
				"ip", getClientIP(r),
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *common.User {
	if user, ok := ctx.Value(UserContextKey).(*common.User); ok {
		return user
	}
	return nil
}

// GetTeamFromContext extracts team from request context
func GetTeamFromContext(ctx context.Context) *common.Team {
	if team, ok := ctx.Value(TeamContextKey).(*common.Team); ok {
		return team
	}
	return nil
}

// GetRequestIDFromContext extracts request ID from context
func GetRequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}

// Helper functions

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		return "", errors.NewValidationError("Authorization header is required")
	}

	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", errors.NewValidationError("Authorization header must start with 'Bearer '")
	}

	token := strings.TrimPrefix(authHeader, BearerPrefix)
	if token == "" {
		return "", errors.NewValidationError("Bearer token is empty")
	}

	return token, nil
}

func shouldSkipAuth(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	// Default paths that should skip authentication
	defaultSkipPaths := []string{
		"/health",
		"/version",
		"/metrics",
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/refresh",
		"/api/v1/auth/reset-password",
		"/api/v1/webhooks/public",
	}

	for _, skipPath := range defaultSkipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath+"/") {
			return true
		}
	}

	return false
}

func hasRequiredScopes(userScopes, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	scopeSet := make(map[string]bool)
	for _, scope := range userScopes {
		scopeSet[scope] = true
	}

	for _, required := range requiredScopes {
		if !scopeSet[required] {
			return false
		}
	}

	return true
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Get the first IP from the list
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		host, _, found := strings.Cut(ip, ":")
		if found {
			return host
		}
	}

	return ip
}

func writeErrorResponse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	var message string

	if appErr := errors.GetAppError(err); appErr != nil {
		statusCode = appErr.HTTPStatus()
		message = appErr.Message
	} else {
		statusCode = http.StatusInternalServerError
		message = "Internal server error"
	}

	w.WriteHeader(statusCode)
	response := fmt.Sprintf(`{"error":"%s","status":%d}`, message, statusCode)
	w.Write([]byte(response))
}

// CORS middleware for handling cross-origin requests
func CORSMiddleware(allowedOrigins, allowedMethods, allowedHeaders []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if isOriginAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "300")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// RequestLogger middleware for logging HTTP requests
func RequestLogger(log logger.Logger) func(http.Handler) http.Handler {
	return middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  &loggerAdapter{log},
		NoColor: true,
	})
}

// loggerAdapter adapts our logger.Logger to chi's middleware.LoggerInterface
type loggerAdapter struct {
	logger.Logger
}

func (l *loggerAdapter) Print(v ...interface{}) {
	l.Logger.Info(fmt.Sprint(v...))
}
