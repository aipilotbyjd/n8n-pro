package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/errors"

	"github.com/go-chi/chi/v5/middleware"
)

// AuthContextKey represents context keys for authentication data
type AuthContextKey string

const (
	UserIDKey        AuthContextKey = "user_id"
	EmailKey         AuthContextKey = "email"
	RoleKey          AuthContextKey = "role"
	OrganizationIDKey AuthContextKey = "organization_id"
	TeamIDKey        AuthContextKey = "team_id"
	ScopesKey        AuthContextKey = "scopes"
	AuthMethodKey    AuthContextKey = "auth_method"
	APIKeyIDKey      AuthContextKey = "api_key_id"
)

// AuthMethod represents the authentication method used
type AuthMethod string

const (
	AuthMethodJWT    AuthMethod = "jwt"
	AuthMethodAPIKey AuthMethod = "api_key"
	AuthMethodNone   AuthMethod = "none"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	authService *AuthService
	logger      logger.Logger
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService *AuthService, logger logger.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		logger:      logger,
	}
}

// RequireAuth is the main authentication middleware
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for certain paths
		if m.shouldSkipAuth(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Try JWT authentication first
		if m.tryJWTAuth(w, r, next) {
			return
		}

		// Try API key authentication
		if m.tryAPIKeyAuth(w, r, next) {
			return
		}

		// No valid authentication found
		m.writeUnauthorizedResponse(w, "Authentication required")
	})
}

// OptionalAuth provides optional authentication (doesn't fail if no auth)
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try authentication but don't fail if none found
		if !m.tryJWTAuth(w, r, nil) {
			m.tryAPIKeyAuth(w, r, nil)
		}

		// Always continue to next handler
		next.ServeHTTP(w, r)
	})
}

// RequireAPIKey requires API key authentication specifically
func (m *AuthMiddleware) RequireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.tryAPIKeyAuth(w, r, next) {
			m.writeUnauthorizedResponse(w, "Valid API key required")
		}
	})
}

// tryJWTAuth attempts JWT authentication
func (m *AuthMiddleware) tryJWTAuth(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	// Check if it's a Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}

	token := parts[1]
	if token == "" {
		return false
	}

	// Validate the token
	claims, err := m.authService.ValidateAccessToken(r.Context(), token)
	if err != nil {
		m.logger.Debug("JWT validation failed", "error", err, "token", token[:10]+"...")
		return false
	}

	// Add claims to context
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
	ctx = context.WithValue(ctx, EmailKey, claims.Email)
	ctx = context.WithValue(ctx, RoleKey, claims.Role)
	ctx = context.WithValue(ctx, TeamIDKey, claims.TeamID)
	ctx = context.WithValue(ctx, ScopesKey, claims.Scopes)
	ctx = context.WithValue(ctx, AuthMethodKey, AuthMethodJWT)

	// Add request ID from middleware
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		m.logger.Info("JWT authentication successful",
			"user_id", claims.UserID,
			"email", claims.Email,
			"role", claims.Role,
			"request_id", reqID,
		)
	}

	// Continue with authenticated context
	r = r.WithContext(ctx)
	if next != nil {
		next.ServeHTTP(w, r)
	}
	return true
}

// tryAPIKeyAuth attempts API key authentication
func (m *AuthMiddleware) tryAPIKeyAuth(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	// Try to get API key from different sources
	apiKey := m.extractAPIKey(r)
	if apiKey == "" {
		return false
	}

	// Validate the API key
	keyInfo, err := m.authService.apiKeyRepo.FindByKey(r.Context(), apiKey)
	if err != nil {
		m.logger.Debug("API key validation failed", "error", err, "key_prefix", apiKey[:12])
		return false
	}

	// Update last used timestamp (async)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.authService.apiKeyRepo.UpdateLastUsed(ctx, keyInfo.ID); err != nil {
			m.logger.Error("Failed to update API key usage", "error", err, "key_id", keyInfo.ID)
		}
	}()

	// Add key info to context
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserIDKey, keyInfo.UserID)
	ctx = context.WithValue(ctx, OrganizationIDKey, keyInfo.OrganizationID)
	ctx = context.WithValue(ctx, ScopesKey, keyInfo.Scopes)
	ctx = context.WithValue(ctx, AuthMethodKey, AuthMethodAPIKey)
	ctx = context.WithValue(ctx, APIKeyIDKey, keyInfo.ID)

	m.logger.Info("API key authentication successful",
		"user_id", keyInfo.UserID,
		"key_id", keyInfo.ID,
		"key_name", keyInfo.Name,
	)

	// Continue with authenticated context
	r = r.WithContext(ctx)
	if next != nil {
		next.ServeHTTP(w, r)
	}
	return true
}

// extractAPIKey extracts API key from various sources
func (m *AuthMiddleware) extractAPIKey(r *http.Request) string {
	// 1. Authorization header with Bearer
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			token := parts[1]
			// Check if it looks like an API key (starts with n8n_)
			if strings.HasPrefix(token, "n8n_") {
				return token
			}
		}
	}

	// 2. X-API-Key header
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// 3. Query parameter (less secure, but sometimes needed)
	if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
		return apiKey
	}

	return ""
}

// shouldSkipAuth checks if authentication should be skipped for this request
func (m *AuthMiddleware) shouldSkipAuth(r *http.Request) bool {
	path := r.URL.Path

	// Skip auth for public endpoints
	publicPaths := []string{
		"/health",
		"/metrics",
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/refresh",
		"/api/v1/auth/forgot-password",
		"/api/v1/auth/reset-password",
		"/api/v1/auth/verify-email",
		"/api/v1/invitations/",
		"/webhooks/",
		"/api/v1/auth/health",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}

	return false
}

// writeUnauthorizedResponse writes an unauthorized response
func (m *AuthMiddleware) writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	
	response := map[string]interface{}{
		"error": "Unauthorized",
		"code":  "UNAUTHORIZED",
		"message": message,
	}
	
	json.NewEncoder(w).Encode(response)
}

// Context helper functions

// GetUserID extracts user ID from request context
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

// GetEmail extracts email from request context
func GetEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(EmailKey).(string)
	return email, ok
}

// GetRole extracts role from request context
func GetRole(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(RoleKey).(string)
	return role, ok
}

// GetOrganizationID extracts organization ID from request context
func GetOrganizationID(ctx context.Context) (string, bool) {
	orgID, ok := ctx.Value(OrganizationIDKey).(string)
	return orgID, ok
}

// GetTeamID extracts team ID from request context
func GetTeamID(ctx context.Context) (string, bool) {
	teamID, ok := ctx.Value(TeamIDKey).(string)
	return teamID, ok
}

// GetScopes extracts scopes from request context
func GetScopes(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value(ScopesKey).([]string)
	return scopes, ok
}

// GetAuthMethod extracts authentication method from request context
func GetAuthMethod(ctx context.Context) (AuthMethod, bool) {
	method, ok := ctx.Value(AuthMethodKey).(AuthMethod)
	return method, ok
}

// GetAPIKeyID extracts API key ID from request context
func GetAPIKeyID(ctx context.Context) (string, bool) {
	keyID, ok := ctx.Value(APIKeyIDKey).(string)
	return keyID, ok
}

// RequireUser ensures user is authenticated
func RequireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r.Context())
		if !ok || userID == "" {
			writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", "AUTHENTICATION_REQUIRED")
			return
		}
		next.ServeHTTP(w, r)
	}
}

// RequireRole ensures user has required role
func RequireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok || userID == "" {
				writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
				return
			}

			role, ok := GetRole(r.Context())
			if !ok {
				writeErrorResponse(w, http.StatusForbidden, "Role information not available", "ROLE_REQUIRED")
				return
			}

			// Check if user has required role
			hasRole := false
			for _, requiredRole := range roles {
				if role == requiredRole {
					hasRole = true
					break
				}
			}

			if !hasRole {
				writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS")
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// RequireScope ensures user has required scope
func RequireScope(requiredScopes ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok || userID == "" {
				writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
				return
			}

			scopes, ok := GetScopes(r.Context())
			if !ok {
				writeErrorResponse(w, http.StatusForbidden, "Scope information not available", "SCOPE_REQUIRED")
				return
			}

			// Check if user has required scopes
			hasAllScopes := true
			for _, requiredScope := range requiredScopes {
				hasScope := false
				for _, userScope := range scopes {
					if userScope == requiredScope {
						hasScope = true
						break
					}
				}
				if !hasScope {
					hasAllScopes = false
					break
				}
			}

			if !hasAllScopes {
				writeErrorResponse(w, http.StatusForbidden, "Insufficient scopes", "INSUFFICIENT_SCOPES")
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// writeErrorResponse writes an error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":   http.StatusText(statusCode),
		"code":    code,
		"message": message,
	}
	
	json.NewEncoder(w).Encode(response)
}

// RequestInfo holds information about the current request
type RequestInfo struct {
	UserID         string
	Email          string
	Role           string
	OrganizationID string
	TeamID         string
	Scopes         []string
	AuthMethod     AuthMethod
	APIKeyID       string
	IsAuthenticated bool
}

// GetRequestInfo extracts all auth information from context
func GetRequestInfo(ctx context.Context) *RequestInfo {
	info := &RequestInfo{}

	if userID, ok := GetUserID(ctx); ok {
		info.UserID = userID
		info.IsAuthenticated = true
	}

	if email, ok := GetEmail(ctx); ok {
		info.Email = email
	}

	if role, ok := GetRole(ctx); ok {
		info.Role = role
	}

	if orgID, ok := GetOrganizationID(ctx); ok {
		info.OrganizationID = orgID
	}

	if teamID, ok := GetTeamID(ctx); ok {
		info.TeamID = teamID
	}

	if scopes, ok := GetScopes(ctx); ok {
		info.Scopes = scopes
	}

	if method, ok := GetAuthMethod(ctx); ok {
		info.AuthMethod = method
	}

	if keyID, ok := GetAPIKeyID(ctx); ok {
		info.APIKeyID = keyID
	}

	return info
}