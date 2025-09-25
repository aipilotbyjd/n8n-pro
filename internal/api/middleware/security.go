package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/time/rate"
)

// SecurityMiddleware provides various security-related middleware
type SecurityMiddleware struct {
	rateLimiters map[string]*rate.Limiter
	mutex        sync.RWMutex
	logger       logger.Logger
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(logger logger.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		rateLimiters: make(map[string]*rate.Limiter),
		logger:       logger,
	}
}

// RateLimit creates a rate limiting middleware
func (s *SecurityMiddleware) RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			
			limiter := s.getLimiter(clientIP, requestsPerMinute)
			
			if !limiter.Allow() {
				s.logger.Warn("Rate limit exceeded", "client_ip", clientIP, "path", r.URL.Path)
				writeSecurityError(w, errors.NewRateLimitError("Too many requests"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// StrictRateLimit creates a stricter rate limiting middleware for sensitive endpoints
func (s *SecurityMiddleware) StrictRateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			key := clientIP + ":" + r.URL.Path
			
			limiter := s.getLimiter(key, requestsPerMinute)
			
			if !limiter.Allow() {
				s.logger.Warn("Strict rate limit exceeded", "client_ip", clientIP, "path", r.URL.Path)
				
				// Add additional headers for strict rate limiting
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(requestsPerMinute))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
				
				writeSecurityError(w, errors.NewRateLimitError("Rate limit exceeded for this endpoint"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers to responses
func (s *SecurityMiddleware) SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			
			// HSTS (HTTP Strict Transport Security)
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			
			// Content Security Policy
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
				"style-src 'self' 'unsafe-inline'; " +
				"img-src 'self' data: https:; " +
				"font-src 'self' data:; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none'"
			w.Header().Set("Content-Security-Policy", csp)

			next.ServeHTTP(w, r)
		})
	}
}

// CORS handles Cross-Origin Resource Sharing
func (s *SecurityMiddleware) CORS(allowedOrigins []string, allowCredentials bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Check if origin is allowed
			allowed := false
			if len(allowedOrigins) == 0 {
				// If no origins specified, allow all (not recommended for production)
				allowed = true
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				for _, allowedOrigin := range allowedOrigins {
					if allowedOrigin == "*" || allowedOrigin == origin {
						allowed = true
						w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
						break
					}
				}
			}

			if !allowed && origin != "" {
				s.logger.Warn("CORS request from disallowed origin", "origin", origin, "path", r.URL.Path)
				writeSecurityError(w, errors.NewForbiddenError("Origin not allowed"))
				return
			}

			// Set CORS headers
			if allowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "3600")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtection provides CSRF protection for state-changing operations
func (s *SecurityMiddleware) CSRFProtection(cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF protection for safe methods
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF protection for API key authentication
			if r.Header.Get("Authorization") != "" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				// This is likely API key authentication, skip CSRF
				next.ServeHTTP(w, r)
				return
			}

			// Get CSRF token from header
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}

			if csrfToken == "" {
				s.logger.Warn("CSRF token missing", "path", r.URL.Path, "method", r.Method, "client_ip", getClientIP(r))
				writeSecurityError(w, errors.NewForbiddenError("CSRF token required"))
				return
			}

			// Get expected token from cookie
			cookie, err := r.Cookie(cookieName)
			if err != nil || cookie.Value == "" {
				s.logger.Warn("CSRF cookie missing", "path", r.URL.Path, "method", r.Method, "client_ip", getClientIP(r))
				writeSecurityError(w, errors.NewForbiddenError("CSRF token invalid"))
				return
			}

			// Validate token
			if !validateCSRFToken(csrfToken, cookie.Value) {
				s.logger.Warn("CSRF token invalid", "path", r.URL.Path, "method", r.Method, "client_ip", getClientIP(r))
				writeSecurityError(w, errors.NewForbiddenError("CSRF token invalid"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestSizeLimit limits the size of request bodies
func (s *SecurityMiddleware) RequestSizeLimit(maxSizeBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSizeBytes {
				s.logger.Warn("Request body too large", "size", r.ContentLength, "limit", maxSizeBytes, "path", r.URL.Path)
				writeSecurityError(w, errors.NewValidationError("Request body too large"))
				return
			}

			// Limit the reader to prevent memory exhaustion attacks
			r.Body = http.MaxBytesReader(w, r.Body, maxSizeBytes)

			next.ServeHTTP(w, r)
		})
	}
}

// IPWhitelist restricts access to whitelisted IP addresses
func (s *SecurityMiddleware) IPWhitelist(allowedIPs []string) func(http.Handler) http.Handler {
	// Convert to map for faster lookup
	allowedIPMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowedIPMap[ip] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			
			if !allowedIPMap[clientIP] {
				s.logger.Warn("IP not whitelisted", "client_ip", clientIP, "path", r.URL.Path)
				writeSecurityError(w, errors.NewForbiddenError("Access denied"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestTimeout sets a timeout for request processing
func (s *SecurityMiddleware) RequestTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)

			done := make(chan bool)
			go func() {
				next.ServeHTTP(w, r)
				done <- true
			}()

			select {
			case <-ctx.Done():
				s.logger.Warn("Request timeout", "path", r.URL.Path, "timeout", timeout)
				writeSecurityError(w, errors.NewTimeoutError("Request timeout"))
				return
			case <-done:
				return
			}
		})
	}
}

// RequestValidation validates basic request structure
func (s *SecurityMiddleware) RequestValidation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate Content-Type for POST/PUT/PATCH requests
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
				contentType := r.Header.Get("Content-Type")
				if contentType == "" {
					writeSecurityError(w, errors.NewValidationError("Content-Type header required"))
					return
				}

				// Allow JSON and form data
				if !strings.HasPrefix(contentType, "application/json") &&
					!strings.HasPrefix(contentType, "application/x-www-form-urlencoded") &&
					!strings.HasPrefix(contentType, "multipart/form-data") {
					writeSecurityError(w, errors.NewValidationError("Unsupported Content-Type"))
					return
				}
			}

			// Validate User-Agent (optional but recommended)
			userAgent := r.Header.Get("User-Agent")
			if userAgent == "" {
				s.logger.Debug("Request without User-Agent", "path", r.URL.Path, "client_ip", getClientIP(r))
			}

			// Check for suspicious patterns in URL
			if containsSuspiciousPatterns(r.URL.Path) {
				s.logger.Warn("Suspicious URL pattern detected", "path", r.URL.Path, "client_ip", getClientIP(r))
				writeSecurityError(w, errors.NewValidationError("Invalid request"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Antibot middleware to detect and block automated requests
func (s *SecurityMiddleware) AntiBot() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userAgent := r.Header.Get("User-Agent")
			
			// Check for common bot signatures
			if isLikelyBot(userAgent) {
				s.logger.Warn("Bot request detected", "user_agent", userAgent, "path", r.URL.Path, "client_ip", getClientIP(r))
				
				// Don't block legitimate crawlers for GET requests
				if r.Method != "GET" {
					writeSecurityError(w, errors.NewForbiddenError("Automated requests not allowed"))
					return
				}
			}

			// Check for honeypot field (if present in form data)
			if r.Method == "POST" && r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
				if err := r.ParseForm(); err == nil {
					if r.FormValue("website") != "" { // Honeypot field
						s.logger.Warn("Honeypot field filled", "path", r.URL.Path, "client_ip", getClientIP(r))
						writeSecurityError(w, errors.NewValidationError("Invalid request"))
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

// getLimiter gets or creates a rate limiter for a key
func (s *SecurityMiddleware) getLimiter(key string, requestsPerMinute int) *rate.Limiter {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	limiter, exists := s.rateLimiters[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), requestsPerMinute)
		s.rateLimiters[key] = limiter
	}

	return limiter
}

// generateCSRFToken generates a new CSRF token
func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// validateCSRFToken validates a CSRF token
func validateCSRFToken(token, expected string) bool {
	return token != "" && token == expected
}

// SetCSRFCookie sets a CSRF cookie
func SetCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: false, // Must be accessible by JavaScript
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// containsSuspiciousPatterns checks for suspicious URL patterns
func containsSuspiciousPatterns(path string) bool {
	suspiciousPatterns := []string{
		"../", "..\\", // Path traversal
		"<script", "</script>", // XSS attempts
		"javascript:", "data:", // Dangerous protocols
		"union select", "drop table", // SQL injection attempts
		"%3Cscript", "%3C/script%3E", // URL-encoded XSS
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isLikelyBot checks if a user agent looks like a bot
func isLikelyBot(userAgent string) bool {
	if userAgent == "" {
		return true
	}

	botSignatures := []string{
		"bot", "crawler", "spider", "scraper",
		"python", "curl", "wget", "libwww",
		"httpclient", "okhttp", "go-http-client",
		"axios", "node-fetch", "request",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, signature := range botSignatures {
		if strings.Contains(lowerUA, signature) {
			return true
		}
	}
	return false
}

// writeSecurityError writes a security-related error response
func writeSecurityError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	
	if apiError, ok := err.(*errors.APIError); ok {
		w.WriteHeader(apiError.StatusCode)
		w.Write([]byte(`{"error": "` + apiError.Message + `", "code": "` + apiError.Code + `"}`))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error", "code": "INTERNAL_ERROR"}`))
	}
}

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	RateLimit struct {
		RequestsPerMinute int      `json:"requests_per_minute"`
		Enabled           bool     `json:"enabled"`
	} `json:"rate_limit"`
	
	CORS struct {
		AllowedOrigins   []string `json:"allowed_origins"`
		AllowCredentials bool     `json:"allow_credentials"`
		Enabled          bool     `json:"enabled"`
	} `json:"cors"`
	
	CSRF struct {
		CookieName string `json:"cookie_name"`
		Enabled    bool   `json:"enabled"`
	} `json:"csrf"`
	
	Security struct {
		MaxRequestSize int64    `json:"max_request_size"`
		RequestTimeout int      `json:"request_timeout_seconds"`
		IPWhitelist    []string `json:"ip_whitelist"`
		Enabled        bool     `json:"enabled"`
	} `json:"security"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		RateLimit: struct {
			RequestsPerMinute int  `json:"requests_per_minute"`
			Enabled           bool `json:"enabled"`
		}{
			RequestsPerMinute: 100,
			Enabled:           true,
		},
		CORS: struct {
			AllowedOrigins   []string `json:"allowed_origins"`
			AllowCredentials bool     `json:"allow_credentials"`
			Enabled          bool     `json:"enabled"`
		}{
			AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8080"},
			AllowCredentials: true,
			Enabled:          true,
		},
		CSRF: struct {
			CookieName string `json:"cookie_name"`
			Enabled    bool   `json:"enabled"`
		}{
			CookieName: "csrf_token",
			Enabled:    true,
		},
		Security: struct {
			MaxRequestSize int64    `json:"max_request_size"`
			RequestTimeout int      `json:"request_timeout_seconds"`
			IPWhitelist    []string `json:"ip_whitelist"`
			Enabled        bool     `json:"enabled"`
		}{
			MaxRequestSize: 10 * 1024 * 1024, // 10MB
			RequestTimeout: 30,                // 30 seconds
			IPWhitelist:    []string{},        // Empty = allow all
			Enabled:        true,
		},
	}
}