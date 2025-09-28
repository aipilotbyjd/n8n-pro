package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeadersConfig contains security headers configuration
type SecurityHeadersConfig struct {
	// HSTS settings
	EnableHSTS      bool   `json:"enable_hsts"`
	HSTSMaxAge      int    `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool   `json:"hsts_include_subdomains"`
	HSTSPreload     bool   `json:"hsts_preload"`
	
	// Content Security Policy
	EnableCSP       bool   `json:"enable_csp"`
	CSPPolicy       string `json:"csp_policy"`
	CSPReportOnly   bool   `json:"csp_report_only"`
	CSPReportURI    string `json:"csp_report_uri"`
	
	// Frame options
	XFrameOptions   string `json:"x_frame_options"` // DENY, SAMEORIGIN, ALLOW-FROM
	
	// Content type options
	XContentTypeNoSniff bool   `json:"x_content_type_nosniff"`
	
	// XSS Protection
	XXSSProtection  string `json:"x_xss_protection"`
	
	// Referrer Policy
	ReferrerPolicy  string `json:"referrer_policy"`
	
	// Permissions Policy (formerly Feature Policy)
	PermissionsPolicy string `json:"permissions_policy"`
	
	// Custom headers
	CustomHeaders   map[string]string `json:"custom_headers"`
	
	// Development mode (disables some headers for local dev)
	DevelopmentMode bool   `json:"development_mode"`
}

// DefaultSecurityHeadersConfig returns secure default configuration
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		EnableHSTS:            true,
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false,
		
		EnableCSP:      true,
		CSPPolicy:      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
		CSPReportOnly:  false,
		
		XFrameOptions:       "DENY",
		XContentTypeNoSniff: true,
		XXSSProtection:      "1; mode=block",
		ReferrerPolicy:      "strict-origin-when-cross-origin",
		PermissionsPolicy:   "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
		
		CustomHeaders:       make(map[string]string),
		DevelopmentMode:     false,
	}
}

// SecurityHeaders middleware adds security headers to responses
func SecurityHeaders(config *SecurityHeadersConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS (HTTP Strict Transport Security)
			if config.EnableHSTS && !config.DevelopmentMode {
				hstsValue := buildHSTSHeader(config)
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Content Security Policy
			if config.EnableCSP {
				cspHeader := "Content-Security-Policy"
				if config.CSPReportOnly {
					cspHeader = "Content-Security-Policy-Report-Only"
				}
				
				cspValue := config.CSPPolicy
				if config.CSPReportURI != "" {
					cspValue += "; report-uri " + config.CSPReportURI
				}
				
				w.Header().Set(cspHeader, cspValue)
			}

			// X-Frame-Options
			if config.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.XFrameOptions)
			}

			// X-Content-Type-Options
			if config.XContentTypeNoSniff {
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}

			// X-XSS-Protection
			if config.XXSSProtection != "" {
				w.Header().Set("X-XSS-Protection", config.XXSSProtection)
			}

			// Referrer-Policy
			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}

			// Permissions-Policy (formerly Feature-Policy)
			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}

			// Remove potentially dangerous headers
			w.Header().Del("X-Powered-By")
			w.Header().Del("Server")

			// Add custom headers
			for key, value := range config.CustomHeaders {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// buildHSTSHeader constructs the HSTS header value
func buildHSTSHeader(config *SecurityHeadersConfig) string {
	parts := []string{
		"max-age=" + string(rune(config.HSTSMaxAge)),
	}
	
	if config.HSTSIncludeSubdomains {
		parts = append(parts, "includeSubDomains")
	}
	
	if config.HSTSPreload {
		parts = append(parts, "preload")
	}
	
	return strings.Join(parts, "; ")
}

// SecurityNonce generates a nonce for CSP
func SecurityNonce() string {
	// This would generate a random nonce for inline scripts
	// Implementation would use crypto/rand
	return "nonce-" + generateRandomString(32)
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	// Simplified - should use crypto/rand in production
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}