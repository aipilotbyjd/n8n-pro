package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	if e.Value != nil {
		return fmt.Sprintf("validation error for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
	}
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("configuration validation failed: %s", strings.Join(messages, "; "))
}

// HasErrors returns true if there are validation errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// Add adds a validation error
func (e *ValidationErrors) Add(field, message string, value interface{}) {
	*e = append(*e, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}


// validateEnvironment validates the environment configuration
func (c *Config) validateEnvironment(errors *ValidationErrors) {
	validEnvironments := map[string]bool{
		"development": true,
		"staging":     true,
		"production":  true,
		"testing":     true,
	}

	if !validEnvironments[c.Environment] {
		errors.Add("environment", "invalid environment", c.Environment)
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		errors.Add("log_level", "invalid log level", c.LogLevel)
	}
}

// validate validates API configuration
func (a *APIConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate host
	if a.Host == "" {
		errors.Add(prefix+".host", "host cannot be empty", a.Host)
	} else {
		// Check if it's a valid IP or hostname
		if net.ParseIP(a.Host) == nil && !isValidHostname(a.Host) {
			errors.Add(prefix+".host", "invalid host", a.Host)
		}
	}

	// Validate port
	if a.Port < 1 || a.Port > 65535 {
		errors.Add(prefix+".port", "port must be between 1 and 65535", a.Port)
	}

	// Validate timeouts
	if a.ReadTimeout <= 0 {
		errors.Add(prefix+".read_timeout", "read timeout must be positive", a.ReadTimeout)
	}
	if a.WriteTimeout <= 0 {
		errors.Add(prefix+".write_timeout", "write timeout must be positive", a.WriteTimeout)
	}
	if a.IdleTimeout <= 0 {
		errors.Add(prefix+".idle_timeout", "idle timeout must be positive", a.IdleTimeout)
	}

	// Validate request size
	if a.MaxRequestSize <= 0 {
		errors.Add(prefix+".max_request_size", "max request size must be positive", a.MaxRequestSize)
	}

	// Validate rate limiting
	if a.EnableRateLimit {
		if a.RateLimitRequests <= 0 {
			errors.Add(prefix+".rate_limit_requests", "rate limit requests must be positive", a.RateLimitRequests)
		}
		if a.RateLimitWindow <= 0 {
			errors.Add(prefix+".rate_limit_window", "rate limit window must be positive", a.RateLimitWindow)
		}
	}

	// Validate CORS origins
	for i, origin := range a.CORSAllowedOrigins {
		if origin != "*" && !isValidURL(origin) {
			errors.Add(fmt.Sprintf("%s.cors_allowed_origins[%d]", prefix, i), "invalid CORS origin", origin)
		}
	}

	// Validate TLS
	if a.TLSEnabled {
		if a.TLSCertFile == "" {
			errors.Add(prefix+".tls_cert_file", "TLS cert file required when TLS is enabled", a.TLSCertFile)
		} else if !fileExists(a.TLSCertFile) {
			errors.Add(prefix+".tls_cert_file", "TLS cert file does not exist", a.TLSCertFile)
		}

		if a.TLSKeyFile == "" {
			errors.Add(prefix+".tls_key_file", "TLS key file required when TLS is enabled", a.TLSKeyFile)
		} else if !fileExists(a.TLSKeyFile) {
			errors.Add(prefix+".tls_key_file", "TLS key file does not exist", a.TLSKeyFile)
		}
	}
}

// validate validates Database configuration
func (d *DatabaseConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate host
	if d.Host == "" {
		errors.Add(prefix+".host", "database host cannot be empty", d.Host)
	}

	// Validate port
	if d.Port < 1 || d.Port > 65535 {
		errors.Add(prefix+".port", "database port must be between 1 and 65535", d.Port)
	}

	// Validate database name
	if d.Database == "" {
		errors.Add(prefix+".database", "database name cannot be empty", d.Database)
	}

	// Validate username
	if d.Username == "" {
		errors.Add(prefix+".username", "database username cannot be empty", d.Username)
	}

	// Validate SSL mode
	validSSLModes := map[string]bool{
		"disable":     true,
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
	}
	if !validSSLModes[d.SSLMode] {
		errors.Add(prefix+".ssl_mode", "invalid SSL mode", d.SSLMode)
	}

	// Validate connection pool settings
	if d.MaxOpenConnections <= 0 {
		errors.Add(prefix+".max_open_connections", "max open connections must be positive", d.MaxOpenConnections)
	}
	if d.MaxIdleConnections < 0 {
		errors.Add(prefix+".max_idle_connections", "max idle connections cannot be negative", d.MaxIdleConnections)
	}
	if d.MaxIdleConnections > d.MaxOpenConnections {
		errors.Add(prefix+".max_idle_connections", "max idle connections cannot exceed max open connections", d.MaxIdleConnections)
	}

	// Validate timeouts
	if d.ConnectionLifetime <= 0 {
		errors.Add(prefix+".connection_lifetime", "connection lifetime must be positive", d.ConnectionLifetime)
	}
	if d.ConnectionTimeout <= 0 {
		errors.Add(prefix+".connection_timeout", "connection timeout must be positive", d.ConnectionTimeout)
	}

	// Validate migrations path
	if d.EnableMigrations && d.MigrationsPath == "" {
		errors.Add(prefix+".migrations_path", "migrations path required when migrations are enabled", d.MigrationsPath)
	}

	// Validate retry settings
	if d.RetryAttempts < 0 {
		errors.Add(prefix+".retry_attempts", "retry attempts cannot be negative", d.RetryAttempts)
	}
	if d.RetryDelay <= 0 {
		errors.Add(prefix+".retry_delay", "retry delay must be positive", d.RetryDelay)
	}
}

// validate validates Redis configuration
func (r *RedisConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate host
	if r.Host == "" {
		errors.Add(prefix+".host", "Redis host cannot be empty", r.Host)
	}

	// Validate port
	if r.Port < 1 || r.Port > 65535 {
		errors.Add(prefix+".port", "Redis port must be between 1 and 65535", r.Port)
	}

	// Validate database number
	if r.Database < 0 || r.Database > 15 {
		errors.Add(prefix+".database", "Redis database must be between 0 and 15", r.Database)
	}

	// Validate timeouts
	if r.DialTimeout <= 0 {
		errors.Add(prefix+".dial_timeout", "dial timeout must be positive", r.DialTimeout)
	}
	if r.ReadTimeout <= 0 {
		errors.Add(prefix+".read_timeout", "read timeout must be positive", r.ReadTimeout)
	}
	if r.WriteTimeout <= 0 {
		errors.Add(prefix+".write_timeout", "write timeout must be positive", r.WriteTimeout)
	}

	// Validate pool settings
	if r.PoolSize <= 0 {
		errors.Add(prefix+".pool_size", "pool size must be positive", r.PoolSize)
	}
	if r.MinIdleConnections < 0 {
		errors.Add(prefix+".min_idle_connections", "min idle connections cannot be negative", r.MinIdleConnections)
	}
	if r.MaxIdleConnections < 0 {
		errors.Add(prefix+".max_idle_connections", "max idle connections cannot be negative", r.MaxIdleConnections)
	}

	// Validate cluster mode
	if r.ClusterMode && len(r.ClusterNodes) == 0 {
		errors.Add(prefix+".cluster_nodes", "cluster nodes required when cluster mode is enabled", r.ClusterNodes)
	}

	// Validate cluster node addresses
	for i, node := range r.ClusterNodes {
		if !isValidHostPort(node) {
			errors.Add(fmt.Sprintf("%s.cluster_nodes[%d]", prefix, i), "invalid cluster node address", node)
		}
	}
}

// validate validates Kafka configuration
func (k *KafkaConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate brokers
	if len(k.Brokers) == 0 {
		errors.Add(prefix+".brokers", "at least one Kafka broker is required", k.Brokers)
	}

	for i, broker := range k.Brokers {
		if !isValidHostPort(broker) {
			errors.Add(fmt.Sprintf("%s.brokers[%d]", prefix, i), "invalid broker address", broker)
		}
	}

	// Validate topic
	if k.Topic == "" {
		errors.Add(prefix+".topic", "Kafka topic cannot be empty", k.Topic)
	}

	// Validate group ID
	if k.GroupID == "" {
		errors.Add(prefix+".group_id", "Kafka group ID cannot be empty", k.GroupID)
	}

	// Validate SASL
	if k.EnableSASL {
		if k.SASLUsername == "" {
			errors.Add(prefix+".sasl_username", "SASL username required when SASL is enabled", k.SASLUsername)
		}
		if k.SASLPassword == "" {
			errors.Add(prefix+".sasl_password", "SASL password required when SASL is enabled", k.SASLPassword)
		}

		validMechanisms := map[string]bool{
			"PLAIN":       true,
			"SCRAM-SHA-256": true,
			"SCRAM-SHA-512": true,
			"GSSAPI":      true,
		}
		if !validMechanisms[k.SASLMechanism] {
			errors.Add(prefix+".sasl_mechanism", "invalid SASL mechanism", k.SASLMechanism)
		}
	}

	// Validate timeouts
	if k.SessionTimeout <= 0 {
		errors.Add(prefix+".session_timeout", "session timeout must be positive", k.SessionTimeout)
	}
	if k.HeartbeatInterval <= 0 {
		errors.Add(prefix+".heartbeat_interval", "heartbeat interval must be positive", k.HeartbeatInterval)
	}
	if k.HeartbeatInterval >= k.SessionTimeout {
		errors.Add(prefix+".heartbeat_interval", "heartbeat interval must be less than session timeout", k.HeartbeatInterval)
	}
}

// validate validates Auth configuration
func (a *AuthConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate JWT secret
	if a.JWTSecret == "" {
		errors.Add(prefix+".jwt_secret", "JWT secret cannot be empty", "***")
	} else if len(a.JWTSecret) < 32 {
		errors.Add(prefix+".jwt_secret", "JWT secret should be at least 32 characters", "***")
	}

	// Validate expiration times
	if a.JWTExpiration <= 0 {
		errors.Add(prefix+".jwt_expiration", "JWT expiration must be positive", a.JWTExpiration)
	}
	if a.RefreshTokenExpiration <= 0 {
		errors.Add(prefix+".refresh_token_expiration", "refresh token expiration must be positive", a.RefreshTokenExpiration)
	}
	if a.RefreshTokenExpiration <= a.JWTExpiration {
		errors.Add(prefix+".refresh_token_expiration", "refresh token expiration should be greater than JWT expiration", a.RefreshTokenExpiration)
	}

	// Validate password requirements
	if a.PasswordMinLength < 8 {
		errors.Add(prefix+".password_min_length", "password minimum length should be at least 8", a.PasswordMinLength)
	}

	// Validate login attempt settings
	if a.MaxLoginAttempts <= 0 {
		errors.Add(prefix+".max_login_attempts", "max login attempts must be positive", a.MaxLoginAttempts)
	}
	if a.LoginAttemptWindow <= 0 {
		errors.Add(prefix+".login_attempt_window", "login attempt window must be positive", a.LoginAttemptWindow)
	}

	// Validate MFA
	if a.EnableMFA && a.MFAIssuer == "" {
		errors.Add(prefix+".mfa_issuer", "MFA issuer required when MFA is enabled", a.MFAIssuer)
	}

	// Validate OAuth
	if a.EnableOAuth {
		if len(a.OAuthProviders) == 0 {
			errors.Add(prefix+".oauth_providers", "OAuth providers required when OAuth is enabled", a.OAuthProviders)
		}

		for _, provider := range a.OAuthProviders {
			switch provider {
			case "google":
				if a.GoogleOAuth == nil {
					errors.Add(prefix+".google_oauth", "Google OAuth config required", nil)
				} else {
					a.GoogleOAuth.validate(prefix+".google_oauth", errors)
				}
			case "github":
				if a.GitHubOAuth == nil {
					errors.Add(prefix+".github_oauth", "GitHub OAuth config required", nil)
				} else {
					a.GitHubOAuth.validate(prefix+".github_oauth", errors)
				}
			default:
				errors.Add(prefix+".oauth_providers", "invalid OAuth provider", provider)
			}
		}
	}
}

// validate validates OAuth configuration
func (o *OAuthConfig) validate(prefix string, errors *ValidationErrors) {
	if o.ClientID == "" {
		errors.Add(prefix+".client_id", "OAuth client ID cannot be empty", o.ClientID)
	}
	if o.ClientSecret == "" {
		errors.Add(prefix+".client_secret", "OAuth client secret cannot be empty", "***")
	}
	if o.RedirectURL == "" {
		errors.Add(prefix+".redirect_url", "OAuth redirect URL cannot be empty", o.RedirectURL)
	} else if !isValidURL(o.RedirectURL) {
		errors.Add(prefix+".redirect_url", "invalid OAuth redirect URL", o.RedirectURL)
	}
}

// validate validates Webhook configuration
func (w *WebhookConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate host and port
	if w.Host == "" {
		errors.Add(prefix+".host", "webhook host cannot be empty", w.Host)
	}
	if w.Port < 1 || w.Port > 65535 {
		errors.Add(prefix+".port", "webhook port must be between 1 and 65535", w.Port)
	}

	// Validate payload size
	if w.MaxPayloadSize <= 0 {
		errors.Add(prefix+".max_payload_size", "max payload size must be positive", w.MaxPayloadSize)
	}

	// Validate timeout
	if w.Timeout <= 0 {
		errors.Add(prefix+".timeout", "webhook timeout must be positive", w.Timeout)
	}

	// Validate signature verification
	if w.EnableSignatureVerify {
		if w.SignatureSecret == "" {
			errors.Add(prefix+".signature_secret", "signature secret required when verification is enabled", "***")
		}
		if w.SignatureHeader == "" {
			errors.Add(prefix+".signature_header", "signature header required when verification is enabled", w.SignatureHeader)
		}

		validAlgorithms := map[string]bool{
			"sha1":   true,
			"sha256": true,
			"sha512": true,
		}
		if !validAlgorithms[w.SignatureAlgorithm] {
			errors.Add(prefix+".signature_algorithm", "invalid signature algorithm", w.SignatureAlgorithm)
		}
	}

	// Validate retry settings
	if w.RetryAttempts < 0 {
		errors.Add(prefix+".retry_attempts", "retry attempts cannot be negative", w.RetryAttempts)
	}
	if w.RetryDelay <= 0 {
		errors.Add(prefix+".retry_delay", "retry delay must be positive", w.RetryDelay)
	}
}

// validate validates Security configuration
func (s *SecurityConfig) validate(prefix string, errors *ValidationErrors) {
	// Validate encryption key
	if s.EncryptionKey == "" {
		errors.Add(prefix+".encryption_key", "encryption key cannot be empty", "***")
	} else if len(s.EncryptionKey) < 32 {
		errors.Add(prefix+".encryption_key", "encryption key should be at least 32 characters", "***")
	}

	// Validate hash cost
	if s.HashCost < 10 || s.HashCost > 15 {
		errors.Add(prefix+".hash_cost", "hash cost should be between 10 and 15", s.HashCost)
	}

	// Validate CSRF settings
	if s.EnableCSRF && s.CSRFTokenLength < 32 {
		errors.Add(prefix+".csrf_token_length", "CSRF token length should be at least 32", s.CSRFTokenLength)
	}

	// Validate HSTS settings
	if s.EnableHSTS && s.HSTSMaxAge <= 0 {
		errors.Add(prefix+".hsts_max_age", "HSTS max age must be positive when HSTS is enabled", s.HSTSMaxAge)
	}
}

// validate validates Metrics configuration
func (m *MetricsConfig) validate(prefix string, errors *ValidationErrors) {
	if !m.Enabled {
		return // Skip validation if metrics are disabled
	}

	// Validate host
	if m.Host == "" {
		errors.Add(prefix+".host", "metrics host cannot be empty", m.Host)
	}

	// Validate port
	if m.Port < 1 || m.Port > 65535 {
		errors.Add(prefix+".port", "metrics port must be between 1 and 65535", m.Port)
	}

	// Validate path
	if m.Path == "" {
		errors.Add(prefix+".path", "metrics path cannot be empty", m.Path)
	} else if !strings.HasPrefix(m.Path, "/") {
		errors.Add(prefix+".path", "metrics path must start with /", m.Path)
	}

	// Validate namespace and subsystem
	if m.Namespace == "" {
		errors.Add(prefix+".namespace", "metrics namespace cannot be empty", m.Namespace)
	}
}

// validate validates Storage configuration
func (s *StorageConfig) validate(prefix string, errors *ValidationErrors) {
	validProviders := map[string]bool{
		"local": true,
		"s3":    true,
		"gcs":   true,
	}

	if !validProviders[s.Provider] {
		errors.Add(prefix+".provider", "invalid storage provider", s.Provider)
	}

	// Validate provider-specific config
	switch s.Provider {
	case "local":
		if s.LocalPath == "" {
			errors.Add(prefix+".local_path", "local path required for local storage", s.LocalPath)
		}
	case "s3", "gcs":
		if s.S3Config == nil {
			errors.Add(prefix+".s3_config", "S3 config required for S3/GCS storage", nil)
		} else {
			s.S3Config.validate(prefix+".s3_config", errors)
		}
	}

	// Validate file size
	if s.MaxFileSize <= 0 {
		errors.Add(prefix+".max_file_size", "max file size must be positive", s.MaxFileSize)
	}
}

// validate validates S3 configuration
func (s *S3Config) validate(prefix string, errors *ValidationErrors) {
	if s.Bucket == "" {
		errors.Add(prefix+".bucket", "S3 bucket cannot be empty", s.Bucket)
	}
	if s.AccessKeyID == "" {
		errors.Add(prefix+".access_key_id", "S3 access key ID cannot be empty", s.AccessKeyID)
	}
	if s.SecretAccessKey == "" {
		errors.Add(prefix+".secret_access_key", "S3 secret access key cannot be empty", "***")
	}
	if s.Region == "" {
		errors.Add(prefix+".region", "S3 region cannot be empty", s.Region)
	}
}

// validate validates Email configuration
func (e *EmailConfig) validate(prefix string, errors *ValidationErrors) {
	validProviders := map[string]bool{
		"smtp":     true,
		"sendgrid": true,
	}

	if !validProviders[e.Provider] {
		errors.Add(prefix+".provider", "invalid email provider", e.Provider)
	}

	// Validate from email
	if e.FromEmail == "" {
		errors.Add(prefix+".from_email", "from email cannot be empty", e.FromEmail)
	} else if !isValidEmail(e.FromEmail) {
		errors.Add(prefix+".from_email", "invalid from email", e.FromEmail)
	}

	// Validate provider-specific config
	switch e.Provider {
	case "smtp":
		if e.SMTPConfig == nil {
			errors.Add(prefix+".smtp_config", "SMTP config required for SMTP provider", nil)
		} else {
			e.SMTPConfig.validate(prefix+".smtp_config", errors)
		}
	case "sendgrid":
		if e.SendGridConfig == nil {
			errors.Add(prefix+".sendgrid_config", "SendGrid config required for SendGrid provider", nil)
		} else {
			e.SendGridConfig.validate(prefix+".sendgrid_config", errors)
		}
	}
}

// validate validates SMTP configuration
func (s *SMTPConfig) validate(prefix string, errors *ValidationErrors) {
	if s.Host == "" {
		errors.Add(prefix+".host", "SMTP host cannot be empty", s.Host)
	}
	if s.Port < 1 || s.Port > 65535 {
		errors.Add(prefix+".port", "SMTP port must be between 1 and 65535", s.Port)
	}
	if s.Username == "" {
		errors.Add(prefix+".username", "SMTP username cannot be empty", s.Username)
	}
}

// validate validates SendGrid configuration
func (s *SendGridConfig) validate(prefix string, errors *ValidationErrors) {
	if s.APIKey == "" {
		errors.Add(prefix+".api_key", "SendGrid API key cannot be empty", "***")
	}
}

// validate validates Worker configuration
func (w *WorkerConfig) validate(prefix string, errors *ValidationErrors) {
	if !w.Enabled {
		return
	}

	if w.Concurrency <= 0 {
		errors.Add(prefix+".concurrency", "worker concurrency must be positive", w.Concurrency)
	}
	if w.QueueName == "" {
		errors.Add(prefix+".queue_name", "worker queue name cannot be empty", w.QueueName)
	}
	if w.PollInterval <= 0 {
		errors.Add(prefix+".poll_interval", "worker poll interval must be positive", w.PollInterval)
	}
	if w.JobTimeout <= 0 {
		errors.Add(prefix+".job_timeout", "worker job timeout must be positive", w.JobTimeout)
	}
}

// validate validates Limits configuration
func (l *LimitsConfig) validate(prefix string, errors *ValidationErrors) {
	if l.MaxWorkflowsPerTeam <= 0 {
		errors.Add(prefix+".max_workflows_per_team", "max workflows per team must be positive", l.MaxWorkflowsPerTeam)
	}
	if l.MaxNodesPerWorkflow <= 0 {
		errors.Add(prefix+".max_nodes_per_workflow", "max nodes per workflow must be positive", l.MaxNodesPerWorkflow)
	}
	if l.MaxExecutionsPerMinute <= 0 {
		errors.Add(prefix+".max_executions_per_minute", "max executions per minute must be positive", l.MaxExecutionsPerMinute)
	}
	if l.MaxExecutionTime <= 0 {
		errors.Add(prefix+".max_execution_time", "max execution time must be positive", l.MaxExecutionTime)
	}
	if l.MaxPayloadSize <= 0 {
		errors.Add(prefix+".max_payload_size", "max payload size must be positive", l.MaxPayloadSize)
	}
}

// Helper functions
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	return true // Simplified validation
}

func isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isValidEmail(email string) bool {
	return strings.Contains(email, "@") && len(email) > 3
}

func isValidHostPort(hostPort string) bool {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port >= 1 && port <= 65535
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func dirExists(dirname string) bool {
	info, err := os.Stat(dirname)
	return !os.IsNotExist(err) && info.IsDir()
}

func isAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}