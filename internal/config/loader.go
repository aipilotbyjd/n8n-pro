package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
)

// Continue loading functions from config.go

func loadAuthConfig() *AuthConfig {
	return &AuthConfig{
		JWTSecret:              getEnvString("JWT_SECRET", ""),
		JWTExpiration:          getEnvDuration("JWT_EXPIRATION", 24*time.Hour),
		RefreshTokenExpiration: getEnvDuration("REFRESH_TOKEN_EXPIRATION", 7*24*time.Hour),
		PasswordMinLength:      getEnvInt("PASSWORD_MIN_LENGTH", 8),
		PasswordRequireSymbols: getEnvBool("PASSWORD_REQUIRE_SYMBOLS", true),
		PasswordRequireNumbers: getEnvBool("PASSWORD_REQUIRE_NUMBERS", true),
		PasswordRequireUpper:   getEnvBool("PASSWORD_REQUIRE_UPPER", true),
		PasswordRequireLower:   getEnvBool("PASSWORD_REQUIRE_LOWER", true),
		MaxLoginAttempts:       getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		LoginAttemptWindow:     getEnvDuration("LOGIN_ATTEMPT_WINDOW", 15*time.Minute),
		EnableMFA:              getEnvBool("ENABLE_MFA", false),
		MFAIssuer:              getEnvString("MFA_ISSUER", "n8n-pro"),
		EnableOAuth:            getEnvBool("ENABLE_OAUTH", false),
		OAuthProviders:         getEnvStringSlice("OAUTH_PROVIDERS", []string{}),
		GoogleOAuth: &OAuthConfig{
			ClientID:     getEnvString("GOOGLE_OAUTH_CLIENT_ID", ""),
			ClientSecret: getEnvString("GOOGLE_OAUTH_CLIENT_SECRET", ""),
			RedirectURL:  getEnvString("GOOGLE_OAUTH_REDIRECT_URL", ""),
			Scopes:       getEnvStringSlice("GOOGLE_OAUTH_SCOPES", []string{"openid", "profile", "email"}),
		},
		GitHubOAuth: &OAuthConfig{
			ClientID:     getEnvString("GITHUB_OAUTH_CLIENT_ID", ""),
			ClientSecret: getEnvString("GITHUB_OAUTH_CLIENT_SECRET", ""),
			RedirectURL:  getEnvString("GITHUB_OAUTH_REDIRECT_URL", ""),
			Scopes:       getEnvStringSlice("GITHUB_OAUTH_SCOPES", []string{"user:email"}),
		},
		SessionCookieName:     getEnvString("SESSION_COOKIE_NAME", "n8n_session"),
		SessionCookieDomain:   getEnvString("SESSION_COOKIE_DOMAIN", ""),
		SessionCookieSecure:   getEnvBool("SESSION_COOKIE_SECURE", false),
		SessionCookieHTTPOnly: getEnvBool("SESSION_COOKIE_HTTP_ONLY", true),
	}
}

func loadWebhookConfig() *WebhookConfig {
	return &WebhookConfig{
		Host:                  getEnvString("WEBHOOK_HOST", "0.0.0.0"),
		Port:                  getEnvInt("WEBHOOK_PORT", 8081),
		Path:                  getEnvString("WEBHOOK_PATH", "/webhook"),
		MaxPayloadSize:        getEnvInt64("WEBHOOK_MAX_PAYLOAD_SIZE", 10*1024*1024),
		Timeout:               getEnvDuration("WEBHOOK_TIMEOUT", 30*time.Second),
		EnableSignatureVerify: getEnvBool("WEBHOOK_ENABLE_SIGNATURE_VERIFY", true),
		SignatureHeader:       getEnvString("WEBHOOK_SIGNATURE_HEADER", "X-Signature"),
		SignatureAlgorithm:    getEnvString("WEBHOOK_SIGNATURE_ALGORITHM", "sha256"),
		SignatureSecret:       getEnvString("WEBHOOK_SIGNATURE_SECRET", ""),
		RetryAttempts:         getEnvInt("WEBHOOK_RETRY_ATTEMPTS", 3),
		RetryDelay:            getEnvDuration("WEBHOOK_RETRY_DELAY", time.Second),
		EnableLogging:         getEnvBool("WEBHOOK_ENABLE_LOGGING", true),
		AllowedHosts:          getEnvStringSlice("WEBHOOK_ALLOWED_HOSTS", []string{}),
		BlockedHosts:          getEnvStringSlice("WEBHOOK_BLOCKED_HOSTS", []string{"localhost", "127.0.0.1", "0.0.0.0"}),
		EnableRateLimit:       getEnvBool("WEBHOOK_ENABLE_RATE_LIMIT", true),
		RateLimitRequests:     getEnvInt("WEBHOOK_RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:       getEnvDuration("WEBHOOK_RATE_LIMIT_WINDOW", time.Minute),
	}
}

func loadSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		Enabled:               getEnvBool("SCHEDULER_ENABLED", true),
		CheckInterval:         getEnvDuration("SCHEDULER_CHECK_INTERVAL", 30*time.Second),
		MaxConcurrentJobs:     getEnvInt("SCHEDULER_MAX_CONCURRENT_JOBS", 10),
		JobTimeout:            getEnvDuration("SCHEDULER_JOB_TIMEOUT", 5*time.Minute),
		EnableDistributedMode: getEnvBool("SCHEDULER_ENABLE_DISTRIBUTED_MODE", false),
		LockTimeout:           getEnvDuration("SCHEDULER_LOCK_TIMEOUT", 10*time.Minute),
		LockRefreshInterval:   getEnvDuration("SCHEDULER_LOCK_REFRESH_INTERVAL", 30*time.Second),
		CleanupInterval:       getEnvDuration("SCHEDULER_CLEANUP_INTERVAL", time.Hour),
		RetainCompletedJobs:   getEnvDuration("SCHEDULER_RETAIN_COMPLETED_JOBS", 24*time.Hour),
		RetainFailedJobs:      getEnvDuration("SCHEDULER_RETAIN_FAILED_JOBS", 7*24*time.Hour),
	}
}

func loadSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EncryptionKey:         getEnvString("ENCRYPTION_KEY", ""),
		HashCost:              getEnvInt("HASH_COST", 12),
		AllowedOrigins:        getEnvStringSlice("SECURITY_ALLOWED_ORIGINS", []string{}),
		TrustedProxies:        getEnvStringSlice("SECURITY_TRUSTED_PROXIES", []string{}),
		EnableCSRF:            getEnvBool("SECURITY_ENABLE_CSRF", true),
		CSRFTokenLength:       getEnvInt("SECURITY_CSRF_TOKEN_LENGTH", 32),
		EnableContentSecurity: getEnvBool("SECURITY_ENABLE_CONTENT_SECURITY", true),
		ContentSecurityPolicy: getEnvString("SECURITY_CONTENT_SECURITY_POLICY", "default-src 'self'"),
		EnableHSTS:            getEnvBool("SECURITY_ENABLE_HSTS", false),
		HSTSMaxAge:            getEnvInt("SECURITY_HSTS_MAX_AGE", 31536000),
		EnableXFrameOptions:   getEnvBool("SECURITY_ENABLE_X_FRAME_OPTIONS", true),
		XFrameOptions:         getEnvString("SECURITY_X_FRAME_OPTIONS", "DENY"),
		EnableXContentType:    getEnvBool("SECURITY_ENABLE_X_CONTENT_TYPE", true),
		EnableXSSProtection:   getEnvBool("SECURITY_ENABLE_XSS_PROTECTION", true),
		EnableClickjacking:    getEnvBool("SECURITY_ENABLE_CLICKJACKING", true),
	}
}

func loadMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled:     getEnvBool("METRICS_ENABLED", true),
		Host:        getEnvString("METRICS_HOST", "0.0.0.0"),
		Port:        getEnvInt("METRICS_PORT", 9090),
		Path:        getEnvString("METRICS_PATH", "/metrics"),
		Namespace:   getEnvString("METRICS_NAMESPACE", "n8n_pro"),
		Subsystem:   getEnvString("METRICS_SUBSYSTEM", ""),
		ServiceName: getEnvString("METRICS_SERVICE_NAME", "api"),
	}
}

func loadStorageConfig() *StorageConfig {
	return &StorageConfig{
		Provider:         getEnvString("STORAGE_PROVIDER", "local"),
		LocalPath:        getEnvString("STORAGE_LOCAL_PATH", "./storage"),
		MaxFileSize:      getEnvInt64("STORAGE_MAX_FILE_SIZE", 100*1024*1024),
		AllowedMimeTypes: getEnvStringSlice("STORAGE_ALLOWED_MIME_TYPES", []string{"application/json", "text/plain", "image/*"}),
		EnableEncryption: getEnvBool("STORAGE_ENABLE_ENCRYPTION", false),
		EncryptionKey:    getEnvString("STORAGE_ENCRYPTION_KEY", ""),
		CDNEnabled:       getEnvBool("STORAGE_CDN_ENABLED", false),
		CDNBaseURL:       getEnvString("STORAGE_CDN_BASE_URL", ""),
		S3Config: &S3Config{
			Endpoint:        getEnvString("S3_ENDPOINT", ""),
			Region:          getEnvString("S3_REGION", "us-east-1"),
			Bucket:          getEnvString("S3_BUCKET", ""),
			AccessKeyID:     getEnvString("S3_ACCESS_KEY_ID", ""),
			SecretAccessKey: getEnvString("S3_SECRET_ACCESS_KEY", ""),
			UseSSL:          getEnvBool("S3_USE_SSL", true),
			PathStyle:       getEnvBool("S3_PATH_STYLE", false),
		},
		Metadata: make(map[string]string),
	}
}

func loadEmailConfig() *EmailConfig {
	return &EmailConfig{
		Provider:      getEnvString("EMAIL_PROVIDER", "smtp"),
		FromEmail:     getEnvString("EMAIL_FROM_EMAIL", "noreply@example.com"),
		FromName:      getEnvString("EMAIL_FROM_NAME", "n8n Pro"),
		ReplyToEmail:  getEnvString("EMAIL_REPLY_TO_EMAIL", ""),
		TemplatesPath: getEnvString("EMAIL_TEMPLATES_PATH", "./templates/email"),
		EnableRetries: getEnvBool("EMAIL_ENABLE_RETRIES", true),
		MaxRetries:    getEnvInt("EMAIL_MAX_RETRIES", 3),
		RetryDelay:    getEnvDuration("EMAIL_RETRY_DELAY", 5*time.Second),
		SMTPConfig: &SMTPConfig{
			Host:     getEnvString("SMTP_HOST", "localhost"),
			Port:     getEnvInt("SMTP_PORT", 587),
			Username: getEnvString("SMTP_USERNAME", ""),
			Password: getEnvString("SMTP_PASSWORD", ""),
			UseTLS:   getEnvBool("SMTP_USE_TLS", true),
			UseSSL:   getEnvBool("SMTP_USE_SSL", false),
		},
		SendGridConfig: &SendGridConfig{
			APIKey: getEnvString("SENDGRID_API_KEY", ""),
		},
	}
}

func loadBillingConfig() *BillingConfig {
	return &BillingConfig{
		Provider:        getEnvString("BILLING_PROVIDER", "stripe"),
		EnableBilling:   getEnvBool("BILLING_ENABLED", false),
		TrialPeriodDays: getEnvInt("BILLING_TRIAL_PERIOD_DAYS", 14),
		GracePeriodDays: getEnvInt("BILLING_GRACE_PERIOD_DAYS", 7),
		WebhookSecret:   getEnvString("BILLING_WEBHOOK_SECRET", ""),
		StripeConfig: &StripeConfig{
			PublicKey:       getEnvString("STRIPE_PUBLIC_KEY", ""),
			SecretKey:       getEnvString("STRIPE_SECRET_KEY", ""),
			WebhookSecret:   getEnvString("STRIPE_WEBHOOK_SECRET", ""),
			DefaultCurrency: getEnvString("STRIPE_DEFAULT_CURRENCY", "usd"),
			EnableConnect:   getEnvBool("STRIPE_ENABLE_CONNECT", false),
		},
	}
}

func loadWorkerConfig() *WorkerConfig {
	return &WorkerConfig{
		Enabled:           getEnvBool("WORKER_ENABLED", true),
		Concurrency:       getEnvInt("WORKER_CONCURRENCY", 10),
		QueueName:         getEnvString("WORKER_QUEUE_NAME", "workflow-jobs"),
		PollInterval:      getEnvDuration("WORKER_POLL_INTERVAL", 5*time.Second),
		JobTimeout:        getEnvDuration("WORKER_JOB_TIMEOUT", 10*time.Minute),
		RetryAttempts:     getEnvInt("WORKER_RETRY_ATTEMPTS", 3),
		RetryDelay:        getEnvDuration("WORKER_RETRY_DELAY", 30*time.Second),
		EnableHealthCheck: getEnvBool("WORKER_ENABLE_HEALTH_CHECK", true),
		HealthCheckPort:   getEnvInt("WORKER_HEALTH_CHECK_PORT", 8082),
		ShutdownTimeout:   getEnvDuration("WORKER_SHUTDOWN_TIMEOUT", 30*time.Second),
	}
}

func loadSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		Enabled:           getEnvBool("SANDBOX_ENABLED", true),
		DefaultContext:    getEnvString("SANDBOX_DEFAULT_CONTEXT", "javascript"),
		MaxConcurrentJobs: getEnvInt("SANDBOX_MAX_CONCURRENT_JOBS", 5),
		JobTimeout:        getEnvDuration("SANDBOX_JOB_TIMEOUT", 5*time.Minute),
		MaxMemoryMB:       getEnvInt("SANDBOX_MAX_MEMORY_MB", 128),
		MaxCPUPercent:     getEnvInt("SANDBOX_MAX_CPU_PERCENT", 50),
		MaxDiskMB:         getEnvInt("SANDBOX_MAX_DISK_MB", 10),
		EnableNodeJS:      getEnvBool("SANDBOX_ENABLE_NODEJS", true),
		EnablePython:      getEnvBool("SANDBOX_ENABLE_PYTHON", true),
		EnableDocker:      getEnvBool("SANDBOX_ENABLE_DOCKER", false),
		WorkingDirectory:  getEnvString("SANDBOX_WORKING_DIRECTORY", "/tmp/n8n-sandbox"),
		AllowedPackages:   getEnvStringSlice("SANDBOX_ALLOWED_PACKAGES", []string{"lodash", "axios", "moment"}),
		BlockedPackages:   getEnvStringSlice("SANDBOX_BLOCKED_PACKAGES", []string{"fs", "child_process"}),
		NetworkPolicy:     getEnvString("SANDBOX_NETWORK_POLICY", "restricted"),
		AllowedDomains:    getEnvStringSlice("SANDBOX_ALLOWED_DOMAINS", []string{}),
		BlockedDomains:    getEnvStringSlice("SANDBOX_BLOCKED_DOMAINS", []string{"localhost", "127.0.0.1"}),
	}
}

func loadLimitsConfig() *LimitsConfig {
	return &LimitsConfig{
		MaxWorkflowsPerTeam:     getEnvInt("LIMITS_MAX_WORKFLOWS_PER_TEAM", 100),
		MaxNodesPerWorkflow:     getEnvInt("LIMITS_MAX_NODES_PER_WORKFLOW", 50),
		MaxExecutionsPerMinute:  getEnvInt("LIMITS_MAX_EXECUTIONS_PER_MINUTE", 60),
		MaxExecutionTime:        getEnvDuration("LIMITS_MAX_EXECUTION_TIME", 10*time.Minute),
		MaxPayloadSize:          getEnvInt64("LIMITS_MAX_PAYLOAD_SIZE", 50*1024*1024),
		MaxConcurrentExecutions: getEnvInt("LIMITS_MAX_CONCURRENT_EXECUTIONS", 10),
		MaxWebhooksPerWorkflow:  getEnvInt("LIMITS_MAX_WEBHOOKS_PER_WORKFLOW", 5),
		MaxTriggersPerWorkflow:  getEnvInt("LIMITS_MAX_TRIGGERS_PER_WORKFLOW", 5),
		MaxFileUploadSize:       getEnvInt64("LIMITS_MAX_FILE_UPLOAD_SIZE", 100*1024*1024),
		MaxStoragePerTeam:       getEnvInt64("LIMITS_MAX_STORAGE_PER_TEAM", 10*1024*1024*1024),
		MaxUsersPerTeam:         getEnvInt("LIMITS_MAX_USERS_PER_TEAM", 25),
		MaxTeamsPerUser:         getEnvInt("LIMITS_MAX_TEAMS_PER_USER", 5),
	}
}

// Validate validates the complete configuration
func (c *Config) Validate() error {
	errs := errors.NewErrorList()

	// Validate required fields
	if c.Database.Host == "" {
		errs.Add(errors.ValidationError(errors.CodeMissingField, "database host is required"))
	}
	if c.Database.Database == "" {
		errs.Add(errors.ValidationError(errors.CodeMissingField, "database name is required"))
	}
	if c.Auth.JWTSecret == "" && c.Environment == "production" {
		errs.Add(errors.ValidationError(errors.CodeMissingField, "JWT secret is required in production"))
	}
	if c.Security.EncryptionKey == "" && c.Environment == "production" {
		errs.Add(errors.ValidationError(errors.CodeMissingField, "encryption key is required in production"))
	}

	// Validate port ranges
	if c.API.Port < 1 || c.API.Port > 65535 {
		errs.Add(errors.ValidationError(errors.CodeValueOutOfRange, "API port must be between 1 and 65535"))
	}
	if c.Metrics.Port < 1 || c.Metrics.Port > 65535 {
		errs.Add(errors.ValidationError(errors.CodeValueOutOfRange, "metrics port must be between 1 and 65535"))
	}

	// Validate timeout values
	if c.API.ReadTimeout < 0 {
		errs.Add(errors.ValidationError(errors.CodeValueOutOfRange, "API read timeout cannot be negative"))
	}
	if c.API.WriteTimeout < 0 {
		errs.Add(errors.ValidationError(errors.CodeValueOutOfRange, "API write timeout cannot be negative"))
	}

	// Validate Kafka configuration
	if len(c.Kafka.Brokers) == 0 {
		errs.Add(errors.ValidationError(errors.CodeMissingField, "at least one Kafka broker is required"))
	}

	// Validate storage configuration
	if c.Storage.Provider == "s3" {
		if c.Storage.S3Config.Bucket == "" {
			errs.Add(errors.ValidationError(errors.CodeMissingField, "S3 bucket is required when using S3 storage"))
		}
		if c.Storage.S3Config.AccessKeyID == "" {
			errs.Add(errors.ValidationError(errors.CodeMissingField, "S3 access key ID is required when using S3 storage"))
		}
		if c.Storage.S3Config.SecretAccessKey == "" {
			errs.Add(errors.ValidationError(errors.CodeMissingField, "S3 secret access key is required when using S3 storage"))
		}
	}

	if errs.HasErrors() {
		return errs
	}

	return nil
}

// GetDSN returns the database connection string
func (c *Config) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host, c.Database.Port, c.Database.Username, c.Database.Password, c.Database.Database, c.Database.SSLMode)
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsTest returns true if running in test mode
func (c *Config) IsTest() bool {
	return c.Environment == "test"
}

// Helper functions for loading environment variables

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvInt32(key string, defaultValue int32) int32 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 32); err == nil {
			return int32(intValue)
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		// Try parsing as seconds if duration parsing fails
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// GetConfig returns the global configuration instance
var globalConfig *Config

func GetConfig() *Config {
	return globalConfig
}

func SetConfig(config *Config) {
	globalConfig = config
}

// MustLoad loads configuration and panics if there's an error
func MustLoad() *Config {
	config, err := Load()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	SetConfig(config)
	return config
}

// LoadFromFile loads configuration from a file (placeholder for future implementation)
func LoadFromFile(filename string) (*Config, error) {
	// This would implement loading from YAML/JSON configuration files
	// For now, we only support environment variables
	return Load()
}

// SaveToFile saves configuration to a file (placeholder for future implementation)
func (c *Config) SaveToFile(filename string) error {
	// This would implement saving configuration to YAML/JSON files
	// For now, this is a placeholder
	return fmt.Errorf("saving configuration to file is not implemented")
}

// Reload reloads configuration from environment variables
func Reload() (*Config, error) {
	return Load()
}

// Override allows overriding specific configuration values at runtime
func (c *Config) Override(overrides map[string]interface{}) error {
	// This would implement runtime configuration overrides
	// For now, this is a placeholder
	return fmt.Errorf("configuration override is not implemented")
}
