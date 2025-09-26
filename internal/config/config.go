// Package config provides production-grade application configuration management
package config

import (
	"time"
	
	pkgconfig "n8n-pro/pkg/config"
	"n8n-pro/pkg/logger"
)

// Config holds the complete application configuration
type Config struct {
	Environment string           `json:"environment" yaml:"environment"`
	Debug       bool             `json:"debug" yaml:"debug"`
	LogLevel    string           `json:"log_level" yaml:"log_level"`
	API         *APIConfig       `json:"api" yaml:"api"`
	Database    *DatabaseConfig  `json:"database" yaml:"database"`
	Redis       *RedisConfig     `json:"redis" yaml:"redis"`
	Kafka       *KafkaConfig     `json:"kafka" yaml:"kafka"`
	Auth        *AuthConfig      `json:"auth" yaml:"auth"`
	Webhook     *WebhookConfig   `json:"webhook" yaml:"webhook"`
	Scheduler   *SchedulerConfig `json:"scheduler" yaml:"scheduler"`
	Security    *SecurityConfig  `json:"security" yaml:"security"`
	Metrics     *MetricsConfig   `json:"metrics" yaml:"metrics"`
	Storage     *StorageConfig   `json:"storage" yaml:"storage"`
	Email       *EmailConfig     `json:"email" yaml:"email"`
	Billing     *BillingConfig   `json:"billing" yaml:"billing"`
	Worker      *WorkerConfig    `json:"worker" yaml:"worker"`
	Sandbox     *SandboxConfig   `json:"sandbox" yaml:"sandbox"`
	Limits      *LimitsConfig    `json:"limits" yaml:"limits"`
}

// APIConfig holds API server configuration
type APIConfig struct {
	Host                 string        `json:"host" yaml:"host"`
	Port                 int           `json:"port" yaml:"port"`
	ReadTimeout          time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout         time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout          time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	MaxRequestSize       int64         `json:"max_request_size" yaml:"max_request_size"`
	EnableCORS           bool          `json:"enable_cors" yaml:"enable_cors"`
	CORSAllowedOrigins   []string      `json:"cors_allowed_origins" yaml:"cors_allowed_origins"`
	CORSAllowedMethods   []string      `json:"cors_allowed_methods" yaml:"cors_allowed_methods"`
	CORSAllowedHeaders   []string      `json:"cors_allowed_headers" yaml:"cors_allowed_headers"`
	EnableRateLimit      bool          `json:"enable_rate_limit" yaml:"enable_rate_limit"`
	RateLimitRequests    int           `json:"rate_limit_requests" yaml:"rate_limit_requests"`
	RateLimitWindow      time.Duration `json:"rate_limit_window" yaml:"rate_limit_window"`
	EnableGzip           bool          `json:"enable_gzip" yaml:"enable_gzip"`
	EnableRecovery       bool          `json:"enable_recovery" yaml:"enable_recovery"`
	EnableRequestLogging bool          `json:"enable_request_logging" yaml:"enable_request_logging"`
	TLSEnabled           bool          `json:"tls_enabled" yaml:"tls_enabled"`
	TLSCertFile          string        `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile           string        `json:"tls_key_file" yaml:"tls_key_file"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host               string        `json:"host" yaml:"host"`
	Port               int           `json:"port" yaml:"port"`
	Database           string        `json:"database" yaml:"database"`
	Username           string        `json:"username" yaml:"username"`
	Password           string        `json:"-" yaml:"-"` // Hidden from JSON/YAML output
	SSLMode            string        `json:"ssl_mode" yaml:"ssl_mode"`
	MaxOpenConnections int           `json:"max_open_connections" yaml:"max_open_connections"`
	MaxIdleConnections int           `json:"max_idle_connections" yaml:"max_idle_connections"`
	ConnectionLifetime time.Duration `json:"connection_lifetime" yaml:"connection_lifetime"`
	ConnectionTimeout  time.Duration `json:"connection_timeout" yaml:"connection_timeout"`
	EnableMigrations   bool          `json:"enable_migrations" yaml:"enable_migrations"`
	MigrationsPath     string        `json:"migrations_path" yaml:"migrations_path"`
	EnableQueryLogging bool          `json:"enable_query_logging" yaml:"enable_query_logging"`
	SlowQueryThreshold time.Duration `json:"slow_query_threshold" yaml:"slow_query_threshold"`
	RetryAttempts      int           `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay" yaml:"retry_delay"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host               string        `json:"host" yaml:"host"`
	Port               int           `json:"port" yaml:"port"`
	Password           string        `json:"-" yaml:"-"`
	Database           int           `json:"database" yaml:"database"`
	MaxRetries         int           `json:"max_retries" yaml:"max_retries"`
	MinRetryBackoff    time.Duration `json:"min_retry_backoff" yaml:"min_retry_backoff"`
	MaxRetryBackoff    time.Duration `json:"max_retry_backoff" yaml:"max_retry_backoff"`
	DialTimeout        time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout        time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout       time.Duration `json:"write_timeout" yaml:"write_timeout"`
	PoolSize           int           `json:"pool_size" yaml:"pool_size"`
	MinIdleConnections int           `json:"min_idle_connections" yaml:"min_idle_connections"`
	MaxIdleConnections int           `json:"max_idle_connections" yaml:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
	TLSEnabled         bool          `json:"tls_enabled" yaml:"tls_enabled"`
	ClusterMode        bool          `json:"cluster_mode" yaml:"cluster_mode"`
	ClusterNodes       []string      `json:"cluster_nodes" yaml:"cluster_nodes"`
}

// KafkaConfig holds Kafka configuration
type KafkaConfig struct {
	Brokers                 []string      `json:"brokers" yaml:"brokers"`
	Topic                   string        `json:"topic" yaml:"topic"`
	GroupID                 string        `json:"group_id" yaml:"group_id"`
	ClientID                string        `json:"client_id" yaml:"client_id"`
	Version                 string        `json:"version" yaml:"version"`
	EnableSASL              bool          `json:"enable_sasl" yaml:"enable_sasl"`
	SASLMechanism           string        `json:"sasl_mechanism" yaml:"sasl_mechanism"`
	SASLUsername            string        `json:"sasl_username" yaml:"sasl_username"`
	SASLPassword            string        `json:"-" yaml:"-"`
	EnableTLS               bool          `json:"enable_tls" yaml:"enable_tls"`
	TLSInsecureSkipVerify   bool          `json:"tls_insecure_skip_verify" yaml:"tls_insecure_skip_verify"`
	ProducerRetryMax        int           `json:"producer_retry_max" yaml:"producer_retry_max"`
	ProducerReturnSuccesses bool          `json:"producer_return_successes" yaml:"producer_return_successes"`
	ProducerFlushFrequency  time.Duration `json:"producer_flush_frequency" yaml:"producer_flush_frequency"`
	ConsumerRetryBackoff    time.Duration `json:"consumer_retry_backoff" yaml:"consumer_retry_backoff"`
	ConsumerFetchMin        int32         `json:"consumer_fetch_min" yaml:"consumer_fetch_min"`
	ConsumerFetchDefault    int32         `json:"consumer_fetch_default" yaml:"consumer_fetch_default"`
	ConsumerMaxWaitTime     time.Duration `json:"consumer_max_wait_time" yaml:"consumer_max_wait_time"`
	SessionTimeout          time.Duration `json:"session_timeout" yaml:"session_timeout"`
	HeartbeatInterval       time.Duration `json:"heartbeat_interval" yaml:"heartbeat_interval"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTSecret              string        `json:"-" yaml:"-"`
	JWTExpiration          time.Duration `json:"jwt_expiration" yaml:"jwt_expiration"`
	RefreshTokenExpiration time.Duration `json:"refresh_token_expiration" yaml:"refresh_token_expiration"`
	PasswordMinLength      int           `json:"password_min_length" yaml:"password_min_length"`
	PasswordRequireSymbols bool          `json:"password_require_symbols" yaml:"password_require_symbols"`
	PasswordRequireNumbers bool          `json:"password_require_numbers" yaml:"password_require_numbers"`
	PasswordRequireUpper   bool          `json:"password_require_upper" yaml:"password_require_upper"`
	PasswordRequireLower   bool          `json:"password_require_lower" yaml:"password_require_lower"`
	MaxLoginAttempts       int           `json:"max_login_attempts" yaml:"max_login_attempts"`
	LoginAttemptWindow     time.Duration `json:"login_attempt_window" yaml:"login_attempt_window"`
	EnableMFA              bool          `json:"enable_mfa" yaml:"enable_mfa"`
	MFAIssuer              string        `json:"mfa_issuer" yaml:"mfa_issuer"`
	EnableOAuth            bool          `json:"enable_oauth" yaml:"enable_oauth"`
	OAuthProviders         []string      `json:"oauth_providers" yaml:"oauth_providers"`
	GoogleOAuth            *OAuthConfig  `json:"google_oauth" yaml:"google_oauth"`
	GitHubOAuth            *OAuthConfig  `json:"github_oauth" yaml:"github_oauth"`
	SessionCookieName      string        `json:"session_cookie_name" yaml:"session_cookie_name"`
	SessionCookieDomain    string        `json:"session_cookie_domain" yaml:"session_cookie_domain"`
	SessionCookieSecure    bool          `json:"session_cookie_secure" yaml:"session_cookie_secure"`
	SessionCookieHTTPOnly  bool          `json:"session_cookie_http_only" yaml:"session_cookie_http_only"`
}

// OAuthConfig holds OAuth provider configuration
type OAuthConfig struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"-" yaml:"-"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

// WebhookConfig holds webhook service configuration
type WebhookConfig struct {
	Host                  string        `json:"host" yaml:"host"`
	Port                  int           `json:"port" yaml:"port"`
	Path                  string        `json:"path" yaml:"path"`
	MaxPayloadSize        int64         `json:"max_payload_size" yaml:"max_payload_size"`
	Timeout               time.Duration `json:"timeout" yaml:"timeout"`
	EnableSignatureVerify bool          `json:"enable_signature_verify" yaml:"enable_signature_verify"`
	SignatureHeader       string        `json:"signature_header" yaml:"signature_header"`
	SignatureAlgorithm    string        `json:"signature_algorithm" yaml:"signature_algorithm"`
	SignatureSecret       string        `json:"-" yaml:"-"` // Hidden from output for security
	RetryAttempts         int           `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay            time.Duration `json:"retry_delay" yaml:"retry_delay"`
	EnableLogging         bool          `json:"enable_logging" yaml:"enable_logging"`
	AllowedHosts          []string      `json:"allowed_hosts" yaml:"allowed_hosts"`
	BlockedHosts          []string      `json:"blocked_hosts" yaml:"blocked_hosts"`
	EnableRateLimit       bool          `json:"enable_rate_limit" yaml:"enable_rate_limit"`
	RateLimitRequests     int           `json:"rate_limit_requests" yaml:"rate_limit_requests"`
	RateLimitWindow       time.Duration `json:"rate_limit_window" yaml:"rate_limit_window"`
}

// SchedulerConfig holds scheduler service configuration
type SchedulerConfig struct {
	Enabled               bool          `json:"enabled" yaml:"enabled"`
	CheckInterval         time.Duration `json:"check_interval" yaml:"check_interval"`
	MaxConcurrentJobs     int           `json:"max_concurrent_jobs" yaml:"max_concurrent_jobs"`
	JobTimeout            time.Duration `json:"job_timeout" yaml:"job_timeout"`
	EnableDistributedMode bool          `json:"enable_distributed_mode" yaml:"enable_distributed_mode"`
	LockTimeout           time.Duration `json:"lock_timeout" yaml:"lock_timeout"`
	LockRefreshInterval   time.Duration `json:"lock_refresh_interval" yaml:"lock_refresh_interval"`
	CleanupInterval       time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	RetainCompletedJobs   time.Duration `json:"retain_completed_jobs" yaml:"retain_completed_jobs"`
	RetainFailedJobs      time.Duration `json:"retain_failed_jobs" yaml:"retain_failed_jobs"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	EncryptionKey         string   `json:"-" yaml:"-"`
	HashCost              int      `json:"hash_cost" yaml:"hash_cost"`
	AllowedOrigins        []string `json:"allowed_origins" yaml:"allowed_origins"`
	TrustedProxies        []string `json:"trusted_proxies" yaml:"trusted_proxies"`
	EnableCSRF            bool     `json:"enable_csrf" yaml:"enable_csrf"`
	CSRFTokenLength       int      `json:"csrf_token_length" yaml:"csrf_token_length"`
	EnableContentSecurity bool     `json:"enable_content_security" yaml:"enable_content_security"`
	ContentSecurityPolicy string   `json:"content_security_policy" yaml:"content_security_policy"`
	EnableHSTS            bool     `json:"enable_hsts" yaml:"enable_hsts"`
	HSTSMaxAge            int      `json:"hsts_max_age" yaml:"hsts_max_age"`
	EnableXFrameOptions   bool     `json:"enable_x_frame_options" yaml:"enable_x_frame_options"`
	XFrameOptions         string   `json:"x_frame_options" yaml:"x_frame_options"`
	EnableXContentType    bool     `json:"enable_x_content_type" yaml:"enable_x_content_type"`
	EnableXSSProtection   bool     `json:"enable_xss_protection" yaml:"enable_xss_protection"`
	EnableClickjacking    bool     `json:"enable_clickjacking" yaml:"enable_clickjacking"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	Host        string `json:"host" yaml:"host"`
	Port        int    `json:"port" yaml:"port"`
	Path        string `json:"path" yaml:"path"`
	Namespace   string `json:"namespace" yaml:"namespace"`
	Subsystem   string `json:"subsystem" yaml:"subsystem"`
	ServiceName string `json:"service_name" yaml:"service_name"`
}

// StorageConfig holds file storage configuration
type StorageConfig struct {
	Provider         string            `json:"provider" yaml:"provider"`
	LocalPath        string            `json:"local_path" yaml:"local_path"`
	S3Config         *S3Config         `json:"s3_config" yaml:"s3_config"`
	MaxFileSize      int64             `json:"max_file_size" yaml:"max_file_size"`
	AllowedMimeTypes []string          `json:"allowed_mime_types" yaml:"allowed_mime_types"`
	EnableEncryption bool              `json:"enable_encryption" yaml:"enable_encryption"`
	EncryptionKey    string            `json:"-" yaml:"-"`
	CDNEnabled       bool              `json:"cdn_enabled" yaml:"cdn_enabled"`
	CDNBaseURL       string            `json:"cdn_base_url" yaml:"cdn_base_url"`
	Metadata         map[string]string `json:"metadata" yaml:"metadata"`
}

// S3Config holds S3-compatible storage configuration
type S3Config struct {
	Endpoint        string `json:"endpoint" yaml:"endpoint"`
	Region          string `json:"region" yaml:"region"`
	Bucket          string `json:"bucket" yaml:"bucket"`
	AccessKeyID     string `json:"access_key_id" yaml:"access_key_id"`
	SecretAccessKey string `json:"-" yaml:"-"`
	UseSSL          bool   `json:"use_ssl" yaml:"use_ssl"`
	PathStyle       bool   `json:"path_style" yaml:"path_style"`
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	Provider       string          `json:"provider" yaml:"provider"`
	SMTPConfig     *SMTPConfig     `json:"smtp_config" yaml:"smtp_config"`
	SendGridConfig *SendGridConfig `json:"sendgrid_config" yaml:"sendgrid_config"`
	FromEmail      string          `json:"from_email" yaml:"from_email"`
	FromName       string          `json:"from_name" yaml:"from_name"`
	ReplyToEmail   string          `json:"reply_to_email" yaml:"reply_to_email"`
	TemplatesPath  string          `json:"templates_path" yaml:"templates_path"`
	EnableRetries  bool            `json:"enable_retries" yaml:"enable_retries"`
	MaxRetries     int             `json:"max_retries" yaml:"max_retries"`
	RetryDelay     time.Duration   `json:"retry_delay" yaml:"retry_delay"`
}

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"-" yaml:"-"`
	UseTLS   bool   `json:"use_tls" yaml:"use_tls"`
	UseSSL   bool   `json:"use_ssl" yaml:"use_ssl"`
}

// SendGridConfig holds SendGrid configuration
type SendGridConfig struct {
	APIKey string `json:"-" yaml:"-"`
}

// BillingConfig holds billing and subscription configuration
type BillingConfig struct {
	Provider        string        `json:"provider" yaml:"provider"`
	StripeConfig    *StripeConfig `json:"stripe_config" yaml:"stripe_config"`
	EnableBilling   bool          `json:"enable_billing" yaml:"enable_billing"`
	TrialPeriodDays int           `json:"trial_period_days" yaml:"trial_period_days"`
	GracePeriodDays int           `json:"grace_period_days" yaml:"grace_period_days"`
	WebhookSecret   string        `json:"-" yaml:"-"`
}

// StripeConfig holds Stripe configuration
type StripeConfig struct {
	PublicKey       string `json:"public_key" yaml:"public_key"`
	SecretKey       string `json:"-" yaml:"-"`
	WebhookSecret   string `json:"-" yaml:"-"`
	DefaultCurrency string `json:"default_currency" yaml:"default_currency"`
	EnableConnect   bool   `json:"enable_connect" yaml:"enable_connect"`
}

// WorkerConfig holds worker service configuration
type WorkerConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	Concurrency       int           `json:"concurrency" yaml:"concurrency"`
	QueueName         string        `json:"queue_name" yaml:"queue_name"`
	PollInterval      time.Duration `json:"poll_interval" yaml:"poll_interval"`
	JobTimeout        time.Duration `json:"job_timeout" yaml:"job_timeout"`
	RetryAttempts     int           `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay        time.Duration `json:"retry_delay" yaml:"retry_delay"`
	EnableHealthCheck bool          `json:"enable_health_check" yaml:"enable_health_check"`
	HealthCheckPort   int           `json:"health_check_port" yaml:"health_check_port"`
	ShutdownTimeout   time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout"`
}

// SandboxConfig holds sandbox execution configuration
type SandboxConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	DefaultContext    string        `json:"default_context" yaml:"default_context"`
	MaxConcurrentJobs int           `json:"max_concurrent_jobs" yaml:"max_concurrent_jobs"`
	JobTimeout        time.Duration `json:"job_timeout" yaml:"job_timeout"`
	MaxMemoryMB       int           `json:"max_memory_mb" yaml:"max_memory_mb"`
	MaxCPUPercent     int           `json:"max_cpu_percent" yaml:"max_cpu_percent"`
	MaxDiskMB         int           `json:"max_disk_mb" yaml:"max_disk_mb"`
	EnableNodeJS      bool          `json:"enable_nodejs" yaml:"enable_nodejs"`
	EnablePython      bool          `json:"enable_python" yaml:"enable_python"`
	EnableDocker      bool          `json:"enable_docker" yaml:"enable_docker"`
	WorkingDirectory  string        `json:"working_directory" yaml:"working_directory"`
	AllowedPackages   []string      `json:"allowed_packages" yaml:"allowed_packages"`
	BlockedPackages   []string      `json:"blocked_packages" yaml:"blocked_packages"`
	NetworkPolicy     string        `json:"network_policy" yaml:"network_policy"`
	AllowedDomains    []string      `json:"allowed_domains" yaml:"allowed_domains"`
	BlockedDomains    []string      `json:"blocked_domains" yaml:"blocked_domains"`
}

// LimitsConfig holds various system limits
type LimitsConfig struct {
	MaxWorkflowsPerTeam     int           `json:"max_workflows_per_team" yaml:"max_workflows_per_team"`
	MaxNodesPerWorkflow     int           `json:"max_nodes_per_workflow" yaml:"max_nodes_per_workflow"`
	MaxExecutionsPerMinute  int           `json:"max_executions_per_minute" yaml:"max_executions_per_minute"`
	MaxExecutionTime        time.Duration `json:"max_execution_time" yaml:"max_execution_time"`
	MaxPayloadSize          int64         `json:"max_payload_size" yaml:"max_payload_size"`
	MaxConcurrentExecutions int           `json:"max_concurrent_executions" yaml:"max_concurrent_executions"`
	MaxWebhooksPerWorkflow  int           `json:"max_webhooks_per_workflow" yaml:"max_webhooks_per_workflow"`
	MaxTriggersPerWorkflow  int           `json:"max_triggers_per_workflow" yaml:"max_triggers_per_workflow"`
	MaxFileUploadSize       int64         `json:"max_file_upload_size" yaml:"max_file_upload_size"`
	MaxStoragePerTeam       int64         `json:"max_storage_per_team" yaml:"max_storage_per_team"`
	MaxUsersPerTeam         int           `json:"max_users_per_team" yaml:"max_users_per_team"`
	MaxTeamsPerUser         int           `json:"max_teams_per_user" yaml:"max_teams_per_user"`
}

// Load loads the configuration from environment variables
func Load() (*Config, error) {
	// Create a simple logger for the environment loader
	logger := logger.New("config")
	
	// Load environment files before reading configuration
	envLoader := pkgconfig.NewEnvironmentLoader(logger)
	if err := envLoader.LoadEnvironmentWithDefaults(); err != nil {
		// Log warning but don't fail - environment files are optional
		logger.Warn("Failed to load environment files", "error", err)
	}
	
	config := &Config{
		Environment: getEnvString("ENVIRONMENT", "development"),
		Debug:       getEnvBool("DEBUG", false),
		LogLevel:    getEnvString("LOG_LEVEL", "info"),
		API:         loadAPIConfig(),
		Database:    loadDatabaseConfig(),
		Redis:       loadRedisConfig(),
		Kafka:       loadKafkaConfig(),
		Auth:        loadAuthConfig(),
		Webhook:     loadWebhookConfig(),
		Scheduler:   loadSchedulerConfig(),
		Security:    loadSecurityConfig(),
		Metrics:     loadMetricsConfig(),
		Storage:     loadStorageConfig(),
		Email:       loadEmailConfig(),
		Billing:     loadBillingConfig(),
		Worker:      loadWorkerConfig(),
		Sandbox:     loadSandboxConfig(),
		Limits:      loadLimitsConfig(),
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func loadAPIConfig() *APIConfig {
	return &APIConfig{
		Host:                 getEnvString("API_HOST", "0.0.0.0"),
		Port:                 getEnvInt("API_PORT", 8080),
		ReadTimeout:          getEnvDuration("API_READ_TIMEOUT", 30*time.Second),
		WriteTimeout:         getEnvDuration("API_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:          getEnvDuration("API_IDLE_TIMEOUT", 120*time.Second),
		MaxRequestSize:       getEnvInt64("API_MAX_REQUEST_SIZE", 10*1024*1024), // 10MB
		EnableCORS:           getEnvBool("API_ENABLE_CORS", true),
		CORSAllowedOrigins:   getEnvStringSlice("API_CORS_ALLOWED_ORIGINS", []string{"*"}),
		CORSAllowedMethods:   getEnvStringSlice("API_CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		CORSAllowedHeaders:   getEnvStringSlice("API_CORS_ALLOWED_HEADERS", []string{"*"}),
		EnableRateLimit:      getEnvBool("API_ENABLE_RATE_LIMIT", true),
		RateLimitRequests:    getEnvInt("API_RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:      getEnvDuration("API_RATE_LIMIT_WINDOW", time.Hour),
		EnableGzip:           getEnvBool("API_ENABLE_GZIP", true),
		EnableRecovery:       getEnvBool("API_ENABLE_RECOVERY", true),
		EnableRequestLogging: getEnvBool("API_ENABLE_REQUEST_LOGGING", true),
		TLSEnabled:           getEnvBool("API_TLS_ENABLED", false),
		TLSCertFile:          getEnvString("API_TLS_CERT_FILE", ""),
		TLSKeyFile:           getEnvString("API_TLS_KEY_FILE", ""),
	}
}

func loadDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Host:               getEnvString("DB_HOST", "localhost"),
		Port:               getEnvInt("DB_PORT", 5432),
		Database:           getEnvString("DB_NAME", "n8n_pro"),
		Username:           getEnvString("DB_USER", "postgres"),
		Password:           getEnvString("DB_PASSWORD", ""),
		SSLMode:            getEnvString("DB_SSL_MODE", "disable"),
		MaxOpenConnections: getEnvInt("DB_MAX_OPEN_CONNECTIONS", 25),
		MaxIdleConnections: getEnvInt("DB_MAX_IDLE_CONNECTIONS", 5),
		ConnectionLifetime: getEnvDuration("DB_CONNECTION_LIFETIME", 5*time.Minute),
		ConnectionTimeout:  getEnvDuration("DB_CONNECTION_TIMEOUT", 10*time.Second),
		EnableMigrations:   getEnvBool("DB_ENABLE_MIGRATIONS", true),
		MigrationsPath:     getEnvString("DB_MIGRATIONS_PATH", "migrations"),
		EnableQueryLogging: getEnvBool("DB_ENABLE_QUERY_LOGGING", false),
		SlowQueryThreshold: getEnvDuration("DB_SLOW_QUERY_THRESHOLD", 2*time.Second),
		RetryAttempts:      getEnvInt("DB_RETRY_ATTEMPTS", 3),
		RetryDelay:         getEnvDuration("DB_RETRY_DELAY", time.Second),
	}
}

func loadRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host:               getEnvString("REDIS_HOST", "localhost"),
		Port:               getEnvInt("REDIS_PORT", 6379),
		Password:           getEnvString("REDIS_PASSWORD", ""),
		Database:           getEnvInt("REDIS_DATABASE", 0),
		MaxRetries:         getEnvInt("REDIS_MAX_RETRIES", 3),
		MinRetryBackoff:    getEnvDuration("REDIS_MIN_RETRY_BACKOFF", 8*time.Millisecond),
		MaxRetryBackoff:    getEnvDuration("REDIS_MAX_RETRY_BACKOFF", 512*time.Millisecond),
		DialTimeout:        getEnvDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
		ReadTimeout:        getEnvDuration("REDIS_READ_TIMEOUT", 3*time.Second),
		WriteTimeout:       getEnvDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
		PoolSize:           getEnvInt("REDIS_POOL_SIZE", 10),
		MinIdleConnections: getEnvInt("REDIS_MIN_IDLE_CONNECTIONS", 5),
		MaxIdleConnections: getEnvInt("REDIS_MAX_IDLE_CONNECTIONS", 10),
		ConnMaxLifetime:    getEnvDuration("REDIS_CONN_MAX_LIFETIME", 30*time.Minute),
		TLSEnabled:         getEnvBool("REDIS_TLS_ENABLED", false),
		ClusterMode:        getEnvBool("REDIS_CLUSTER_MODE", false),
		ClusterNodes:       getEnvStringSlice("REDIS_CLUSTER_NODES", []string{}),
	}
}

func loadKafkaConfig() *KafkaConfig {
	return &KafkaConfig{
		Brokers:                 getEnvStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		Topic:                   getEnvString("KAFKA_TOPIC", "n8n-workflows"),
		GroupID:                 getEnvString("KAFKA_GROUP_ID", "n8n-workers"),
		ClientID:                getEnvString("KAFKA_CLIENT_ID", "n8n-pro"),
		Version:                 getEnvString("KAFKA_VERSION", "2.8.0"),
		EnableSASL:              getEnvBool("KAFKA_ENABLE_SASL", false),
		SASLMechanism:           getEnvString("KAFKA_SASL_MECHANISM", "PLAIN"),
		SASLUsername:            getEnvString("KAFKA_SASL_USERNAME", ""),
		SASLPassword:            getEnvString("KAFKA_SASL_PASSWORD", ""),
		EnableTLS:               getEnvBool("KAFKA_ENABLE_TLS", false),
		TLSInsecureSkipVerify:   getEnvBool("KAFKA_TLS_INSECURE_SKIP_VERIFY", false),
		ProducerRetryMax:        getEnvInt("KAFKA_PRODUCER_RETRY_MAX", 3),
		ProducerReturnSuccesses: getEnvBool("KAFKA_PRODUCER_RETURN_SUCCESSES", true),
		ProducerFlushFrequency:  getEnvDuration("KAFKA_PRODUCER_FLUSH_FREQUENCY", 500*time.Millisecond),
		ConsumerRetryBackoff:    getEnvDuration("KAFKA_CONSUMER_RETRY_BACKOFF", 2*time.Second),
		ConsumerFetchMin:        getEnvInt32("KAFKA_CONSUMER_FETCH_MIN", 1),
		ConsumerFetchDefault:    getEnvInt32("KAFKA_CONSUMER_FETCH_DEFAULT", 1024*1024),
		ConsumerMaxWaitTime:     getEnvDuration("KAFKA_CONSUMER_MAX_WAIT_TIME", 250*time.Millisecond),
		SessionTimeout:          getEnvDuration("KAFKA_SESSION_TIMEOUT", 10*time.Second),
		HeartbeatInterval:       getEnvDuration("KAFKA_HEARTBEAT_INTERVAL", 3*time.Second),
	}
}
