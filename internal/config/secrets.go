package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// SecretsManager handles secure storage and retrieval of secrets
type SecretsManager interface {
	GetSecret(ctx context.Context, key string) (string, error)
	SetSecret(ctx context.Context, key, value string) error
	DeleteSecret(ctx context.Context, key string) error
	ListSecrets(ctx context.Context) ([]string, error)
	RotateSecret(ctx context.Context, key string, newValue string) error
}

// SecretStore represents different secret storage backends
type SecretStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]string, error)
}

// LocalSecretsManager implements SecretsManager using local encrypted storage
type LocalSecretsManager struct {
	store      SecretStore
	encryptKey []byte
}

// NewLocalSecretsManager creates a new local secrets manager
func NewLocalSecretsManager(masterKey string) (*LocalSecretsManager, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master key must be at least 32 characters")
	}

	// Derive encryption key from master key
	hash := sha256.Sum256([]byte(masterKey))
	
	store := &FileSecretStore{
		basePath: getSecretStorePath(),
	}

	return &LocalSecretsManager{
		store:      store,
		encryptKey: hash[:],
	}, nil
}

// GetSecret retrieves and decrypts a secret
func (lsm *LocalSecretsManager) GetSecret(ctx context.Context, key string) (string, error) {
	encryptedData, err := lsm.store.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("failed to get encrypted secret: %w", err)
	}

	decryptedData, err := lsm.decrypt(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return string(decryptedData), nil
}

// SetSecret encrypts and stores a secret
func (lsm *LocalSecretsManager) SetSecret(ctx context.Context, key, value string) error {
	encryptedData, err := lsm.encrypt([]byte(value))
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return lsm.store.Set(ctx, key, encryptedData)
}

// DeleteSecret removes a secret
func (lsm *LocalSecretsManager) DeleteSecret(ctx context.Context, key string) error {
	return lsm.store.Delete(ctx, key)
}

// ListSecrets lists all secret keys
func (lsm *LocalSecretsManager) ListSecrets(ctx context.Context) ([]string, error) {
	return lsm.store.List(ctx)
}

// RotateSecret updates a secret with a new value
func (lsm *LocalSecretsManager) RotateSecret(ctx context.Context, key string, newValue string) error {
	// Store old value for rollback
	oldValue, err := lsm.GetSecret(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to get current secret for rotation: %w", err)
	}

	// Set new value
	if err := lsm.SetSecret(ctx, key, newValue); err != nil {
		return fmt.Errorf("failed to set new secret value: %w", err)
	}

	// Store old value as backup
	backupKey := fmt.Sprintf("%s.backup.%d", key, time.Now().Unix())
	if err := lsm.SetSecret(ctx, backupKey, oldValue); err != nil {
		// Log error but don't fail the rotation
		fmt.Printf("Warning: failed to create backup of rotated secret: %v\n", err)
	}

	return nil
}

// encrypt encrypts data using AES-GCM
func (lsm *LocalSecretsManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(lsm.encryptKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (lsm *LocalSecretsManager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(lsm.encryptKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// FileSecretStore implements SecretStore using local files
type FileSecretStore struct {
	basePath string
}

// Get reads a secret from file
func (fss *FileSecretStore) Get(ctx context.Context, key string) ([]byte, error) {
	if !isValidSecretKey(key) {
		return nil, fmt.Errorf("invalid secret key")
	}

	filePath := fmt.Sprintf("%s/%s.secret", fss.basePath, key)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("secret not found: %s", key)
		}
		return nil, err
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}

	return decoded, nil
}

// Set writes a secret to file
func (fss *FileSecretStore) Set(ctx context.Context, key string, value []byte) error {
	if !isValidSecretKey(key) {
		return fmt.Errorf("invalid secret key")
	}

	// Ensure directory exists
	if err := os.MkdirAll(fss.basePath, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	filePath := fmt.Sprintf("%s/%s.secret", fss.basePath, key)
	
	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(value)
	
	// Write with secure permissions
	return os.WriteFile(filePath, []byte(encoded), 0600)
}

// Delete removes a secret file
func (fss *FileSecretStore) Delete(ctx context.Context, key string) error {
	if !isValidSecretKey(key) {
		return fmt.Errorf("invalid secret key")
	}

	filePath := fmt.Sprintf("%s/%s.secret", fss.basePath, key)
	return os.Remove(filePath)
}

// List returns all secret keys
func (fss *FileSecretStore) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(fss.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var keys []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".secret") {
			key := strings.TrimSuffix(entry.Name(), ".secret")
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// SecretResolver resolves secret references in configuration
type SecretResolver struct {
	manager SecretsManager
}

// NewSecretResolver creates a new secret resolver
func NewSecretResolver(manager SecretsManager) *SecretResolver {
	return &SecretResolver{
		manager: manager,
	}
}

// ResolveSecrets resolves all secret references in configuration
func (sr *SecretResolver) ResolveSecrets(ctx context.Context, config *Config) error {
	return sr.resolveConfigSecrets(ctx, config)
}

// resolveConfigSecrets recursively resolves secrets in config struct
func (sr *SecretResolver) resolveConfigSecrets(ctx context.Context, config *Config) error {
	// Resolve Database secrets
	if config.Database != nil {
		if err := sr.resolveSecret(ctx, &config.Database.Password); err != nil {
			return fmt.Errorf("failed to resolve database password: %w", err)
		}
	}

	// Resolve Redis secrets
	if config.Redis != nil {
		if err := sr.resolveSecret(ctx, &config.Redis.Password); err != nil {
			return fmt.Errorf("failed to resolve Redis password: %w", err)
		}
	}

	// Resolve Kafka secrets
	if config.Kafka != nil {
		if err := sr.resolveSecret(ctx, &config.Kafka.SASLPassword); err != nil {
			return fmt.Errorf("failed to resolve Kafka SASL password: %w", err)
		}
	}

	// Resolve Auth secrets
	if config.Auth != nil {
		if err := sr.resolveSecret(ctx, &config.Auth.JWTSecret); err != nil {
			return fmt.Errorf("failed to resolve JWT secret: %w", err)
		}
		
		if config.Auth.GoogleOAuth != nil {
			if err := sr.resolveSecret(ctx, &config.Auth.GoogleOAuth.ClientSecret); err != nil {
				return fmt.Errorf("failed to resolve Google OAuth client secret: %w", err)
			}
		}
		
		if config.Auth.GitHubOAuth != nil {
			if err := sr.resolveSecret(ctx, &config.Auth.GitHubOAuth.ClientSecret); err != nil {
				return fmt.Errorf("failed to resolve GitHub OAuth client secret: %w", err)
			}
		}
	}

	// Resolve Security secrets
	if config.Security != nil {
		if err := sr.resolveSecret(ctx, &config.Security.EncryptionKey); err != nil {
			return fmt.Errorf("failed to resolve encryption key: %w", err)
		}
	}

	// Resolve Storage secrets
	if config.Storage != nil && config.Storage.S3Config != nil {
		if err := sr.resolveSecret(ctx, &config.Storage.S3Config.SecretAccessKey); err != nil {
			return fmt.Errorf("failed to resolve S3 secret access key: %w", err)
		}
		if err := sr.resolveSecret(ctx, &config.Storage.EncryptionKey); err != nil {
			return fmt.Errorf("failed to resolve storage encryption key: %w", err)
		}
	}

	// Resolve Email secrets
	if config.Email != nil {
		if config.Email.SMTPConfig != nil {
			if err := sr.resolveSecret(ctx, &config.Email.SMTPConfig.Password); err != nil {
				return fmt.Errorf("failed to resolve SMTP password: %w", err)
			}
		}
		if config.Email.SendGridConfig != nil {
			if err := sr.resolveSecret(ctx, &config.Email.SendGridConfig.APIKey); err != nil {
				return fmt.Errorf("failed to resolve SendGrid API key: %w", err)
			}
		}
	}

	// Resolve Billing secrets
	if config.Billing != nil {
		if err := sr.resolveSecret(ctx, &config.Billing.WebhookSecret); err != nil {
			return fmt.Errorf("failed to resolve billing webhook secret: %w", err)
		}
		if config.Billing.StripeConfig != nil {
			if err := sr.resolveSecret(ctx, &config.Billing.StripeConfig.SecretKey); err != nil {
				return fmt.Errorf("failed to resolve Stripe secret key: %w", err)
			}
			if err := sr.resolveSecret(ctx, &config.Billing.StripeConfig.WebhookSecret); err != nil {
				return fmt.Errorf("failed to resolve Stripe webhook secret: %w", err)
			}
		}
	}

	// Resolve Webhook secrets
	if config.Webhook != nil {
		if err := sr.resolveSecret(ctx, &config.Webhook.SignatureSecret); err != nil {
			return fmt.Errorf("failed to resolve webhook signature secret: %w", err)
		}
	}

	return nil
}

// resolveSecret resolves a single secret reference
func (sr *SecretResolver) resolveSecret(ctx context.Context, secretRef *string) error {
	if secretRef == nil || *secretRef == "" {
		return nil
	}

	// Check if this is a secret reference (starts with secret://)
	if !strings.HasPrefix(*secretRef, "secret://") {
		return nil // Not a secret reference, leave as is
	}

	// Extract secret key
	secretKey := strings.TrimPrefix(*secretRef, "secret://")
	if secretKey == "" {
		return fmt.Errorf("empty secret key")
	}

	// Resolve secret
	secretValue, err := sr.manager.GetSecret(ctx, secretKey)
	if err != nil {
		return fmt.Errorf("failed to resolve secret '%s': %w", secretKey, err)
	}

	*secretRef = secretValue
	return nil
}

// ConfigTemplate represents a configuration template with secret references
type ConfigTemplate struct {
	Template string            `json:"template" yaml:"template"`
	Secrets  map[string]string `json:"secrets" yaml:"secrets"`
}

// LoadConfigFromTemplate loads configuration from a template with secrets
func LoadConfigFromTemplate(templatePath string, secretsManager SecretsManager) (*Config, error) {
	ctx := context.Background()

	// Read template file
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var template ConfigTemplate
	if err := json.Unmarshal(templateData, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	// Resolve template secrets
	resolvedTemplate := template.Template
	for key, secretRef := range template.Secrets {
		secretValue, err := secretsManager.GetSecret(ctx, secretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve template secret '%s': %w", secretRef, err)
		}

		placeholder := fmt.Sprintf("${%s}", key)
		resolvedTemplate = strings.ReplaceAll(resolvedTemplate, placeholder, secretValue)
	}

	// Parse resolved configuration
	var config Config
	if err := json.Unmarshal([]byte(resolvedTemplate), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resolved config: %w", err)
	}

	return &config, nil
}

// Helper functions
func getSecretStorePath() string {
	if path := os.Getenv("N8N_PRO_SECRETS_PATH"); path != "" {
		return path
	}
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/n8n-pro-secrets"
	}
	
	return fmt.Sprintf("%s/.n8n-pro/secrets", homeDir)
}

func isValidSecretKey(key string) bool {
	// Allow alphanumeric, hyphens, underscores, and dots
	validKey := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	return validKey.MatchString(key) && len(key) > 0 && len(key) <= 128
}

// DefaultSecretsManager creates a default secrets manager
func DefaultSecretsManager() (SecretsManager, error) {
	masterKey := os.Getenv("N8N_PRO_MASTER_KEY")
	if masterKey == "" {
		return nil, fmt.Errorf("N8N_PRO_MASTER_KEY environment variable is required")
	}

	return NewLocalSecretsManager(masterKey)
}

// InitializeSecrets initializes common secrets if they don't exist
func InitializeSecrets(manager SecretsManager) error {
	ctx := context.Background()

	secrets := []struct {
		key         string
		defaultFunc func() string
		required    bool
	}{
		{"jwt_secret", generateRandomString, true},
		{"encryption_key", generateRandomString, true},
		{"csrf_secret", generateRandomString, false},
		{"session_secret", generateRandomString, false},
	}

	for _, secret := range secrets {
		// Check if secret already exists
		_, err := manager.GetSecret(ctx, secret.key)
		if err == nil {
			continue // Secret exists, skip
		}

		if secret.required {
			// Generate default value for required secrets
			defaultValue := secret.defaultFunc()
			if err := manager.SetSecret(ctx, secret.key, defaultValue); err != nil {
				return fmt.Errorf("failed to initialize secret '%s': %w", secret.key, err)
			}
		}
	}

	return nil
}

func generateRandomString() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)
}