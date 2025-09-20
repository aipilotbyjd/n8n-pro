package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// Vault defines the interface for secure credential storage
type Vault interface {
	Store(ctx context.Context, key string, data []byte) error
	Retrieve(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]string, error)
	Exists(ctx context.Context, key string) (bool, error)
	Close() error
}

// VaultConfig represents vault configuration
type VaultConfig struct {
	Type            string        `json:"type" yaml:"type"` // memory, file, hashicorp
	EncryptionKey   string        `json:"encryption_key" yaml:"encryption_key"`
	FilePath        string        `json:"file_path" yaml:"file_path"`
	HashiCorpURL    string        `json:"hashicorp_url" yaml:"hashicorp_url"`
	HashiCorpToken  string        `json:"hashicorp_token" yaml:"hashicorp_token"`
	TTL             time.Duration `json:"ttl" yaml:"ttl"`
	MaxSize         int64         `json:"max_size" yaml:"max_size"`
	AutoCleanup     bool          `json:"auto_cleanup" yaml:"auto_cleanup"`
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
}

// DefaultVaultConfig returns default vault configuration
func DefaultVaultConfig() *VaultConfig {
	return &VaultConfig{
		Type:            "memory",
		TTL:             24 * time.Hour,
		MaxSize:         100 * 1024 * 1024, // 100MB
		AutoCleanup:     true,
		CleanupInterval: 1 * time.Hour,
	}
}

// VaultEntry represents an entry in the vault
type VaultEntry struct {
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Size      int64     `json:"size"`
}

// IsExpired checks if the vault entry has expired
func (e *VaultEntry) IsExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// MemoryVault implements an in-memory vault with encryption
type MemoryVault struct {
	config      *VaultConfig
	entries     map[string]*VaultEntry
	mutex       sync.RWMutex
	cipher      cipher.AEAD
	logger      logger.Logger
	stopCleanup chan struct{}
	cleanupWG   sync.WaitGroup
}

// NewVault creates a new vault instance
func NewVault(config *VaultConfig, log logger.Logger) (Vault, error) {
	if config == nil {
		config = DefaultVaultConfig()
	}

	switch config.Type {
	case "memory":
		return NewMemoryVault(config, log)
	default:
		return nil, errors.NewValidationError(fmt.Sprintf("unsupported vault type: %s", config.Type))
	}
}

// NewMemoryVault creates a new in-memory vault
func NewMemoryVault(config *VaultConfig, log logger.Logger) (*MemoryVault, error) {
	if config.EncryptionKey == "" {
		return nil, errors.NewValidationError("encryption key is required")
	}

	// Create AES cipher
	key := []byte(config.EncryptionKey)
	if len(key) < 32 {
		// Pad key to 32 bytes for AES-256
		padded := make([]byte, 32)
		copy(padded, key)
		key = padded
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	vault := &MemoryVault{
		config:      config,
		entries:     make(map[string]*VaultEntry),
		cipher:      aead,
		logger:      log,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup routine if enabled
	if config.AutoCleanup {
		vault.cleanupWG.Add(1)
		go vault.cleanupRoutine()
	}

	log.Info("Memory vault initialized", "max_size", config.MaxSize, "ttl", config.TTL)
	return vault, nil
}

// Store encrypts and stores data in the vault
func (v *MemoryVault) Store(ctx context.Context, key string, data []byte) error {
	if key == "" {
		return errors.NewValidationError("key cannot be empty")
	}

	if len(data) == 0 {
		return errors.NewValidationError("data cannot be empty")
	}

	// Check size limits
	if v.config.MaxSize > 0 && int64(len(data)) > v.config.MaxSize {
		return errors.NewValidationError("data size exceeds maximum limit")
	}

	// Encrypt data
	encryptedData, err := v.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Create entry
	entry := &VaultEntry{
		Data:      encryptedData,
		CreatedAt: time.Now(),
		Size:      int64(len(data)),
	}

	// Set expiration if TTL is configured
	if v.config.TTL > 0 {
		entry.ExpiresAt = entry.CreatedAt.Add(v.config.TTL)
	}

	// Store entry
	v.mutex.Lock()
	v.entries[key] = entry
	v.mutex.Unlock()

	v.logger.Debug("Data stored in vault", "key", key, "size", len(data))
	return nil
}

// Retrieve decrypts and retrieves data from the vault
func (v *MemoryVault) Retrieve(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, errors.NewValidationError("key cannot be empty")
	}

	v.mutex.RLock()
	entry, exists := v.entries[key]
	v.mutex.RUnlock()

	if !exists {
		return nil, errors.NewNotFoundError("vault entry not found")
	}

	if entry.IsExpired() {
		// Remove expired entry
		v.mutex.Lock()
		delete(v.entries, key)
		v.mutex.Unlock()
		return nil, errors.NewNotFoundError("vault entry expired")
	}

	// Decrypt data
	data, err := v.decrypt(entry.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	v.logger.Debug("Data retrieved from vault", "key", key, "size", len(data))
	return data, nil
}

// Delete removes an entry from the vault
func (v *MemoryVault) Delete(ctx context.Context, key string) error {
	if key == "" {
		return errors.NewValidationError("key cannot be empty")
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	if _, exists := v.entries[key]; !exists {
		return errors.NewNotFoundError("vault entry not found")
	}

	delete(v.entries, key)
	v.logger.Debug("Data deleted from vault", "key", key)
	return nil
}

// List returns all keys in the vault
func (v *MemoryVault) List(ctx context.Context) ([]string, error) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	keys := make([]string, 0, len(v.entries))
	for key, entry := range v.entries {
		if !entry.IsExpired() {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Exists checks if a key exists in the vault
func (v *MemoryVault) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, errors.NewValidationError("key cannot be empty")
	}

	v.mutex.RLock()
	entry, exists := v.entries[key]
	v.mutex.RUnlock()

	if !exists {
		return false, nil
	}

	if entry.IsExpired() {
		// Remove expired entry
		v.mutex.Lock()
		delete(v.entries, key)
		v.mutex.Unlock()
		return false, nil
	}

	return true, nil
}

// Close shuts down the vault
func (v *MemoryVault) Close() error {
	close(v.stopCleanup)
	v.cleanupWG.Wait()

	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Clear all entries
	v.entries = make(map[string]*VaultEntry)

	v.logger.Info("Memory vault closed")
	return nil
}

// encrypt encrypts data using AES-GCM
func (v *MemoryVault) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, v.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := v.cipher.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (v *MemoryVault) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := v.cipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.NewValidationError("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := v.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// cleanupRoutine periodically removes expired entries
func (v *MemoryVault) cleanupRoutine() {
	defer v.cleanupWG.Done()

	ticker := time.NewTicker(v.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			v.cleanup()
		case <-v.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (v *MemoryVault) cleanup() {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	expiredKeys := make([]string, 0)
	for key, entry := range v.entries {
		if entry.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(v.entries, key)
	}

	if len(expiredKeys) > 0 {
		v.logger.Debug("Cleaned up expired vault entries", "count", len(expiredKeys))
	}
}

// GetStats returns vault statistics
func (v *MemoryVault) GetStats() map[string]interface{} {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	totalSize := int64(0)
	expiredCount := 0

	for _, entry := range v.entries {
		totalSize += entry.Size
		if entry.IsExpired() {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(v.entries),
		"expired_entries": expiredCount,
		"total_size":      totalSize,
		"max_size":        v.config.MaxSize,
		"ttl":             v.config.TTL,
	}
}

// VaultManager manages multiple vault instances
type VaultManager struct {
	vaults map[string]Vault
	mutex  sync.RWMutex
	logger logger.Logger
}

// NewVaultManager creates a new vault manager
func NewVaultManager(log logger.Logger) *VaultManager {
	return &VaultManager{
		vaults: make(map[string]Vault),
		logger: log,
	}
}

// AddVault adds a vault to the manager
func (vm *VaultManager) AddVault(name string, vault Vault) error {
	if name == "" {
		return errors.NewValidationError("vault name cannot be empty")
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if _, exists := vm.vaults[name]; exists {
		return errors.NewValidationError(fmt.Sprintf("vault '%s' already exists", name))
	}

	vm.vaults[name] = vault
	vm.logger.Info("Vault added to manager", "name", name)
	return nil
}

// GetVault returns a vault by name
func (vm *VaultManager) GetVault(name string) (Vault, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vault, exists := vm.vaults[name]
	if !exists {
		return nil, errors.NewNotFoundError(fmt.Sprintf("vault '%s' not found", name))
	}

	return vault, nil
}

// RemoveVault removes a vault from the manager
func (vm *VaultManager) RemoveVault(name string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vault, exists := vm.vaults[name]
	if !exists {
		return errors.NewNotFoundError(fmt.Sprintf("vault '%s' not found", name))
	}

	if err := vault.Close(); err != nil {
		vm.logger.Error("Error closing vault", "name", name, "error", err)
	}

	delete(vm.vaults, name)
	vm.logger.Info("Vault removed from manager", "name", name)
	return nil
}

// CloseAll closes all vaults
func (vm *VaultManager) CloseAll() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	for name, vault := range vm.vaults {
		if err := vault.Close(); err != nil {
			vm.logger.Error("Error closing vault", "name", name, "error", err)
		}
	}

	vm.vaults = make(map[string]Vault)
	return nil
}

// Helper function to generate secure encryption key
func GenerateEncryptionKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Fallback to timestamp-based key if random fails
		return fmt.Sprintf("n8n-vault-key-%d", time.Now().UnixNano())
	}
	return base64.StdEncoding.EncodeToString(key)
}
