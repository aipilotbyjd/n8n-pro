package repository

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"n8n-pro/internal/auth/ldap"
	"n8n-pro/internal/auth/saml"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jmoiron/sqlx"
)

// EnterpriseConfigType represents the type of enterprise configuration
type EnterpriseConfigType string

const (
	ConfigTypeSAML EnterpriseConfigType = "saml"
	ConfigTypeLDAP EnterpriseConfigType = "ldap"
)

// EnterpriseConfig represents a stored enterprise configuration
type EnterpriseConfig struct {
	ID             string               `json:"id" db:"id"`
	OrganizationID string               `json:"organization_id" db:"organization_id"`
	ConfigType     EnterpriseConfigType `json:"config_type" db:"config_type"`
	Name           string               `json:"name" db:"name"`
	Description    string               `json:"description" db:"description"`
	IsEnabled      bool                 `json:"is_enabled" db:"is_enabled"`
	ConfigData     map[string]interface{} `json:"config_data" db:"-"` // Not stored directly
	EncryptedData  []byte               `json:"-" db:"encrypted_data"` // Encrypted config data
	CreatedAt      time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at" db:"updated_at"`
	CreatedBy      string               `json:"created_by" db:"created_by"`
	UpdatedBy      string               `json:"updated_by" db:"updated_by"`
	Version        int                  `json:"version" db:"version"`
}

// PostgresEnterpriseConfigRepository implements enterprise config repository using PostgreSQL
type PostgresEnterpriseConfigRepository struct {
	db            *sqlx.DB
	logger        logger.Logger
	encryptionKey []byte
	gcm           cipher.AEAD
}

// NewPostgresEnterpriseConfigRepository creates a new PostgreSQL enterprise config repository
func NewPostgresEnterpriseConfigRepository(db *sqlx.DB, logger logger.Logger, encryptionKey string) (*PostgresEnterpriseConfigRepository, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes long")
	}

	key := []byte(encryptionKey)
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	return &PostgresEnterpriseConfigRepository{
		db:            db,
		logger:        logger,
		encryptionKey: key,
		gcm:           gcm,
	}, nil
}

// CreateSAMLConfig creates a new SAML configuration
func (r *PostgresEnterpriseConfigRepository) CreateSAMLConfig(ctx context.Context, organizationID, name, description string, config *saml.SAMLConfig, createdBy string) (*EnterpriseConfig, error) {
	configData := map[string]interface{}{
		"entity_id":                    config.EntityID,
		"base_url":                     config.BaseURL,
		"certificate":                  config.Certificate,
		"private_key":                  config.PrivateKey,
		"sign_requests":                config.SignRequests,
		"encrypt_assertions":           config.EncryptAssertions,
		"require_encrypted_assertions": config.RequireEncryptedAssertions,
		"attribute_mappings":           config.AttributeMappings,
		"default_organization_id":      config.DefaultOrganizationID,
		"auto_create_users":            config.AutoCreateUsers,
	}

	return r.createConfig(ctx, organizationID, ConfigTypeSAML, name, description, configData, createdBy)
}

// CreateLDAPConfig creates a new LDAP configuration
func (r *PostgresEnterpriseConfigRepository) CreateLDAPConfig(ctx context.Context, organizationID, name, description string, config *ldap.LDAPConfig, createdBy string) (*EnterpriseConfig, error) {
	configData := map[string]interface{}{
		"host":                     config.Host,
		"port":                     config.Port,
		"use_ssl":                  config.UseSSL,
		"use_start_tls":            config.UseStartTLS,
		"skip_verify":              config.SkipVerify,
		"bind_dn":                  config.BindDN,
		"bind_password":            config.BindPassword,
		"base_dn":                  config.BaseDN,
		"user_filter":              config.UserFilter,
		"group_base_dn":            config.GroupBaseDN,
		"group_filter":             config.GroupFilter,
		"attribute_mappings":       config.AttributeMappings,
		"connection_timeout":       config.ConnectionTimeout.String(),
		"read_timeout":             config.ReadTimeout.String(),
		"default_organization_id":  config.DefaultOrganizationID,
		"auto_create_users":        config.AutoCreateUsers,
		"sync_groups":              config.SyncGroups,
	}

	return r.createConfig(ctx, organizationID, ConfigTypeLDAP, name, description, configData, createdBy)
}

// createConfig creates a new enterprise configuration (internal method)
func (r *PostgresEnterpriseConfigRepository) createConfig(ctx context.Context, organizationID string, configType EnterpriseConfigType, name, description string, configData map[string]interface{}, createdBy string) (*EnterpriseConfig, error) {
	id := generateConfigID(string(configType))
	
	// Encrypt configuration data
	encryptedData, err := r.encryptConfigData(configData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt config data: %w", err)
	}

	query := `
		INSERT INTO enterprise_configs (
			id, organization_id, config_type, name, description, 
			is_enabled, encrypted_data, created_at, updated_at, 
			created_by, updated_by, version
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`

	now := time.Now().UTC()
	_, err = r.db.ExecContext(ctx, query,
		id, organizationID, string(configType), name, description,
		true, encryptedData, now, now, createdBy, createdBy, 1,
	)
	if err != nil {
		r.logger.Error("Failed to create enterprise config", "error", err, "config_id", id)
		return nil, fmt.Errorf("failed to create enterprise config: %w", err)
	}

	config := &EnterpriseConfig{
		ID:             id,
		OrganizationID: organizationID,
		ConfigType:     configType,
		Name:           name,
		Description:    description,
		IsEnabled:      true,
		ConfigData:     configData,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      createdBy,
		UpdatedBy:      createdBy,
		Version:        1,
	}

	r.logger.Info("Enterprise config created", "config_id", id, "type", configType, "organization_id", organizationID)
	return config, nil
}

// GetConfigByID retrieves an enterprise configuration by its ID
func (r *PostgresEnterpriseConfigRepository) GetConfigByID(ctx context.Context, id string) (*EnterpriseConfig, error) {
	query := `
		SELECT id, organization_id, config_type, name, description, 
		       is_enabled, encrypted_data, created_at, updated_at, 
		       created_by, updated_by, version
		FROM enterprise_configs 
		WHERE id = $1`

	var config EnterpriseConfig
	var configType string
	var encryptedData []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&config.ID,
		&config.OrganizationID,
		&configType,
		&config.Name,
		&config.Description,
		&config.IsEnabled,
		&encryptedData,
		&config.CreatedAt,
		&config.UpdatedAt,
		&config.CreatedBy,
		&config.UpdatedBy,
		&config.Version,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Enterprise config not found")
		}
		return nil, fmt.Errorf("failed to get enterprise config: %w", err)
	}

	config.ConfigType = EnterpriseConfigType(configType)

	// Decrypt configuration data
	configData, err := r.decryptConfigData(encryptedData)
	if err != nil {
		r.logger.Error("Failed to decrypt config data", "config_id", id, "error", err)
		return nil, fmt.Errorf("failed to decrypt config data: %w", err)
	}
	config.ConfigData = configData

	return &config, nil
}

// GetConfigsByOrganization retrieves all enterprise configurations for an organization
func (r *PostgresEnterpriseConfigRepository) GetConfigsByOrganization(ctx context.Context, organizationID string, configType *EnterpriseConfigType) ([]*EnterpriseConfig, error) {
	query := `
		SELECT id, organization_id, config_type, name, description, 
		       is_enabled, encrypted_data, created_at, updated_at, 
		       created_by, updated_by, version
		FROM enterprise_configs 
		WHERE organization_id = $1`
	
	args := []interface{}{organizationID}
	
	if configType != nil {
		query += ` AND config_type = $2`
		args = append(args, string(*configType))
	}
	
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get enterprise configs: %w", err)
	}
	defer rows.Close()

	var configs []*EnterpriseConfig
	for rows.Next() {
		var config EnterpriseConfig
		var configTypeStr string
		var encryptedData []byte

		err := rows.Scan(
			&config.ID,
			&config.OrganizationID,
			&configTypeStr,
			&config.Name,
			&config.Description,
			&config.IsEnabled,
			&encryptedData,
			&config.CreatedAt,
			&config.UpdatedAt,
			&config.CreatedBy,
			&config.UpdatedBy,
			&config.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan enterprise config: %w", err)
		}

		config.ConfigType = EnterpriseConfigType(configTypeStr)

		// Decrypt configuration data
		configData, err := r.decryptConfigData(encryptedData)
		if err != nil {
			r.logger.Error("Failed to decrypt config data", "config_id", config.ID, "error", err)
			// Skip corrupted configs but log error
			continue
		}
		config.ConfigData = configData

		configs = append(configs, &config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return configs, nil
}

// UpdateConfig updates an existing enterprise configuration
func (r *PostgresEnterpriseConfigRepository) UpdateConfig(ctx context.Context, id string, name, description *string, configData map[string]interface{}, isEnabled *bool, updatedBy string) (*EnterpriseConfig, error) {
	// Start transaction
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current config for optimistic locking
	var currentVersion int
	err = tx.GetContext(ctx, &currentVersion, "SELECT version FROM enterprise_configs WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Enterprise config not found")
		}
		return nil, fmt.Errorf("failed to get current config version: %w", err)
	}

	// Build update query dynamically
	setParts := []string{"updated_at = $2", "updated_by = $3", "version = $4"}
	args := []interface{}{id, time.Now().UTC(), updatedBy, currentVersion + 1}
	argIndex := 5

	if name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *name)
		argIndex++
	}

	if description != nil {
		setParts = append(setParts, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *description)
		argIndex++
	}

	if isEnabled != nil {
		setParts = append(setParts, fmt.Sprintf("is_enabled = $%d", argIndex))
		args = append(args, *isEnabled)
		argIndex++
	}

	if configData != nil {
		// Encrypt new configuration data
		encryptedData, err := r.encryptConfigData(configData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt config data: %w", err)
		}

		setParts = append(setParts, fmt.Sprintf("encrypted_data = $%d", argIndex))
		args = append(args, encryptedData)
		argIndex++
	}

	query := fmt.Sprintf(`
		UPDATE enterprise_configs 
		SET %s 
		WHERE id = $1 AND version = $%d`, 
		fmt.Sprintf("%s", setParts[0]), argIndex)
	
	for i := 1; i < len(setParts); i++ {
		query = fmt.Sprintf("%s, %s", query, setParts[i])
	}
	
	args = append(args, currentVersion)

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update enterprise config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return nil, errors.NewConflictError("Configuration was modified by another process")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return updated config
	updatedConfig, err := r.GetConfigByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated config: %w", err)
	}

	r.logger.Info("Enterprise config updated", "config_id", id, "updated_by", updatedBy)
	return updatedConfig, nil
}

// DeleteConfig soft deletes an enterprise configuration
func (r *PostgresEnterpriseConfigRepository) DeleteConfig(ctx context.Context, id string, deletedBy string) error {
	query := `
		UPDATE enterprise_configs 
		SET is_enabled = false, updated_at = $2, updated_by = $3
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id, time.Now().UTC(), deletedBy)
	if err != nil {
		return fmt.Errorf("failed to delete enterprise config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("Enterprise config not found")
	}

	r.logger.Info("Enterprise config deleted", "config_id", id, "deleted_by", deletedBy)
	return nil
}

// HardDeleteConfig permanently deletes an enterprise configuration
func (r *PostgresEnterpriseConfigRepository) HardDeleteConfig(ctx context.Context, id string) error {
	query := `DELETE FROM enterprise_configs WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to hard delete enterprise config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("Enterprise config not found")
	}

	r.logger.Info("Enterprise config permanently deleted", "config_id", id)
	return nil
}

// ConvertToSAMLConfig converts enterprise config to SAML config
func (r *PostgresEnterpriseConfigRepository) ConvertToSAMLConfig(config *EnterpriseConfig) (*saml.SAMLConfig, error) {
	if config.ConfigType != ConfigTypeSAML {
		return nil, fmt.Errorf("config is not SAML type")
	}

	samlConfig := &saml.SAMLConfig{
		EntityID:                   getStringFromConfig(config.ConfigData, "entity_id"),
		BaseURL:                    getStringFromConfig(config.ConfigData, "base_url"),
		Certificate:                getStringFromConfig(config.ConfigData, "certificate"),
		PrivateKey:                 getStringFromConfig(config.ConfigData, "private_key"),
		SignRequests:               getBoolFromConfig(config.ConfigData, "sign_requests"),
		EncryptAssertions:          getBoolFromConfig(config.ConfigData, "encrypt_assertions"),
		RequireEncryptedAssertions: getBoolFromConfig(config.ConfigData, "require_encrypted_assertions"),
		DefaultOrganizationID:      getStringFromConfig(config.ConfigData, "default_organization_id"),
		AutoCreateUsers:            getBoolFromConfig(config.ConfigData, "auto_create_users"),
	}

	// Extract attribute mappings
	if mappings, ok := config.ConfigData["attribute_mappings"].(map[string]interface{}); ok {
		samlConfig.AttributeMappings = saml.AttributeMappings{
			Email:     getStringFromInterface(mappings["email"]),
			FirstName: getStringFromInterface(mappings["first_name"]),
			LastName:  getStringFromInterface(mappings["last_name"]),
			Groups:    getStringFromInterface(mappings["groups"]),
		}
	}

	return samlConfig, nil
}

// ConvertToLDAPConfig converts enterprise config to LDAP config
func (r *PostgresEnterpriseConfigRepository) ConvertToLDAPConfig(config *EnterpriseConfig) (*ldap.LDAPConfig, error) {
	if config.ConfigType != ConfigTypeLDAP {
		return nil, fmt.Errorf("config is not LDAP type")
	}

	ldapConfig := &ldap.LDAPConfig{
		Host:                  getStringFromConfig(config.ConfigData, "host"),
		Port:                  getIntFromConfig(config.ConfigData, "port"),
		UseSSL:                getBoolFromConfig(config.ConfigData, "use_ssl"),
		UseStartTLS:           getBoolFromConfig(config.ConfigData, "use_start_tls"),
		SkipVerify:            getBoolFromConfig(config.ConfigData, "skip_verify"),
		BindDN:                getStringFromConfig(config.ConfigData, "bind_dn"),
		BindPassword:          getStringFromConfig(config.ConfigData, "bind_password"),
		BaseDN:                getStringFromConfig(config.ConfigData, "base_dn"),
		UserFilter:            getStringFromConfig(config.ConfigData, "user_filter"),
		GroupBaseDN:           getStringFromConfig(config.ConfigData, "group_base_dn"),
		GroupFilter:           getStringFromConfig(config.ConfigData, "group_filter"),
		DefaultOrganizationID: getStringFromConfig(config.ConfigData, "default_organization_id"),
		AutoCreateUsers:       getBoolFromConfig(config.ConfigData, "auto_create_users"),
		SyncGroups:            getBoolFromConfig(config.ConfigData, "sync_groups"),
	}

	// Parse timeouts
	if timeoutStr := getStringFromConfig(config.ConfigData, "connection_timeout"); timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			ldapConfig.ConnectionTimeout = timeout
		}
	}
	if timeoutStr := getStringFromConfig(config.ConfigData, "read_timeout"); timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			ldapConfig.ReadTimeout = timeout
		}
	}

	// Extract attribute mappings
	if mappings, ok := config.ConfigData["attribute_mappings"].(map[string]interface{}); ok {
		ldapConfig.AttributeMappings = ldap.LDAPAttributeMappings{
			Email:     getStringFromInterface(mappings["email"]),
			FirstName: getStringFromInterface(mappings["first_name"]),
			LastName:  getStringFromInterface(mappings["last_name"]),
			FullName:  getStringFromInterface(mappings["full_name"]),
			UserID:    getStringFromInterface(mappings["user_id"]),
			Groups:    getStringFromInterface(mappings["groups"]),
		}
	}

	return ldapConfig, nil
}

// Encryption/Decryption methods

func (r *PostgresEnterpriseConfigRepository) encryptConfigData(data map[string]interface{}) ([]byte, error) {
	// Convert to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	// Create nonce
	nonce := make([]byte, r.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := r.gcm.Seal(nonce, nonce, jsonData, nil)
	return ciphertext, nil
}

func (r *PostgresEnterpriseConfigRepository) decryptConfigData(encryptedData []byte) (map[string]interface{}, error) {
	if len(encryptedData) < r.gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce and ciphertext
	nonce := encryptedData[:r.gcm.NonceSize()]
	ciphertext := encryptedData[r.gcm.NonceSize():]

	// Decrypt
	plaintext, err := r.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Unmarshal JSON
	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted data: %w", err)
	}

	return data, nil
}

// Utility functions

func generateConfigID(configType string) string {
	return fmt.Sprintf("%s_config_%d", configType, time.Now().UnixNano())
}

func getStringFromConfig(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolFromConfig(data map[string]interface{}, key string) bool {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getIntFromConfig(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return 0
}

func getStringFromInterface(val interface{}) string {
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

// ConfigurationSummary provides a summary of configurations for an organization
type ConfigurationSummary struct {
	OrganizationID string                       `json:"organization_id"`
	TotalConfigs   int                          `json:"total_configs"`
	ConfigsByType  map[string]int               `json:"configs_by_type"`
	ActiveConfigs  int                          `json:"active_configs"`
	LastUpdated    time.Time                    `json:"last_updated"`
}

// GetConfigurationSummary returns a summary of configurations for an organization
func (r *PostgresEnterpriseConfigRepository) GetConfigurationSummary(ctx context.Context, organizationID string) (*ConfigurationSummary, error) {
	query := `
		SELECT 
			config_type,
			COUNT(*) as total,
			COUNT(CASE WHEN is_enabled = true THEN 1 END) as active,
			MAX(updated_at) as last_updated
		FROM enterprise_configs 
		WHERE organization_id = $1
		GROUP BY config_type`

	rows, err := r.db.QueryContext(ctx, query, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration summary: %w", err)
	}
	defer rows.Close()

	summary := &ConfigurationSummary{
		OrganizationID: organizationID,
		ConfigsByType:  make(map[string]int),
	}

	var latestUpdate time.Time
	for rows.Next() {
		var configType string
		var total, active int
		var lastUpdated time.Time

		err := rows.Scan(&configType, &total, &active, &lastUpdated)
		if err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
		}

		summary.ConfigsByType[configType] = total
		summary.TotalConfigs += total
		summary.ActiveConfigs += active

		if lastUpdated.After(latestUpdate) {
			latestUpdate = lastUpdated
		}
	}

	summary.LastUpdated = latestUpdate
	return summary, nil
}