package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	OrganizationID string                 `json:"organization_id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	KeyHash        string                 `json:"-"`
	KeyPrefix      string                 `json:"key_prefix"`
	Permissions    []string               `json:"permissions"`
	Scopes         []string               `json:"scopes"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time             `json:"last_used_at,omitempty"`
	UsageCount     int64                  `json:"usage_count"`
	IsActive       bool                   `json:"is_active"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// APIKeyRepository provides API key data access operations
type APIKeyRepository interface {
	Create(ctx context.Context, apiKey *APIKey) (*APIKey, string, error)
	FindByID(ctx context.Context, id string) (*APIKey, error)
	FindByKey(ctx context.Context, key string) (*APIKey, error)
	FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*APIKey, int64, error)
	FindByOrganizationID(ctx context.Context, orgID string, limit, offset int) ([]*APIKey, int64, error)
	Update(ctx context.Context, apiKey *APIKey) error
	Revoke(ctx context.Context, keyID string) error
	UpdateLastUsed(ctx context.Context, keyID string) error
	CleanupExpiredKeys(ctx context.Context) error
}

// apiKeyRepository implements APIKeyRepository using GORM
type apiKeyRepository struct {
	db *gorm.DB
}

// NewAPIKeyRepository creates a new API key repository
func NewAPIKeyRepository(db *gorm.DB) APIKeyRepository {
	return &apiKeyRepository{db: db}
}

// Create creates a new API key
func (r *apiKeyRepository) Create(ctx context.Context, apiKey *APIKey) (*APIKey, string, error) {
	// Generate the actual API key
	key, keyHash, keyPrefix, err := r.generateAPIKey()
	if err != nil {
		return nil, "", errors.NewInternalError("Failed to generate API key")
	}

	// Convert to GORM model for storage
	gormAPIKey := &models.APIKey{
		BaseModel: models.BaseModel{
			ID: apiKey.ID,
		},
		UserID:         apiKey.UserID,
		OrganizationID: apiKey.OrganizationID,
		Name:           apiKey.Name,
		Description:    apiKey.Description,
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		Permissions:    apiKey.Permissions,
		Scopes:         apiKey.Scopes,
		ExpiresAt:      apiKey.ExpiresAt,
		IsActive:       true,
		Metadata:       apiKey.Metadata,
	}

	if err := r.db.WithContext(ctx).Create(gormAPIKey).Error; err != nil {
		return nil, "", errors.NewInternalError("Failed to create API key")
	}

	// Convert back to domain model
	result := r.gormToDomain(gormAPIKey)
	return result, key, nil
}

// FindByID finds an API key by ID
func (r *apiKeyRepository) FindByID(ctx context.Context, id string) (*APIKey, error) {
	var apiKey models.APIKey
	if err := r.db.WithContext(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		First(&apiKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("API key not found")
		}
		return nil, errors.NewInternalError("Failed to find API key")
	}

	return r.gormToDomain(&apiKey), nil
}

// FindByKey finds an API key by the actual key value
func (r *apiKeyRepository) FindByKey(ctx context.Context, key string) (*APIKey, error) {
	// Extract prefix from key (first 8 characters after "n8n_")
	if len(key) < 12 || !fmt.Sprintf(key[:4]) == "n8n_" {
		return nil, errors.NewNotFoundError("Invalid API key format")
	}

	prefix := key[:12] // "n8n_" + 8 characters
	
	var apiKeys []models.APIKey
	if err := r.db.WithContext(ctx).
		Where("key_prefix = ? AND is_active = ? AND deleted_at IS NULL", prefix, true).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Find(&apiKeys).Error; err != nil {
		return nil, errors.NewInternalError("Failed to search API keys")
	}

	// Find matching key by comparing hashes
	for _, apiKey := range apiKeys {
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(key)); err == nil {
			return r.gormToDomain(&apiKey), nil
		}
	}

	return nil, errors.NewNotFoundError("API key not found")
}

// FindByUserID finds API keys for a user with pagination
func (r *apiKeyRepository) FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*APIKey, int64, error) {
	var apiKeys []models.APIKey
	var total int64

	// Get total count
	if err := r.db.WithContext(ctx).
		Model(&models.APIKey{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Count(&total).Error; err != nil {
		return nil, 0, errors.NewInternalError("Failed to count API keys")
	}

	// Get paginated results
	query := r.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	if err := query.Find(&apiKeys).Error; err != nil {
		return nil, 0, errors.NewInternalError("Failed to find API keys")
	}

	var result []*APIKey
	for _, key := range apiKeys {
		result = append(result, r.gormToDomain(&key))
	}

	return result, total, nil
}

// FindByOrganizationID finds API keys for an organization with pagination
func (r *apiKeyRepository) FindByOrganizationID(ctx context.Context, orgID string, limit, offset int) ([]*APIKey, int64, error) {
	var apiKeys []models.APIKey
	var total int64

	// Get total count
	if err := r.db.WithContext(ctx).
		Model(&models.APIKey{}).
		Where("organization_id = ? AND deleted_at IS NULL", orgID).
		Count(&total).Error; err != nil {
		return nil, 0, errors.NewInternalError("Failed to count API keys")
	}

	// Get paginated results
	query := r.db.WithContext(ctx).
		Where("organization_id = ? AND deleted_at IS NULL", orgID).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	if err := query.Find(&apiKeys).Error; err != nil {
		return nil, 0, errors.NewInternalError("Failed to find API keys")
	}

	var result []*APIKey
	for _, key := range apiKeys {
		result = append(result, r.gormToDomain(&key))
	}

	return result, total, nil
}

// Update updates an API key
func (r *apiKeyRepository) Update(ctx context.Context, apiKey *APIKey) error {
	gormAPIKey := r.domainToGorm(apiKey)
	if err := r.db.WithContext(ctx).Save(gormAPIKey).Error; err != nil {
		return errors.NewInternalError("Failed to update API key")
	}
	return nil
}

// Revoke revokes an API key
func (r *apiKeyRepository) Revoke(ctx context.Context, keyID string) error {
	result := r.db.WithContext(ctx).
		Model(&models.APIKey{}).
		Where("id = ? AND deleted_at IS NULL", keyID).
		Updates(map[string]interface{}{
			"is_active":  false,
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		return errors.NewInternalError("Failed to revoke API key")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("API key not found")
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp and increments usage count
func (r *apiKeyRepository) UpdateLastUsed(ctx context.Context, keyID string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.APIKey{}).
		Where("id = ? AND deleted_at IS NULL", keyID).
		Updates(map[string]interface{}{
			"last_used_at": now,
			"usage_count":  gorm.Expr("usage_count + 1"),
			"updated_at":   now,
		})

	if result.Error != nil {
		return errors.NewInternalError("Failed to update API key usage")
	}

	return nil
}

// CleanupExpiredKeys removes expired API keys
func (r *apiKeyRepository) CleanupExpiredKeys(ctx context.Context) error {
	// Soft delete expired keys
	result := r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&models.APIKey{})

	if result.Error != nil {
		return errors.NewInternalError("Failed to cleanup expired API keys")
	}

	return nil
}

// Helper methods

func (r *apiKeyRepository) generateAPIKey() (key, keyHash, keyPrefix string, err error) {
	// Generate random bytes for the key
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", "", err
	}

	// Create the key with prefix
	keyBody := hex.EncodeToString(bytes)
	key = fmt.Sprintf("n8n_%s", keyBody)

	// Extract prefix (first 12 characters)
	keyPrefix = key[:12]

	// Hash the key for storage
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", err
	}
	keyHash = string(hash)

	return key, keyHash, keyPrefix, nil
}

func (r *apiKeyRepository) gormToDomain(gormAPIKey *models.APIKey) *APIKey {
	return &APIKey{
		ID:             gormAPIKey.ID,
		UserID:         gormAPIKey.UserID,
		OrganizationID: gormAPIKey.OrganizationID,
		Name:           gormAPIKey.Name,
		Description:    gormAPIKey.Description,
		KeyHash:        gormAPIKey.KeyHash,
		KeyPrefix:      gormAPIKey.KeyPrefix,
		Permissions:    gormAPIKey.Permissions,
		Scopes:         gormAPIKey.Scopes,
		ExpiresAt:      gormAPIKey.ExpiresAt,
		LastUsedAt:     gormAPIKey.LastUsedAt,
		UsageCount:     gormAPIKey.UsageCount,
		IsActive:       gormAPIKey.IsActive,
		Metadata:       gormAPIKey.Metadata,
		CreatedAt:      gormAPIKey.CreatedAt,
		UpdatedAt:      gormAPIKey.UpdatedAt,
	}
}

func (r *apiKeyRepository) domainToGorm(apiKey *APIKey) *models.APIKey {
	return &models.APIKey{
		BaseModel: models.BaseModel{
			ID: apiKey.ID,
		},
		UserID:         apiKey.UserID,
		OrganizationID: apiKey.OrganizationID,
		Name:           apiKey.Name,
		Description:    apiKey.Description,
		KeyHash:        apiKey.KeyHash,
		KeyPrefix:      apiKey.KeyPrefix,
		Permissions:    apiKey.Permissions,
		Scopes:         apiKey.Scopes,
		ExpiresAt:      apiKey.ExpiresAt,
		LastUsedAt:     apiKey.LastUsedAt,
		UsageCount:     apiKey.UsageCount,
		IsActive:       apiKey.IsActive,
		Metadata:       apiKey.Metadata,
	}
}

// APIKeyMetrics represents API key usage metrics
type APIKeyMetrics struct {
	TotalAPIKeys       int64 `json:"total_api_keys"`
	ActiveAPIKeys      int64 `json:"active_api_keys"`
	ExpiredAPIKeys     int64 `json:"expired_api_keys"`
	TotalAPICallsToday int64 `json:"total_api_calls_today"`
}

// GetAPIKeyMetrics returns API key usage metrics
func (r *apiKeyRepository) GetAPIKeyMetrics(ctx context.Context, orgID string) (*APIKeyMetrics, error) {
	metrics := &APIKeyMetrics{}

	baseQuery := r.db.WithContext(ctx).Model(&models.APIKey{}).Where("deleted_at IS NULL")
	if orgID != "" {
		baseQuery = baseQuery.Where("organization_id = ?", orgID)
	}

	// Total API keys
	if err := baseQuery.Count(&metrics.TotalAPIKeys).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get total API keys count")
	}

	// Active API keys
	if err := baseQuery.Where("is_active = ? AND (expires_at IS NULL OR expires_at > ?)", true, time.Now()).
		Count(&metrics.ActiveAPIKeys).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get active API keys count")
	}

	// Expired API keys
	if err := baseQuery.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now()).
		Count(&metrics.ExpiredAPIKeys).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get expired API keys count")
	}

	// Total API calls today (simplified - this would typically be tracked separately)
	today := time.Now().Truncate(24 * time.Hour)
	var totalUsage int64
	if err := baseQuery.Where("last_used_at >= ?", today).
		Select("COALESCE(SUM(usage_count), 0)").
		Scan(&totalUsage).Error; err != nil {
		return nil, errors.NewInternalError("Failed to calculate API usage")
	}
	metrics.TotalAPICallsToday = totalUsage

	return metrics, nil
}