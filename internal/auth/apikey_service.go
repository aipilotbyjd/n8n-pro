package auth

import (
	"context"
	"fmt"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// APIKeyService provides API key management operations
type APIKeyService struct {
	apiKeyRepo APIKeyRepository
	db         *gorm.DB
	logger     logger.Logger
}

// NewAPIKeyService creates a new API key service
func NewAPIKeyService(apiKeyRepo APIKeyRepository, db *gorm.DB, logger logger.Logger) *APIKeyService {
	return &APIKeyService{
		apiKeyRepo: apiKeyRepo,
		db:         db,
		logger:     logger,
	}
}

// CreateAPIKeyRequest represents API key creation request
type CreateAPIKeyRequest struct {
	UserID         string    `json:"user_id" validate:"required"`
	OrganizationID string    `json:"organization_id" validate:"required"`
	Name           string    `json:"name" validate:"required,min=1,max=255"`
	Description    string    `json:"description,omitempty"`
	Permissions    []string  `json:"permissions" validate:"required"`
	Scopes         []string  `json:"scopes,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// CreateAPIKeyResponse represents API key creation response
type CreateAPIKeyResponse struct {
	APIKey *APIKey `json:"api_key"`
	RawKey string  `json:"raw_key"` // Only returned once during creation
}

// UpdateAPIKeyRequest represents API key update request
type UpdateAPIKeyRequest struct {
	Name        *string                 `json:"name,omitempty"`
	Description *string                 `json:"description,omitempty"`
	Permissions []string                `json:"permissions,omitempty"`
	Scopes      []string                `json:"scopes,omitempty"`
	ExpiresAt   *time.Time              `json:"expires_at,omitempty"`
	Metadata    map[string]interface{}  `json:"metadata,omitempty"`
}

// APIKeyListFilter represents filtering options for API key listing
type APIKeyListFilter struct {
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	IsActive       *bool  `json:"is_active,omitempty"`
	ExpiredOnly    bool   `json:"expired_only,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
}

// CreateAPIKey creates a new API key
func (s *APIKeyService) CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	// Validate permissions
	if err := s.validatePermissions(req.Permissions); err != nil {
		return nil, err
	}

	// Check if user exists and belongs to organization
	if err := s.validateUserOrganization(ctx, req.UserID, req.OrganizationID); err != nil {
		return nil, err
	}

	// Check if name is unique for the user
	if err := s.validateUniqueKeyName(ctx, req.UserID, req.Name); err != nil {
		return nil, err
	}

	// Set default expiration if not provided (90 days)
	if req.ExpiresAt == nil {
		expiresAt := time.Now().Add(90 * 24 * time.Hour)
		req.ExpiresAt = &expiresAt
	}

	// Create API key domain object
	apiKey := &APIKey{
		ID:             uuid.New().String(),
		UserID:         req.UserID,
		OrganizationID: req.OrganizationID,
		Name:           req.Name,
		Description:    req.Description,
		Permissions:    req.Permissions,
		Scopes:         req.Scopes,
		ExpiresAt:      req.ExpiresAt,
		IsActive:       true,
		Metadata:       req.Metadata,
	}

	// Create API key in repository (returns the key and raw key)
	createdKey, rawKey, err := s.apiKeyRepo.Create(ctx, apiKey)
	if err != nil {
		s.logger.Error("Failed to create API key", "error", err, "user_id", req.UserID)
		return nil, errors.NewInternalError("Failed to create API key")
	}

	s.logger.Info("API key created successfully", 
		"api_key_id", createdKey.ID, 
		"user_id", req.UserID, 
		"name", req.Name,
	)

	return &CreateAPIKeyResponse{
		APIKey: createdKey,
		RawKey: rawKey,
	}, nil
}

// GetAPIKey retrieves an API key by ID
func (s *APIKeyService) GetAPIKey(ctx context.Context, keyID, userID string) (*APIKey, error) {
	apiKey, err := s.apiKeyRepo.FindByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, errors.NewForbiddenError("Access denied to API key")
	}

	return apiKey, nil
}

// GetUserAPIKeys retrieves all API keys for a user
func (s *APIKeyService) GetUserAPIKeys(ctx context.Context, userID string, limit, offset int) ([]*APIKey, int64, error) {
	return s.apiKeyRepo.FindByUserID(ctx, userID, limit, offset)
}

// GetOrganizationAPIKeys retrieves all API keys for an organization
func (s *APIKeyService) GetOrganizationAPIKeys(ctx context.Context, orgID string, limit, offset int) ([]*APIKey, int64, error) {
	return s.apiKeyRepo.FindByOrganizationID(ctx, orgID, limit, offset)
}

// UpdateAPIKey updates an API key
func (s *APIKeyService) UpdateAPIKey(ctx context.Context, keyID, userID string, req *UpdateAPIKeyRequest) (*APIKey, error) {
	// Get existing API key
	apiKey, err := s.GetAPIKey(ctx, keyID, userID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Name != nil && *req.Name != apiKey.Name {
		// Check if new name is unique
		if err := s.validateUniqueKeyName(ctx, userID, *req.Name); err != nil {
			return nil, err
		}
		apiKey.Name = *req.Name
	}

	if req.Description != nil {
		apiKey.Description = *req.Description
	}

	if req.Permissions != nil {
		if err := s.validatePermissions(req.Permissions); err != nil {
			return nil, err
		}
		apiKey.Permissions = req.Permissions
	}

	if req.Scopes != nil {
		apiKey.Scopes = req.Scopes
	}

	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}

	if req.Metadata != nil {
		apiKey.Metadata = req.Metadata
	}

	// Save changes
	if err := s.apiKeyRepo.Update(ctx, apiKey); err != nil {
		s.logger.Error("Failed to update API key", "error", err, "api_key_id", keyID)
		return nil, errors.NewInternalError("Failed to update API key")
	}

	s.logger.Info("API key updated successfully", "api_key_id", keyID, "user_id", userID)
	return apiKey, nil
}

// RevokeAPIKey revokes an API key
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	// Verify ownership
	if _, err := s.GetAPIKey(ctx, keyID, userID); err != nil {
		return err
	}

	// Revoke the key
	if err := s.apiKeyRepo.Revoke(ctx, keyID); err != nil {
		s.logger.Error("Failed to revoke API key", "error", err, "api_key_id", keyID)
		return errors.NewInternalError("Failed to revoke API key")
	}

	s.logger.Info("API key revoked successfully", "api_key_id", keyID, "user_id", userID)
	return nil
}

// ValidateAPIKey validates an API key and returns its information
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKey, error) {
	apiKey, err := s.apiKeyRepo.FindByKey(ctx, rawKey)
	if err != nil {
		return nil, err
	}

	// Additional validations
	if !apiKey.IsActive {
		return nil, errors.NewUnauthorizedError("API key is not active")
	}

	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, errors.NewUnauthorizedError("API key has expired")
	}

	// Update last used (async to not slow down the request)
	go func() {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.apiKeyRepo.UpdateLastUsed(updateCtx, apiKey.ID); err != nil {
			s.logger.Error("Failed to update API key last used", "error", err, "api_key_id", apiKey.ID)
		}
	}()

	return apiKey, nil
}

// GetAPIKeyMetrics returns API key usage metrics
func (s *APIKeyService) GetAPIKeyMetrics(ctx context.Context, orgID string) (*APIKeyMetrics, error) {
	return s.apiKeyRepo.GetAPIKeyMetrics(ctx, orgID)
}

// CleanupExpiredAPIKeys removes expired API keys
func (s *APIKeyService) CleanupExpiredAPIKeys(ctx context.Context) error {
	if err := s.apiKeyRepo.CleanupExpiredKeys(ctx); err != nil {
		s.logger.Error("Failed to cleanup expired API keys", "error", err)
		return err
	}

	s.logger.Info("Expired API keys cleaned up successfully")
	return nil
}

// RotateAPIKey generates a new key for an existing API key
func (s *APIKeyService) RotateAPIKey(ctx context.Context, keyID, userID string) (*CreateAPIKeyResponse, error) {
	// Get existing API key
	existingKey, err := s.GetAPIKey(ctx, keyID, userID)
	if err != nil {
		return nil, err
	}

	// Create a new API key with same properties
	req := &CreateAPIKeyRequest{
		UserID:         existingKey.UserID,
		OrganizationID: existingKey.OrganizationID,
		Name:           existingKey.Name + "_rotated",
		Description:    existingKey.Description,
		Permissions:    existingKey.Permissions,
		Scopes:         existingKey.Scopes,
		ExpiresAt:      existingKey.ExpiresAt,
		Metadata:       existingKey.Metadata,
	}

	// Create new key
	newKey, err := s.CreateAPIKey(ctx, req)
	if err != nil {
		return nil, err
	}

	// Revoke old key
	if err := s.RevokeAPIKey(ctx, keyID, userID); err != nil {
		s.logger.Error("Failed to revoke old API key during rotation", "error", err, "old_key_id", keyID)
		// Don't fail the rotation if we can't revoke the old key
	}

	s.logger.Info("API key rotated successfully", 
		"old_key_id", keyID, 
		"new_key_id", newKey.APIKey.ID, 
		"user_id", userID,
	)

	return newKey, nil
}

// Helper methods

func (s *APIKeyService) validatePermissions(permissions []string) error {
	validPermissions := map[string]bool{
		string(PermissionUsersRead):      true,
		string(PermissionUsersWrite):     true,
		string(PermissionUsersDelete):    true,
		string(PermissionWorkflowsRead):  true,
		string(PermissionWorkflowsWrite): true,
		string(PermissionWorkflowsDelete): true,
		string(PermissionWorkflowsShare): true,
		string(PermissionExecutionsRead): true,
		string(PermissionExecutionsWrite): true,
		string(PermissionExecutionsDelete): true,
		string(PermissionCredentialsRead): true,
		string(PermissionCredentialsWrite): true,
		string(PermissionCredentialsDelete): true,
		string(PermissionCredentialsShare): true,
		string(PermissionOrganizationRead): true,
		string(PermissionOrganizationWrite): true,
		string(PermissionTeamsRead):       true,
		string(PermissionTeamsWrite):      true,
		string(PermissionTeamsDelete):     true,
		string(PermissionAPIKeys):         true,
	}

	for _, permission := range permissions {
		if !validPermissions[permission] {
			return errors.NewValidationError(fmt.Sprintf("Invalid permission: %s", permission))
		}
	}

	return nil
}

func (s *APIKeyService) validateUserOrganization(ctx context.Context, userID, orgID string) error {
	var count int64
	if err := s.db.Model(&models.User{}).
		Where("id = ? AND organization_id = ? AND deleted_at IS NULL", userID, orgID).
		Count(&count).Error; err != nil {
		return errors.NewInternalError("Failed to validate user organization")
	}

	if count == 0 {
		return errors.NewValidationError("User does not belong to the specified organization")
	}

	return nil
}

func (s *APIKeyService) validateUniqueKeyName(ctx context.Context, userID, name string) error {
	var count int64
	if err := s.db.Model(&models.APIKey{}).
		Where("user_id = ? AND name = ? AND deleted_at IS NULL", userID, name).
		Count(&count).Error; err != nil {
		return errors.NewInternalError("Failed to validate API key name uniqueness")
	}

	if count > 0 {
		return errors.NewValidationError("API key name must be unique for the user")
	}

	return nil
}

// Batch operations

// CreateBulkAPIKeys creates multiple API keys for a user
func (s *APIKeyService) CreateBulkAPIKeys(ctx context.Context, requests []*CreateAPIKeyRequest) ([]*CreateAPIKeyResponse, error) {
	var responses []*CreateAPIKeyResponse
	var errors []error

	// Process each request
	for i, req := range requests {
		response, err := s.CreateAPIKey(ctx, req)
		if err != nil {
			s.logger.Error("Failed to create API key in bulk operation", 
				"error", err, 
				"index", i, 
				"user_id", req.UserID,
			)
			errors = append(errors, fmt.Errorf("request %d: %w", i, err))
			continue
		}
		responses = append(responses, response)
	}

	if len(errors) > 0 {
		return responses, fmt.Errorf("bulk creation completed with errors: %v", errors)
	}

	return responses, nil
}

// RevokeBulkAPIKeys revokes multiple API keys
func (s *APIKeyService) RevokeBulkAPIKeys(ctx context.Context, keyIDs []string, userID string) error {
	var errors []error

	for _, keyID := range keyIDs {
		if err := s.RevokeAPIKey(ctx, keyID, userID); err != nil {
			s.logger.Error("Failed to revoke API key in bulk operation", 
				"error", err, 
				"api_key_id", keyID, 
				"user_id", userID,
			)
			errors = append(errors, fmt.Errorf("key %s: %w", keyID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("bulk revocation completed with errors: %v", errors)
	}

	return nil
}

// ListAPIKeysWithFilter lists API keys with advanced filtering
func (s *APIKeyService) ListAPIKeysWithFilter(ctx context.Context, filter *APIKeyListFilter) ([]*APIKey, int64, error) {
	// This would require extending the repository with more advanced filtering
	// For now, implement basic filtering
	if filter.UserID != "" {
		return s.apiKeyRepo.FindByUserID(ctx, filter.UserID, filter.Limit, filter.Offset)
	}
	
	if filter.OrganizationID != "" {
		return s.apiKeyRepo.FindByOrganizationID(ctx, filter.OrganizationID, filter.Limit, filter.Offset)
	}

	return nil, 0, errors.NewValidationError("Either UserID or OrganizationID must be specified")
}

// GetAPIKeyUsageStats returns usage statistics for an API key
func (s *APIKeyService) GetAPIKeyUsageStats(ctx context.Context, keyID, userID string) (map[string]interface{}, error) {
	apiKey, err := s.GetAPIKey(ctx, keyID, userID)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_usage":    apiKey.UsageCount,
		"last_used_at":   apiKey.LastUsedAt,
		"created_at":     apiKey.CreatedAt,
		"is_active":      apiKey.IsActive,
		"expires_at":     apiKey.ExpiresAt,
		"days_until_expiry": nil,
	}

	if apiKey.ExpiresAt != nil {
		daysUntilExpiry := time.Until(*apiKey.ExpiresAt).Hours() / 24
		stats["days_until_expiry"] = int(daysUntilExpiry)
	}

	return stats, nil
}