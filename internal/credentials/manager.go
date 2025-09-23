package credentials

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
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// CredentialType represents different types of credentials
type CredentialType string

const (
	CredentialTypeAPIKey    CredentialType = "api_key"
	CredentialTypeOAuth2    CredentialType = "oauth2"
	CredentialTypeBasicAuth CredentialType = "basic_auth"
	CredentialTypeDatabase  CredentialType = "database"
	CredentialTypeSMTP      CredentialType = "smtp"
	CredentialTypeSSH       CredentialType = "ssh"
	CredentialTypeAWS       CredentialType = "aws"
	CredentialTypeGCP       CredentialType = "gcp"
	CredentialTypeAzure     CredentialType = "azure"
	CredentialTypeCustom    CredentialType = "custom"
)

// SharingLevel represents credential sharing permissions
type SharingLevel string

const (
	SharingLevelPrivate SharingLevel = "private" // Only owner can use
	SharingLevelTeam    SharingLevel = "team"    // Team members can use
	SharingLevelPublic  SharingLevel = "public"  // Anyone can use
)

// Credential represents a stored credential
type Credential struct {
	ID          string         `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Type        CredentialType `json:"type" db:"type"`
	Description string         `json:"description" db:"description"`

	// Ownership and sharing
	OwnerID      string       `json:"owner_id" db:"owner_id"`
	TeamID       string       `json:"team_id" db:"team_id"`
	SharingLevel SharingLevel `json:"sharing_level" db:"sharing_level"`

	// Encrypted credential data
	EncryptedData string `json:"-" db:"encrypted_data"` // Never return in JSON
	DataHash      string `json:"-" db:"data_hash"`      // Hash for integrity check

	// Connection details for testing
	TestEndpoint string `json:"test_endpoint" db:"test_endpoint"`

	// Usage tracking
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
	UsageCount int        `json:"usage_count" db:"usage_count"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`

	// Metadata
	Tags      []string  `json:"tags" db:"tags"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Decrypted data (populated only when needed, never stored)
	Data map[string]interface{} `json:"data,omitempty" db:"-"`
}

// CredentialData represents the structure of credential data for different types
type CredentialData struct {
	// API Key credentials
	APIKey string `json:"api_key,omitempty"`
	Header string `json:"header,omitempty"` // Custom header name for API key

	// Basic Auth credentials
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// OAuth2 credentials
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	AuthURL      string `json:"auth_url,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// Database credentials
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Database string `json:"database,omitempty"`
	SSL      bool   `json:"ssl,omitempty"`

	// SMTP credentials
	SMTPHost string `json:"smtp_host,omitempty"`
	SMTPPort int    `json:"smtp_port,omitempty"`
	UseTLS   bool   `json:"use_tls,omitempty"`

	// SSH credentials
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`

	// Cloud provider credentials
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	Region          string `json:"region,omitempty"`
	ProjectID       string `json:"project_id,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`

	// Custom fields for flexible credential types
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// CredentialFilter represents filters for credential queries
type CredentialFilter struct {
	OwnerID      string
	TeamID       string
	Type         CredentialType
	SharingLevel SharingLevel
	IsActive     *bool
	Search       string
	Tags         []string
	Limit        int
	Offset       int
}

// Repository defines the credential storage interface
type Repository interface {
	Create(ctx context.Context, credential *Credential) error
	GetByID(ctx context.Context, id string) (*Credential, error)
	GetByOwnerID(ctx context.Context, ownerID string) ([]*Credential, error)
	List(ctx context.Context, filter *CredentialFilter) ([]*Credential, int, error)
	Update(ctx context.Context, credential *Credential) error
	Delete(ctx context.Context, id string) error
	MarkUsed(ctx context.Context, id string) error
}

// Manager handles credential operations with encryption
type Manager struct {
	repo       Repository
	encryptKey []byte
	logger     logger.Logger
}

// Config holds manager configuration
type Config struct {
	EncryptionKey string `json:"encryption_key" yaml:"encryption_key"`
}

// NewManager creates a new credential manager
func NewManager(repo Repository, config *Config, log logger.Logger) (*Manager, error) {
	if config.EncryptionKey == "" {
		return nil, errors.NewValidationError("encryption key is required")
	}

	// Create 32-byte key from the provided key
	hash := sha256.Sum256([]byte(config.EncryptionKey))
	encryptKey := hash[:]

	return &Manager{
		repo:       repo,
		encryptKey: encryptKey,
		logger:     log,
	}, nil
}

// Create creates a new credential with encrypted data
func (m *Manager) Create(ctx context.Context, userID, teamID string, req *CreateCredentialRequest) (*Credential, error) {
	// Validate request
	if err := m.validateCreateRequest(req); err != nil {
		return nil, err
	}

	// Create credential data structure
	credData := m.buildCredentialData(req)

	// Encrypt credential data
	encryptedData, err := m.encrypt(credData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential data: %w", err)
	}

	// Create data hash for integrity
	dataHash := m.createDataHash(credData)

	// Create credential record
	credential := &Credential{
		ID:            uuid.New().String(),
		Name:          req.Name,
		Type:          req.Type,
		Description:   req.Description,
		OwnerID:       userID,
		TeamID:        teamID,
		SharingLevel:  req.SharingLevel,
		EncryptedData: encryptedData,
		DataHash:      dataHash,
		TestEndpoint:  req.TestEndpoint,
		IsActive:      true,
		Tags:          req.Tags,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Save to repository
	if err := m.repo.Create(ctx, credential); err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	m.logger.Info("Credential created",
		"credential_id", credential.ID,
		"user_id", userID,
		"type", string(req.Type),
		"name", req.Name,
	)

	return credential, nil
}

// GetByID retrieves a credential by ID with access control
func (m *Manager) GetByID(ctx context.Context, userID, teamID, credentialID string) (*Credential, error) {
	credential, err := m.repo.GetByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Check access permissions
	if !m.canAccess(credential, userID, teamID) {
		return nil, errors.NewForbiddenError("Insufficient permissions to access credential")
	}

	return credential, nil
}

// List retrieves credentials accessible by a user
func (m *Manager) List(ctx context.Context, userID, teamID string, filter *CredentialFilter) ([]*Credential, int, error) {
	// Set user/team filters if not already set
	if filter.OwnerID == "" {
		filter.OwnerID = userID
	}
	if filter.TeamID == "" {
		filter.TeamID = teamID
	}

	credentials, _, err := m.repo.List(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// Filter by access permissions
	accessible := make([]*Credential, 0, len(credentials))
	for _, cred := range credentials {
		if m.canAccess(cred, userID, teamID) {
			accessible = append(accessible, cred)
		}
	}

	return accessible, len(accessible), nil
}

// TestCredential tests if a credential is valid and returns a result
func (m *Manager) TestCredential(ctx context.Context, credentialID, userID, teamID string) (*TestResult, error) {
	credData, err := m.GetDecryptedData(ctx, credentialID, userID, teamID)
	if err != nil {
		return nil, err
	}

	credential, err := m.repo.GetByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Create test result
	result := &TestResult{
		CredentialID: credentialID,
		TestedAt:     time.Now(),
	}

	// Test credential based on type
	switch credential.Type {
	case CredentialTypeAPIKey:
		err = m.testAPIKey(credential.TestEndpoint, credData)
	case CredentialTypeBasicAuth:
		err = m.testBasicAuth(credential.TestEndpoint, credData)
	case CredentialTypeDatabase:
		err = m.testDatabase(credData)
	case CredentialTypeOAuth2:
		err = errors.NewValidationError("OAuth2 testing requires browser interaction")
	default:
		err = errors.NewValidationError("Credential testing not implemented for this type")
	}

	if err != nil {
		result.Success = false
		result.Message = err.Error()
		result.Details = map[string]interface{}{
			"error": err.Error(),
			"type":  string(credential.Type),
		}
	} else {
		result.Success = true
		result.Message = "Credential test successful"
		result.Details = map[string]interface{}{
			"type": string(credential.Type),
		}
	}

	return result, nil
}

// GetUsageStats returns credential usage statistics for a user
func (m *Manager) GetUsageStats(ctx context.Context, userID string) (map[string]interface{}, error) {
	// Return basic stats - in a real implementation this would query the database
	return map[string]interface{}{
		"total_credentials": 0,
		"used_credentials": 0,
		"by_type": map[string]int{},
	}, nil
}

// ValidateCredentials validates that the given credential IDs exist and are accessible by the team
func (m *Manager) ValidateCredentials(ctx context.Context, credentialIDs []string, teamID string) error {
	for _, credID := range credentialIDs {
		credential, err := m.repo.GetByID(ctx, credID)
		if err != nil {
			return fmt.Errorf("credential %s not found: %w", credID, err)
		}
		if credential.TeamID != teamID && credential.SharingLevel != SharingLevelPublic {
			return errors.NewForbiddenError(fmt.Sprintf("credential %s not accessible", credID))
		}
	}
	return nil
}

// GetCredentialsByIDs retrieves credentials by their IDs and returns their decrypted data
func (m *Manager) GetCredentialsByIDs(ctx context.Context, credentialIDs []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, credID := range credentialIDs {
		credential, err := m.repo.GetByID(ctx, credID)
		if err != nil {
			m.logger.Warn("Credential not found", "credential_id", credID, "error", err)
			continue
		}
		
		// Decrypt credential data
		if err := m.decryptCredential(credential); err != nil {
			m.logger.Error("Failed to decrypt credential", "credential_id", credID, "error", err)
			continue
		}
		
		result[credID] = credential.Data
	}
	return result, nil
}

// Update updates a credential
func (m *Manager) Update(ctx context.Context, userID, teamID, credentialID string, req *UpdateCredentialRequest) (*Credential, error) {
	// Get existing credential
	credential, err := m.repo.GetByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Check permissions
	if !m.canEdit(credential, userID, teamID) {
		return nil, errors.NewForbiddenError("Insufficient permissions to edit credential")
	}

	// Update fields
	if req.Name != "" {
		credential.Name = req.Name
	}
	if req.Description != "" {
		credential.Description = req.Description
	}
	if req.SharingLevel != "" {
		credential.SharingLevel = req.SharingLevel
	}
	if req.TestEndpoint != "" {
		credential.TestEndpoint = req.TestEndpoint
	}
	if req.Tags != nil {
		credential.Tags = req.Tags
	}

	// Update credential data if provided
	if req.Data != nil {
		credData := m.buildCredentialDataFromMap(req.Data)
		encryptedData, err := m.encrypt(credData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt updated credential data: %w", err)
		}
		credential.EncryptedData = encryptedData
		credential.DataHash = m.createDataHash(credData)
	}

	credential.UpdatedAt = time.Now()

	// Save updated credential
	if err := m.repo.Update(ctx, credential); err != nil {
		return nil, fmt.Errorf("failed to update credential: %w", err)
	}

	m.logger.Info("Credential updated",
		"credential_id", credentialID,
		"user_id", userID,
		"name", credential.Name,
	)

	return credential, nil
}

// Delete removes a credential
func (m *Manager) Delete(ctx context.Context, userID, teamID, credentialID string) error {
	// Get credential to check permissions
	credential, err := m.repo.GetByID(ctx, credentialID)
	if err != nil {
		return err
	}

	// Check permissions - only owner can delete
	if credential.OwnerID != userID {
		return errors.NewForbiddenError("Only credential owner can delete")
	}

	// Delete from repository
	if err := m.repo.Delete(ctx, credentialID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	m.logger.Info("Credential deleted",
		"credential_id", credentialID,
		"user_id", userID,
		"name", credential.Name,
	)

	return nil
}

// GetDecryptedData retrieves and decrypts credential data for use
func (m *Manager) GetDecryptedData(ctx context.Context, credentialID, userID, teamID string) (*CredentialData, error) {
	credential, err := m.repo.GetByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Check access permissions
	if !m.canAccess(credential, userID, teamID) {
		return nil, errors.NewForbiddenError("Insufficient permissions to access credential")
	}

	// Decrypt credential data
	if err := m.decryptCredential(credential); err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Mark as used
	go func() {
		if err := m.repo.MarkUsed(context.Background(), credentialID); err != nil {
			m.logger.Error("Failed to mark credential as used", "error", err, "credential_id", credentialID)
		}
	}()

	// Convert to CredentialData struct
	credData := &CredentialData{}
	if credential.Data != nil {
		jsonData, err := json.Marshal(credential.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential data: %w", err)
		}
		if err := json.Unmarshal(jsonData, credData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential data: %w", err)
		}
	}

	return credData, nil
}



// Helper methods

// Helper methods

func (m *Manager) encrypt(data *CredentialData) (string, error) {
	// Convert to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(m.encryptKey)
	if err != nil {
		return "", err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (m *Manager) decrypt(encryptedData string) (*CredentialData, error) {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	// Create cipher
	block, err := aes.NewCipher(m.encryptKey)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.NewValidationError("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var data CredentialData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (m *Manager) decryptCredential(credential *Credential) error {
	if credential.EncryptedData == "" {
		return nil
	}

	data, err := m.decrypt(credential.EncryptedData)
	if err != nil {
		return err
	}

	// Convert to map for flexible access
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &dataMap); err != nil {
		return err
	}

	credential.Data = dataMap
	return nil
}

func (m *Manager) createDataHash(data *CredentialData) string {
	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (m *Manager) canAccess(credential *Credential, userID, teamID string) bool {
	// Owner can always access
	if credential.OwnerID == userID {
		return true
	}

	// Check sharing level
	switch credential.SharingLevel {
	case SharingLevelPublic:
		return true
	case SharingLevelTeam:
		return credential.TeamID == teamID
	case SharingLevelPrivate:
		return false
	default:
		return false
	}
}

func (m *Manager) canEdit(credential *Credential, userID, teamID string) bool {
	// Only owner can edit
	return credential.OwnerID == userID
}

func (m *Manager) validateCreateRequest(req *CreateCredentialRequest) error {
	if req.Name == "" {
		return errors.NewValidationError("Name is required")
	}
	if req.Type == "" {
		return errors.NewValidationError("Type is required")
	}
	if len(req.Data) == 0 {
		return errors.NewValidationError("Credential data is required")
	}
	return nil
}

func (m *Manager) buildCredentialData(req *CreateCredentialRequest) *CredentialData {
	return m.buildCredentialDataFromMap(req.Data)
}

func (m *Manager) buildCredentialDataFromMap(data map[string]interface{}) *CredentialData {
	credData := &CredentialData{}
	jsonData, _ := json.Marshal(data)
	if err := json.Unmarshal(jsonData, credData); err != nil {
		m.logger.Error("Failed to unmarshal credential data from map", "error", err)
	}
	return credData
}

// Test methods for different credential types

func (m *Manager) testAPIKey(endpoint string, data *CredentialData) error {
	if endpoint == "" {
		return errors.NewValidationError("Test endpoint required for API key testing")
	}
	// Implementation would make HTTP request with API key
	m.logger.Info("Testing API key credential", "endpoint", endpoint)
	return nil
}

func (m *Manager) testBasicAuth(endpoint string, data *CredentialData) error {
	if endpoint == "" {
		return errors.NewValidationError("Test endpoint required for basic auth testing")
	}
	// Implementation would make HTTP request with basic auth
	m.logger.Info("Testing basic auth credential", "endpoint", endpoint)
	return nil
}

func (m *Manager) testDatabase(data *CredentialData) error {
	// Implementation would test database connection
	m.logger.Info("Testing database credential", "host", data.Host, "port", data.Port)
	return nil
}

// Request/Response structures

type CreateCredentialRequest struct {
	Name         string                 `json:"name"`
	Type         CredentialType         `json:"type"`
	Description  string                 `json:"description"`
	SharingLevel SharingLevel           `json:"sharing_level"`
	TestEndpoint string                 `json:"test_endpoint"`
	Tags         []string               `json:"tags"`
	Data         map[string]interface{} `json:"data"`
}

type UpdateCredentialRequest struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	SharingLevel SharingLevel           `json:"sharing_level"`
	TestEndpoint string                 `json:"test_endpoint"`
	Tags         []string               `json:"tags"`
	Data         map[string]interface{} `json:"data"`
}

// TestResult represents the result of credential testing
type TestResult struct {
	CredentialID string                 `json:"credential_id"`
	Success      bool                   `json:"success"`
	Message      string                 `json:"message"`
	Details      map[string]interface{} `json:"details"`
	TestedAt     time.Time              `json:"tested_at"`
}
