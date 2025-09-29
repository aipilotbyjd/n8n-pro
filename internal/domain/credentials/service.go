package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

// Credential represents user credentials
type Credential struct {
	ID          string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string                 `json:"name" gorm:"not null;size:255"`
	Type        string                 `json:"type" gorm:"not null;size:100"`
	OwnerID     string                 `json:"owner_id" gorm:"type:uuid;not null;index"`
	TeamID      string                 `json:"team_id" gorm:"type:uuid;index"`
	Data        map[string]interface{} `json:"-" gorm:"type:jsonb;not null"` // Encrypted data
	Encrypted   bool                   `json:"-" gorm:"default:true"`
	IsDefault   bool                   `json:"is_default" gorm:"default:false"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// CredentialType represents different types of credentials
type CredentialType string

const (
	CredentialTypeAPIKey    CredentialType = "api_key"
	CredentialTypeOAuth     CredentialType = "oauth"
	CredentialTypeUsername  CredentialType = "username_password"
	CredentialTypeCertificate CredentialType = "certificate"
	CredentialTypeSSH       CredentialType = "ssh"
	CredentialTypeBearer    CredentialType = "bearer_token"
)

// Service handles credential operations
type Service struct {
	repo        Repository
	encryption  *EncryptionService
	logger      logger.Logger
}

// Repository defines the credential data access interface
type Repository interface {
	Create(ctx context.Context, cred *Credential) error
	GetByID(ctx context.Context, id string) (*Credential, error)
	GetByOwner(ctx context.Context, ownerID string) ([]*Credential, error)
	GetByTeam(ctx context.Context, teamID string) ([]*Credential, error)
	GetByName(ctx context.Context, ownerID, name string) (*Credential, error)
	Update(ctx context.Context, cred *Credential) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *ListFilter) ([]*Credential, int64, error)
	Search(ctx context.Context, query string) ([]*Credential, error)
}

// ListFilter represents filters for listing credentials
type ListFilter struct {
	OwnerID    string
	TeamID     string
	Type       string
	IsDefault  *bool
	SearchTerm string
	Limit      int
	Offset     int
}

// NewService creates a new credential service
func NewService(repo Repository, encryption *EncryptionService, logger logger.Logger) *Service {
	return &Service{
		repo:       repo,
		encryption: encryption,
		logger:     logger,
	}
}

// CreateCredential creates a new credential
func (s *Service) CreateCredential(ctx context.Context, name, credentialType, ownerID, teamID string, data map[string]interface{}) (*Credential, error) {
	s.logger.Info("Creating credential", "name", name, "type", credentialType, "owner_id", ownerID)

	// Validate input
	if err := s.validateInput(name, credentialType, ownerID, data); err != nil {
		return nil, err
	}

	// Encrypt the data
	encryptedData, err := s.encryption.Encrypt(data)
	if err != nil {
		s.logger.Error("Failed to encrypt credential data", "error", err)
		return nil, err
	}

	// Create credential
	cred := &Credential{
		ID:        uuid.New().String(),
		Name:      name,
		Type:      credentialType,
		OwnerID:   ownerID,
		TeamID:    teamID,
		Data:      encryptedData,
		Encrypted: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.repo.Create(ctx, cred); err != nil {
		s.logger.Error("Failed to create credential", "name", name, "error", err)
		return nil, err
	}

	s.logger.Info("Credential created successfully", "credential_id", cred.ID)

	return cred, nil
}

// GetCredential retrieves a credential by ID
func (s *Service) GetCredential(ctx context.Context, id string) (*Credential, error) {
	cred, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get credential", "credential_id", id, "error", err)
		return nil, err
	}

	// Decrypt the data if it's encrypted
	if cred.Encrypted {
		decryptedData, err := s.encryption.Decrypt(cred.Data)
		if err != nil {
			s.logger.Error("Failed to decrypt credential data", "credential_id", id, "error", err)
			return nil, err
		}
		cred.Data = decryptedData
	}

	return cred, nil
}

// GetCredentialsByOwner retrieves credentials for an owner
func (s *Service) GetCredentialsByOwner(ctx context.Context, ownerID string) ([]*Credential, error) {
	creds, err := s.repo.GetByOwner(ctx, ownerID)
	if err != nil {
		s.logger.Error("Failed to get credentials by owner", "owner_id", ownerID, "error", err)
		return nil, err
	}

	// Decrypt data for each credential
	for _, cred := range creds {
		if cred.Encrypted {
			decryptedData, err := s.encryption.Decrypt(cred.Data)
			if err != nil {
				s.logger.Error("Failed to decrypt credential data", "credential_id", cred.ID, "error", err)
				// Continue with other credentials
				continue
			}
			cred.Data = decryptedData
		}
	}

	return creds, nil
}

// GetCredentialsByTeam retrieves credentials for a team
func (s *Service) GetCredentialsByTeam(ctx context.Context, teamID string) ([]*Credential, error) {
	creds, err := s.repo.GetByTeam(ctx, teamID)
	if err != nil {
		s.logger.Error("Failed to get credentials by team", "team_id", teamID, "error", err)
		return nil, err
	}

	// Decrypt data for each credential
	for _, cred := range creds {
		if cred.Encrypted {
			decryptedData, err := s.encryption.Decrypt(cred.Data)
			if err != nil {
				s.logger.Error("Failed to decrypt credential data", "credential_id", cred.ID, "error", err)
				// Continue with other credentials
				continue
			}
			cred.Data = decryptedData
		}
	}

	return creds, nil
}

// UpdateCredential updates an existing credential
func (s *Service) UpdateCredential(ctx context.Context, id, name string, data map[string]interface{}) error {
	cred, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get credential for update", "credential_id", id, "error", err)
		return err
	}

	// Update fields
	if name != "" {
		cred.Name = name
	}

	if data != nil {
		// Encrypt the new data
		encryptedData, err := s.encryption.Encrypt(data)
		if err != nil {
			s.logger.Error("Failed to encrypt credential data", "credential_id", id, "error", err)
			return err
		}
		cred.Data = encryptedData
	}

	cred.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, cred); err != nil {
		s.logger.Error("Failed to update credential", "credential_id", id, "error", err)
		return err
	}

	s.logger.Info("Credential updated successfully", "credential_id", id)

	return nil
}

// DeleteCredential deletes a credential by ID
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete credential", "credential_id", id, "error", err)
		return err
	}

	s.logger.Info("Credential deleted successfully", "credential_id", id)

	return nil
}

// ListCredentials retrieves credentials based on filters
func (s *Service) ListCredentials(ctx context.Context, filter *ListFilter) ([]*Credential, int64, error) {
	creds, total, err := s.repo.List(ctx, filter)
	if err != nil {
		s.logger.Error("Failed to list credentials", "error", err)
		return nil, 0, err
	}

	// Decrypt data for each credential if needed
	for _, cred := range creds {
		if cred.Encrypted {
			decryptedData, err := s.encryption.Decrypt(cred.Data)
			if err != nil {
				s.logger.Error("Failed to decrypt credential data", "credential_id", cred.ID, "error", err)
				// Continue with other credentials
				continue
			}
			cred.Data = decryptedData
		}
	}

	return creds, total, nil
}

// validateInput validates credential input
func (s *Service) validateInput(name, credentialType, ownerID string, data map[string]interface{}) error {
	if name == "" {
		return ValidationError("credential name is required")
	}

	if credentialType == "" {
		return ValidationError("credential type is required")
	}

	if ownerID == "" {
		return ValidationError("owner ID is required")
	}

	if len(name) > 255 {
		return ValidationError("credential name cannot exceed 255 characters")
	}

	if data == nil || len(data) == 0 {
		return ValidationError("credential data is required")
	}

	return nil
}

// EncryptionService handles credential encryption/decryption
type EncryptionService struct {
	encryptionKey []byte
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService(encryptionKey string) *EncryptionService {
	// Derive key from provided string
	key := deriveKey([]byte(encryptionKey))
	return &EncryptionService{
		encryptionKey: key,
	}
}

// deriveKey derives a key from the provided password
func deriveKey(password []byte) []byte {
	salt := []byte("n8n-pro-salt") // In production, use a random salt per credential
	return pbkdf2.Key(password, salt, 10000, 32, sha256.New)
}

// Encrypt encrypts credential data
func (e *EncryptionService) Encrypt(data map[string]interface{}) (map[string]interface{}, error) {
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Encrypt the data
	encryptedData, err := e.encryptData(jsonData)
	if err != nil {
		return nil, err
	}

	// Return as map
	return map[string]interface{}{
		"encrypted": true,
		"data":      encryptedData,
	}, nil
}

// Decrypt decrypts credential data
func (e *EncryptionService) Decrypt(encryptedData map[string]interface{}) (map[string]interface{}, error) {
	if encryptedData["encrypted"] != true {
		return encryptedData, nil
	}

	encryptedStr, ok := encryptedData["data"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid encrypted data format")
	}

	// Decrypt the data
	decryptedData, err := e.decryptData(encryptedStr)
	if err != nil {
		return nil, err
	}

	// Convert back to map
	var result map[string]interface{}
	if err := json.Unmarshal(decryptedData, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// encryptData encrypts the provided data using AES
func (e *EncryptionService) encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return "", err
	}

	// Create a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Create stream cipher
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt the data
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Prepend IV to encrypted data
	result := append(iv, encrypted...)

	// Encode to hex string
	return hex.EncodeToString(result), nil
}

// decryptData decrypts the provided data using AES
func (e *EncryptionService) decryptData(encryptedStr string) ([]byte, error) {
	// Decode from hex string
	encrypted, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return nil, err
	}

	// Extract IV (first 16 bytes)
	if len(encrypted) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	// Create cipher
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, err
	}

	// Create stream cipher
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt the data
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	return decrypted, nil
}

// ValidateCredential validates credential data for a specific type
func (s *Service) ValidateCredential(cred *Credential) error {
	switch CredentialType(cred.Type) {
	case CredentialTypeAPIKey:
		return s.validateAPIKey(cred.Data)
	case CredentialTypeOAuth:
		return s.validateOAuth(cred.Data)
	case CredentialTypeUsername:
		return s.validateUsernamePassword(cred.Data)
	case CredentialTypeCertificate:
		return s.validateCertificate(cred.Data)
	case CredentialTypeSSH:
		return s.validateSSH(cred.Data)
	case CredentialTypeBearer:
		return s.validateBearerToken(cred.Data)
	default:
		return ValidationError(fmt.Sprintf("unsupported credential type: %s", cred.Type))
	}
}

// validateAPIKey validates API key credential
func (s *Service) validateAPIKey(data map[string]interface{}) error {
	if apiKey, exists := data["apiKey"]; !exists || apiKey == "" {
		return ValidationError("API key is required")
	}
	return nil
}

// validateOAuth validates OAuth credential
func (s *Service) validateOAuth(data map[string]interface{}) error {
	if clientID, exists := data["clientId"]; !exists || clientID == "" {
		return ValidationError("OAuth client ID is required")
	}
	if clientSecret, exists := data["clientSecret"]; !exists || clientSecret == "" {
		return ValidationError("OAuth client secret is required")
	}
	return nil
}

// validateUsernamePassword validates username/password credential
func (s *Service) validateUsernamePassword(data map[string]interface{}) error {
	if username, exists := data["username"]; !exists || username == "" {
		return ValidationError("username is required")
	}
	if password, exists := data["password"]; !exists || password == "" {
		return ValidationError("password is required")
	}
	return nil
}

// validateCertificate validates certificate credential
func (s *Service) validateCertificate(data map[string]interface{}) error {
	if cert, exists := data["certificate"]; !exists || cert == "" {
		return ValidationError("certificate is required")
	}
	return nil
}

// validateSSH validates SSH credential
func (s *Service) validateSSH(data map[string]interface{}) error {
	if privateKey, exists := data["privateKey"]; !exists || privateKey == "" {
		return ValidationError("SSH private key is required")
	}
	return nil
}

// validateBearerToken validates bearer token credential
func (s *Service) validateBearerToken(data map[string]interface{}) error {
	if token, exists := data["token"]; !exists || token == "" {
		return ValidationError("bearer token is required")
	}
	return nil
}

// ValidationError represents a validation error
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}

// Import/Export functionality
func (s *Service) ExportCredential(ctx context.Context, credentialID string) ([]byte, error) {
	cred, err := s.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Export credential in a standard format
	exportData := map[string]interface{}{
		"id":        cred.ID,
		"name":      cred.Name,
		"type":      cred.Type,
		"owner_id":  cred.OwnerID,
		"team_id":   cred.TeamID,
		"data":      cred.Data,
		"created_at": cred.CreatedAt,
		"updated_at": cred.UpdatedAt,
	}

	return json.MarshalIndent(exportData, "", "  ")
}

func (s *Service) ImportCredential(ctx context.Context, ownerID, teamID string, data []byte) error {
	var importData map[string]interface{}
	if err := json.Unmarshal(data, &importData); err != nil {
		return err
	}

	name, _ := importData["name"].(string)
	credType, _ := importData["type"].(string)
	credData, _ := importData["data"].(map[string]interface{})

	_, err := s.CreateCredential(ctx, name, credType, ownerID, teamID, credData)
	return err
}