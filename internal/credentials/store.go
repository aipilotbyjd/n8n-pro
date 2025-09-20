package credentials

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store implements credential storage using PostgreSQL
type Store struct {
	db     *pgxpool.Pool
	logger logger.Logger
}

// NewStore creates a new credential store
func NewStore(db *pgxpool.Pool, log logger.Logger) *Store {
	return &Store{
		db:     db,
		logger: log,
	}
}

// Create stores a new credential
func (s *Store) Create(ctx context.Context, credential *Credential) error {
	query := `
		INSERT INTO credentials (
			id, name, type, description, owner_id, team_id, sharing_level,
			encrypted_data, data_hash, test_endpoint, is_active, expires_at,
			tags, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`

	tagsJSON, err := json.Marshal(credential.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = s.db.Exec(ctx, query,
		credential.ID,
		credential.Name,
		credential.Type,
		credential.Description,
		credential.OwnerID,
		credential.TeamID,
		credential.SharingLevel,
		credential.EncryptedData,
		credential.DataHash,
		credential.TestEndpoint,
		credential.IsActive,
		credential.ExpiresAt,
		string(tagsJSON),
		credential.CreatedAt,
		credential.UpdatedAt,
	)

	if err != nil {
		s.logger.Error("Failed to create credential", "error", err, "credential_id", credential.ID)
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

// GetByID retrieves a credential by ID
func (s *Store) GetByID(ctx context.Context, id string) (*Credential, error) {
	query := `
		SELECT id, name, type, description, owner_id, team_id, sharing_level,
			   encrypted_data, data_hash, test_endpoint, last_used_at, usage_count,
			   is_active, expires_at, tags, created_at, updated_at
		FROM credentials
		WHERE id = $1 AND is_active = true`

	var credential Credential
	var tagsJSON string
	var lastUsedAt sql.NullTime

	err := s.db.QueryRow(ctx, query, id).Scan(
		&credential.ID,
		&credential.Name,
		&credential.Type,
		&credential.Description,
		&credential.OwnerID,
		&credential.TeamID,
		&credential.SharingLevel,
		&credential.EncryptedData,
		&credential.DataHash,
		&credential.TestEndpoint,
		&lastUsedAt,
		&credential.UsageCount,
		&credential.IsActive,
		&credential.ExpiresAt,
		&tagsJSON,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("credential not found")
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	if lastUsedAt.Valid {
		credential.LastUsedAt = &lastUsedAt.Time
	}

	if err := json.Unmarshal([]byte(tagsJSON), &credential.Tags); err != nil {
		s.logger.Warn("Failed to unmarshal credential tags", "error", err, "credential_id", id)
		credential.Tags = []string{}
	}

	return &credential, nil
}

// GetByOwnerID retrieves credentials by owner ID
func (s *Store) GetByOwnerID(ctx context.Context, ownerID string) ([]*Credential, error) {
	query := `
		SELECT id, name, type, description, owner_id, team_id, sharing_level,
			   encrypted_data, data_hash, test_endpoint, last_used_at, usage_count,
			   is_active, expires_at, tags, created_at, updated_at
		FROM credentials
		WHERE owner_id = $1 AND is_active = true
		ORDER BY created_at DESC`

	rows, err := s.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials by owner: %w", err)
	}
	defer rows.Close()

	var credentials []*Credential
	for rows.Next() {
		credential, err := s.scanCredential(rows)
		if err != nil {
			s.logger.Error("Failed to scan credential", "error", err)
			continue
		}
		credentials = append(credentials, credential)
	}

	return credentials, rows.Err()
}

// List retrieves credentials with filtering
func (s *Store) List(ctx context.Context, filter *CredentialFilter) ([]*Credential, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "is_active = true")

	if filter.OwnerID != "" {
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", argIndex))
		args = append(args, filter.OwnerID)
		argIndex++
	}

	if filter.TeamID != "" {
		conditions = append(conditions, fmt.Sprintf("team_id = $%d", argIndex))
		args = append(args, filter.TeamID)
		argIndex++
	}

	if filter.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, filter.Type)
		argIndex++
	}

	if filter.SharingLevel != "" {
		conditions = append(conditions, fmt.Sprintf("sharing_level = $%d", argIndex))
		args = append(args, filter.SharingLevel)
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM credentials " + whereClause
	var total int
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count credentials: %w", err)
	}

	// Get credentials
	query := fmt.Sprintf(`
		SELECT id, name, type, description, owner_id, team_id, sharing_level,
			   encrypted_data, data_hash, test_endpoint, last_used_at, usage_count,
			   is_active, expires_at, tags, created_at, updated_at
		FROM credentials %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*Credential
	for rows.Next() {
		credential, err := s.scanCredential(rows)
		if err != nil {
			s.logger.Error("Failed to scan credential", "error", err)
			continue
		}
		credentials = append(credentials, credential)
	}

	return credentials, total, rows.Err()
}

// Update updates a credential
func (s *Store) Update(ctx context.Context, credential *Credential) error {
	query := `
		UPDATE credentials SET
			name = $2, description = $3, sharing_level = $4,
			encrypted_data = $5, data_hash = $6, test_endpoint = $7,
			is_active = $8, expires_at = $9, tags = $10, updated_at = $11
		WHERE id = $1`

	tagsJSON, err := json.Marshal(credential.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	credential.UpdatedAt = time.Now()

	_, err = s.db.Exec(ctx, query,
		credential.ID,
		credential.Name,
		credential.Description,
		credential.SharingLevel,
		credential.EncryptedData,
		credential.DataHash,
		credential.TestEndpoint,
		credential.IsActive,
		credential.ExpiresAt,
		string(tagsJSON),
		credential.UpdatedAt,
	)

	if err != nil {
		s.logger.Error("Failed to update credential", "error", err, "credential_id", credential.ID)
		return fmt.Errorf("failed to update credential: %w", err)
	}

	return nil
}

// Delete soft deletes a credential
func (s *Store) Delete(ctx context.Context, id string) error {
	query := `UPDATE credentials SET is_active = false, updated_at = $2 WHERE id = $1`

	_, err := s.db.Exec(ctx, query, id, time.Now())
	if err != nil {
		s.logger.Error("Failed to delete credential", "error", err, "credential_id", id)
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

// MarkUsed updates the last used timestamp and usage count
func (s *Store) MarkUsed(ctx context.Context, id string) error {
	query := `
		UPDATE credentials
		SET last_used_at = $2, usage_count = usage_count + 1, updated_at = $2
		WHERE id = $1`

	now := time.Now()
	_, err := s.db.Exec(ctx, query, id, now)
	if err != nil {
		s.logger.Error("Failed to mark credential as used", "error", err, "credential_id", id)
		return fmt.Errorf("failed to mark credential as used: %w", err)
	}

	return nil
}

// scanCredential scans a credential row
func (s *Store) scanCredential(rows pgx.Rows) (*Credential, error) {
	var credential Credential
	var tagsJSON string
	var lastUsedAt sql.NullTime

	err := rows.Scan(
		&credential.ID,
		&credential.Name,
		&credential.Type,
		&credential.Description,
		&credential.OwnerID,
		&credential.TeamID,
		&credential.SharingLevel,
		&credential.EncryptedData,
		&credential.DataHash,
		&credential.TestEndpoint,
		&lastUsedAt,
		&credential.UsageCount,
		&credential.IsActive,
		&credential.ExpiresAt,
		&tagsJSON,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if lastUsedAt.Valid {
		credential.LastUsedAt = &lastUsedAt.Time
	}

	if err := json.Unmarshal([]byte(tagsJSON), &credential.Tags); err != nil {
		s.logger.Warn("Failed to unmarshal credential tags", "error", err)
		credential.Tags = []string{}
	}

	return &credential, nil
}

// CreateTables creates the necessary database tables
func (s *Store) CreateTables(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS credentials (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(100) NOT NULL,
			description TEXT,
			owner_id VARCHAR(255) NOT NULL,
			team_id VARCHAR(255),
			sharing_level VARCHAR(50) NOT NULL DEFAULT 'private',
			encrypted_data TEXT NOT NULL,
			data_hash VARCHAR(255) NOT NULL,
			test_endpoint VARCHAR(500),
			last_used_at TIMESTAMP,
			usage_count INTEGER DEFAULT 0,
			is_active BOOLEAN DEFAULT true,
			expires_at TIMESTAMP,
			tags JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT valid_sharing_level CHECK (sharing_level IN ('private', 'team', 'public'))
		);

		CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);
		CREATE INDEX IF NOT EXISTS idx_credentials_team_id ON credentials(team_id);
		CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
		CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(is_active);
		CREATE INDEX IF NOT EXISTS idx_credentials_sharing ON credentials(sharing_level);
		CREATE INDEX IF NOT EXISTS idx_credentials_tags ON credentials USING GIN(tags);`

	_, err := s.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create credentials tables: %w", err)
	}

	s.logger.Info("Credentials tables created successfully")
	return nil
}

// GetExpired returns expired credentials
func (s *Store) GetExpired(ctx context.Context) ([]*Credential, error) {
	query := `
		SELECT id, name, type, description, owner_id, team_id, sharing_level,
			   encrypted_data, data_hash, test_endpoint, last_used_at, usage_count,
			   is_active, expires_at, tags, created_at, updated_at
		FROM credentials
		WHERE is_active = true AND expires_at IS NOT NULL AND expires_at < NOW()
		ORDER BY expires_at ASC`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*Credential
	for rows.Next() {
		credential, err := s.scanCredential(rows)
		if err != nil {
			s.logger.Error("Failed to scan expired credential", "error", err)
			continue
		}
		credentials = append(credentials, credential)
	}

	return credentials, rows.Err()
}

// GetUsageStats returns usage statistics for credentials
func (s *Store) GetUsageStats(ctx context.Context, ownerID string) (map[string]interface{}, error) {
	query := `
		SELECT
			COUNT(*) as total_credentials,
			COUNT(CASE WHEN last_used_at IS NOT NULL THEN 1 END) as used_credentials,
			SUM(usage_count) as total_usage,
			COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN 1 END) as expired_credentials,
			COUNT(CASE WHEN sharing_level = 'private' THEN 1 END) as private_credentials,
			COUNT(CASE WHEN sharing_level = 'team' THEN 1 END) as team_credentials,
			COUNT(CASE WHEN sharing_level = 'public' THEN 1 END) as public_credentials
		FROM credentials
		WHERE owner_id = $1 AND is_active = true`

	var stats struct {
		TotalCredentials   int `json:"total_credentials"`
		UsedCredentials    int `json:"used_credentials"`
		TotalUsage         int `json:"total_usage"`
		ExpiredCredentials int `json:"expired_credentials"`
		PrivateCredentials int `json:"private_credentials"`
		TeamCredentials    int `json:"team_credentials"`
		PublicCredentials  int `json:"public_credentials"`
	}

	err := s.db.QueryRow(ctx, query, ownerID).Scan(
		&stats.TotalCredentials,
		&stats.UsedCredentials,
		&stats.TotalUsage,
		&stats.ExpiredCredentials,
		&stats.PrivateCredentials,
		&stats.TeamCredentials,
		&stats.PublicCredentials,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	return map[string]interface{}{
		"total_credentials":   stats.TotalCredentials,
		"used_credentials":    stats.UsedCredentials,
		"total_usage":         stats.TotalUsage,
		"expired_credentials": stats.ExpiredCredentials,
		"private_credentials": stats.PrivateCredentials,
		"team_credentials":    stats.TeamCredentials,
		"public_credentials":  stats.PublicCredentials,
	}, nil
}
