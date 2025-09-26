package auth

import (
	"context"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SessionRepository provides session data access operations
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id string) (*models.Session, error)
	FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	FindActiveByUserID(ctx context.Context, userID string) ([]*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
	Revoke(ctx context.Context, sessionID string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error
}

// sessionRepository implements SessionRepository using GORM
type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{db: db}
}

// Create creates a new session
func (r *sessionRepository) Create(ctx context.Context, session *models.Session) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return errors.NewInternalError("Failed to create session")
	}
	return nil
}

// FindByID finds a session by ID
func (r *sessionRepository) FindByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("id = ? AND deleted_at IS NULL", id).
		First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("Session not found")
		}
		return nil, errors.NewInternalError("Failed to find session")
	}
	return &session, nil
}

// FindByRefreshToken finds a session by refresh token hash
func (r *sessionRepository) FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	var sessions []models.Session
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("is_active = ? AND expires_at > ? AND deleted_at IS NULL", true, time.Now()).
		Find(&sessions).Error; err != nil {
		return nil, errors.NewInternalError("Failed to search sessions")
	}

	// Find matching session by comparing refresh token hashes
	for _, session := range sessions {
		if err := bcrypt.CompareHashAndPassword([]byte(session.RefreshTokenHash), []byte(refreshToken)); err == nil {
			return &session, nil
		}
	}

	return nil, errors.NewNotFoundError("Session not found")
}

// FindActiveByUserID finds all active sessions for a user
func (r *sessionRepository) FindActiveByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	var sessions []*models.Session
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND is_active = ? AND expires_at > ? AND deleted_at IS NULL", userID, true, time.Now()).
		Order("last_seen_at DESC").
		Find(&sessions).Error; err != nil {
		return nil, errors.NewInternalError("Failed to find sessions")
	}
	return sessions, nil
}

// Update updates a session
func (r *sessionRepository) Update(ctx context.Context, session *models.Session) error {
	if err := r.db.WithContext(ctx).Save(session).Error; err != nil {
		return errors.NewInternalError("Failed to update session")
	}
	return nil
}

// Revoke revokes a session by marking it as inactive
func (r *sessionRepository) Revoke(ctx context.Context, sessionID string) error {
	result := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("id = ? AND deleted_at IS NULL", sessionID).
		Updates(map[string]interface{}{
			"is_active":  false,
			"revoked_at": time.Now(),
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		return errors.NewInternalError("Failed to revoke session")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("Session not found")
	}

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (r *sessionRepository) RevokeAllUserSessions(ctx context.Context, userID string) error {
	result := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("user_id = ? AND is_active = ? AND deleted_at IS NULL", userID, true).
		Updates(map[string]interface{}{
			"is_active":  false,
			"revoked_at": time.Now(),
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		return errors.NewInternalError("Failed to revoke user sessions")
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions from the database
func (r *sessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	// Soft delete expired sessions
	result := r.db.WithContext(ctx).
		Where("expires_at < ? OR (is_active = ? AND revoked_at IS NOT NULL AND revoked_at < ?)",
			time.Now(),
			false,
			time.Now().Add(-24*time.Hour), // Delete revoked sessions after 24 hours
		).
		Delete(&models.Session{})

	if result.Error != nil {
		return errors.NewInternalError("Failed to cleanup expired sessions")
	}

	return nil
}

// SessionMetrics represents session usage metrics
type SessionMetrics struct {
	TotalActiveSessions    int64 `json:"total_active_sessions"`
	TotalSessionsToday     int64 `json:"total_sessions_today"`
	UniqueUsersToday       int64 `json:"unique_users_today"`
	AverageSessionDuration int64 `json:"average_session_duration_minutes"`
}

// GetSessionMetrics returns session usage metrics
func (r *sessionRepository) GetSessionMetrics(ctx context.Context) (*SessionMetrics, error) {
	metrics := &SessionMetrics{}

	// Total active sessions
	if err := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("is_active = ? AND expires_at > ? AND deleted_at IS NULL", true, time.Now()).
		Count(&metrics.TotalActiveSessions).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get active sessions count")
	}

	// Total sessions created today
	today := time.Now().Truncate(24 * time.Hour)
	if err := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("created_at >= ? AND deleted_at IS NULL", today).
		Count(&metrics.TotalSessionsToday).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get today's sessions count")
	}

	// Unique users today
	if err := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("created_at >= ? AND deleted_at IS NULL", today).
		Distinct("user_id").
		Count(&metrics.UniqueUsersToday).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get unique users count")
	}

	// Average session duration (simplified calculation)
	var avgDuration float64
	if err := r.db.WithContext(ctx).
		Model(&models.Session{}).
		Select("AVG(EXTRACT(EPOCH FROM (COALESCE(revoked_at, NOW()) - created_at))/60) as avg_duration").
		Where("created_at >= ? AND deleted_at IS NULL", time.Now().Add(-7*24*time.Hour)).
		Scan(&avgDuration).Error; err != nil {
		return nil, errors.NewInternalError("Failed to calculate average session duration")
	}
	metrics.AverageSessionDuration = int64(avgDuration)

	return metrics, nil
}

// GetUserSessionHistory returns session history for a user
func (r *sessionRepository) GetUserSessionHistory(ctx context.Context, userID string, limit int) ([]*models.Session, error) {
	var sessions []*models.Session
	query := r.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&sessions).Error; err != nil {
		return nil, errors.NewInternalError("Failed to get user session history")
	}

	return sessions, nil
}