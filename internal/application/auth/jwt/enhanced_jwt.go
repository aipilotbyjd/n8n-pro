package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// EnhancedClaims represents enhanced JWT claims with organization support
type EnhancedClaims struct {
	UserID         string   `json:"user_id"`
	Email          string   `json:"email"`
	Role           string   `json:"role"`
	OrganizationID string   `json:"organization_id"`
	TeamID         string   `json:"team_id,omitempty"`
	TeamName       string   `json:"team_name,omitempty"`
	TeamPlan       string   `json:"team_plan,omitempty"`
	Scopes         []string `json:"scopes"`
	SessionID      string   `json:"session_id,omitempty"` // For session tracking
	jwt.RegisteredClaims
}

// EnhancedTokenPair represents access and refresh tokens with enhanced metadata
type EnhancedTokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	SessionID    string `json:"session_id,omitempty"`
}

// EnhancedService handles JWT operations with organization and session support
type EnhancedService struct {
	secret            []byte
	accessTokenTTL    time.Duration
	refreshTokenTTL   time.Duration
	issuer            string
	accessAudience    string
	refreshAudience   string
}

// EnhancedConfig represents JWT service configuration
type EnhancedConfig struct {
	Secret            string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	Issuer            string
	AccessAudience    string
	RefreshAudience   string
}

// NewEnhancedService creates a new JWT service with enhanced configuration
func NewEnhancedService(config *EnhancedConfig) *EnhancedService {
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 1 * time.Hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if config.Issuer == "" {
		config.Issuer = "n8n-pro"
	}
	if config.AccessAudience == "" {
		config.AccessAudience = "n8n-pro-api"
	}
	if config.RefreshAudience == "" {
		config.RefreshAudience = "n8n-pro-refresh"
	}

	return &EnhancedService{
		secret:            []byte(config.Secret),
		accessTokenTTL:    config.AccessTokenTTL,
		refreshTokenTTL:   config.RefreshTokenTTL,
		issuer:            config.Issuer,
		accessAudience:    config.AccessAudience,
		refreshAudience:   config.RefreshAudience,
	}
}

// NewEnhancedServiceWithDefaults creates a new JWT service with default settings
func NewEnhancedServiceWithDefaults(secret string) *EnhancedService {
	return NewEnhancedService(&EnhancedConfig{
		Secret: secret,
	})
}

// GenerateEnhancedTokenPair generates access and refresh tokens with enhanced claims
func (s *EnhancedService) GenerateEnhancedTokenPair(userID, email, role, organizationID string, teamID, teamName, teamPlan string, scopes []string, sessionID string) (*EnhancedTokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(s.accessTokenTTL)
	refreshExpiry := now.Add(s.refreshTokenTTL)

	// Create access token claims with full user context
	accessClaims := &EnhancedClaims{
		UserID:         userID,
		Email:          email,
		Role:           role,
		OrganizationID: organizationID,
		TeamID:         teamID,
		TeamName:       teamName,
		TeamPlan:       teamPlan,
		Scopes:         scopes,
		SessionID:      sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{s.accessAudience},
		},
	}

	// Create refresh token claims (minimal claims for security)
	refreshClaims := &EnhancedClaims{
		UserID:         userID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{s.refreshAudience},
		},
	}

	// Generate tokens
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	accessTokenString, err := accessToken.SignedString(s.secret)
	if err != nil {
		return nil, err
	}

	refreshTokenString, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return nil, err
	}

	return &EnhancedTokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
		SessionID:    sessionID,
	}, nil
}

// ValidateEnhancedToken validates and parses an access token
func (s *EnhancedService) ValidateEnhancedToken(tokenString string) (*EnhancedClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EnhancedClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*EnhancedClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Verify audience for access tokens
	if len(claims.Audience) > 0 && claims.Audience[0] != s.accessAudience {
		return nil, errors.New("invalid token audience")
	}

	// Verify issuer
	if claims.Issuer != s.issuer {
		return nil, errors.New("invalid token issuer")
	}

	return claims, nil
}

// ValidateEnhancedRefreshToken validates and parses a refresh token
func (s *EnhancedService) ValidateEnhancedRefreshToken(tokenString string) (*EnhancedClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EnhancedClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*EnhancedClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Verify audience for refresh tokens
	if len(claims.Audience) > 0 && claims.Audience[0] != s.refreshAudience {
		return nil, errors.New("invalid token audience")
	}

	// Verify issuer
	if claims.Issuer != s.issuer {
		return nil, errors.New("invalid token issuer")
	}

	return claims, nil
}

// IsExpired checks if enhanced claims are expired
func (c *EnhancedClaims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(c.ExpiresAt.Time)
}

// HasScope checks if the token has a specific scope
func (c *EnhancedClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the specified scopes
func (c *EnhancedClaims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the token has all of the specified scopes
func (c *EnhancedClaims) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			return false
		}
	}
	return true
}

// GenerateSessionID generates a secure session ID
func GenerateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// CreateAPIToken creates a long-lived API token
func (s *EnhancedService) CreateAPIToken(userID, email, role, organizationID string, scopes []string, duration time.Duration) (string, error) {
	now := time.Now()
	expiresAt := now.Add(duration)

	claims := &EnhancedClaims{
		UserID:         userID,
		Email:          email,
		Role:           role,
		OrganizationID: organizationID,
		Scopes:         scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{s.accessAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// CreatePasswordResetToken creates a token for password reset
func (s *EnhancedService) CreatePasswordResetToken(userID, email, organizationID string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour) // 1 hour for password reset

	claims := &EnhancedClaims{
		UserID:         userID,
		Email:          email,
		OrganizationID: organizationID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{"password-reset"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// CreateEmailVerificationToken creates a token for email verification
func (s *EnhancedService) CreateEmailVerificationToken(userID, email, organizationID string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // 24 hours for email verification

	claims := &EnhancedClaims{
		UserID:         userID,
		Email:          email,
		OrganizationID: organizationID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{"email-verification"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// ValidateSpecialToken validates tokens for specific purposes (password reset, email verification)
func (s *EnhancedService) ValidateSpecialToken(tokenString, expectedAudience string) (*EnhancedClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EnhancedClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*EnhancedClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Verify audience
	if len(claims.Audience) > 0 && claims.Audience[0] != expectedAudience {
		return nil, errors.New("invalid token audience")
	}

	// Verify issuer
	if claims.Issuer != s.issuer {
		return nil, errors.New("invalid token issuer")
	}

	// Check expiration
	if claims.IsExpired() {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// ExtractClaimsWithoutValidation extracts claims without validation (for debugging)
func (s *EnhancedService) ExtractClaimsWithoutValidation(tokenString string) (*EnhancedClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &EnhancedClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*EnhancedClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}