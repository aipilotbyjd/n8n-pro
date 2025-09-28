package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of JWT token
type TokenType string

const (
	// AccessToken is used for API authentication
	AccessToken TokenType = "access"
	// RefreshToken is used for refreshing access tokens
	RefreshToken TokenType = "refresh"
)

// Claims represents JWT claims structure
type Claims struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	TeamID    string    `json:"team_id"`
	TeamName  string    `json:"team_name"`
	TeamPlan  string    `json:"team_plan"`
	Scopes    []string  `json:"scopes"`
	TokenType TokenType `json:"token_type"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	jwt.RegisteredClaims
}

// IsExpired checks if the token is expired
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsValid checks if the claims are valid
func (c *Claims) IsValid() bool {
	return !c.IsExpired() && c.UserID != "" && c.Email != ""
}

// Config holds JWT service configuration
type Config struct {
	Secret                string        `json:"secret"`
	AccessTokenDuration   time.Duration `json:"access_token_duration"`
	RefreshTokenDuration  time.Duration `json:"refresh_token_duration"`
	Issuer                string        `json:"issuer"`
	Audience              string        `json:"audience"`
	RefreshTokenLength    int           `json:"refresh_token_length"`
	EnableRefreshRotation bool          `json:"enable_refresh_rotation"`
}

// DefaultConfig returns default JWT configuration
func DefaultConfig() *Config {
	return &Config{
		Secret:                generateRandomSecret(64),
		AccessTokenDuration:   15 * time.Minute,
		RefreshTokenDuration:  7 * 24 * time.Hour, // 7 days
		Issuer:                "n8n-pro",
		Audience:              "n8n-pro-api",
		RefreshTokenLength:    32,
		EnableRefreshRotation: true,
	}
}

// Service provides JWT token operations
type Service struct {
	config        *Config
	signingMethod jwt.SigningMethod
	blacklist     map[string]time.Time // Simple in-memory blacklist
	blacklistMu   sync.RWMutex         // Protects blacklist access
}

// New creates a new JWT service
func New(config *Config) *Service {
	if config == nil {
		config = DefaultConfig()
	}

	return &Service{
		config:        config,
		signingMethod: jwt.SigningMethodHS256,
		blacklist:     make(map[string]time.Time),
	}
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// GenerateTokenPair creates a new access and refresh token pair
func (s *Service) GenerateTokenPair(userID, email, role, teamID, teamName, teamPlan string, scopes []string) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessClaims := &Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TeamID:    teamID,
		TeamName:  teamName,
		TeamPlan:  teamPlan,
		Scopes:    scopes,
		TokenType: AccessToken,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.config.AccessTokenDuration),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	accessToken, err := s.generateToken(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TeamID:    teamID,
		TeamName:  teamName,
		TeamPlan:  teamPlan,
		Scopes:    scopes,
		TokenType: RefreshToken,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.config.RefreshTokenDuration),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	refreshToken, err := s.generateToken(refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessClaims.ExpiresAt,
		RefreshTokenExpiresAt: refreshClaims.ExpiresAt,
		TokenType:             "Bearer",
	}, nil
}

// ValidateToken validates and parses a JWT token
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Additional validation
	if !claims.IsValid() {
		return nil, fmt.Errorf("invalid or expired claims")
	}

	// Check if token is revoked
	if s.IsTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// RefreshTokenPair creates new tokens from refresh token
func (s *Service) RefreshTokenPair(refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's a refresh token
	if claims.TokenType != RefreshToken {
		return nil, fmt.Errorf("provided token is not a refresh token")
	}

	// Generate new token pair
	return s.GenerateTokenPair(
		claims.UserID,
		claims.Email,
		claims.Role,
		claims.TeamID,
		claims.TeamName,
		claims.TeamPlan,
		claims.Scopes,
	)
}

// ExtractClaims extracts claims from token without validation (for debugging)
func (s *Service) ExtractClaims(tokenString string) (*Claims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// IsTokenExpired checks if a token is expired without full validation
func (s *Service) IsTokenExpired(tokenString string) bool {
	claims, err := s.ExtractClaims(tokenString)
	if err != nil {
		return true
	}
	return claims.IsExpired()
}

// GetTokenTTL returns the remaining time-to-live for a token
func (s *Service) GetTokenTTL(tokenString string) (time.Duration, error) {
	claims, err := s.ExtractClaims(tokenString)
	if err != nil {
		return 0, err
	}

	ttl := time.Until(claims.ExpiresAt)
	if ttl < 0 {
		return 0, fmt.Errorf("token has expired")
	}

	return ttl, nil
}

// generateToken creates a JWT token from claims
func (s *Service) generateToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(s.signingMethod, claims)
	return token.SignedString([]byte(s.config.Secret))
}

// generateRandomSecret generates a random secret key
func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Panic instead of using insecure fallback
		panic(fmt.Sprintf("Failed to generate secure random secret: %v. This is a critical security failure.", err))
	}
	return hex.EncodeToString(bytes)
}

// ValidateAccessToken validates specifically access tokens
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != AccessToken {
		return nil, fmt.Errorf("token is not an access token")
	}

	return claims, nil
}

// ValidateRefreshToken validates specifically refresh tokens
func (s *Service) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != RefreshToken {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	return claims, nil
}

// CreateAPIToken creates a long-lived API token for programmatic access
func (s *Service) CreateAPIToken(userID, email, role, teamID string, scopes []string, duration time.Duration) (string, error) {
	now := time.Now()
	expiresAt := now.Add(duration)

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TeamID:    teamID,
		Scopes:    scopes,
		TokenType: AccessToken,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	return s.generateToken(claims)
}

// RevokeToken marks a token as revoked using in-memory blacklist
func (s *Service) RevokeToken(tokenString string) error {
	// Validate token first
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return fmt.Errorf("cannot revoke invalid token: %w", err)
	}

	// Add to blacklist with expiration
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	
	s.blacklist[tokenString] = claims.ExpiresAt
	
	// Clean up expired tokens periodically
	go s.cleanupExpiredTokens()

	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (s *Service) IsTokenRevoked(tokenString string) bool {
	s.blacklistMu.RLock()
	defer s.blacklistMu.RUnlock()
	
	expiry, exists := s.blacklist[tokenString]
	if !exists {
		return false
	}
	
	// Remove expired entries
	if time.Now().After(expiry) {
		delete(s.blacklist, tokenString)
		return false
	}
	
	return true
}

// cleanupExpiredTokens removes expired tokens from blacklist
func (s *Service) cleanupExpiredTokens() {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	
	now := time.Now()
	for token, expiry := range s.blacklist {
		if now.After(expiry) {
			delete(s.blacklist, token)
		}
	}
}

// GetUserIDFromToken extracts user ID from token without full validation
func (s *Service) GetUserIDFromToken(tokenString string) (string, error) {
	claims, err := s.ExtractClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// CreatePasswordResetToken creates a short-lived token for password reset
func (s *Service) CreatePasswordResetToken(userID, email string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(30 * time.Minute) // 30 minutes for password reset

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		TokenType: "password_reset",
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	return s.generateToken(claims)
}

// CreateEmailVerificationToken creates a token for email verification
func (s *Service) CreateEmailVerificationToken(userID, email string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // 24 hours for email verification

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		TokenType: "email_verification",
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	return s.generateToken(claims)
}
