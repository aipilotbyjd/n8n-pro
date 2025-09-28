package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Service represents the JWT service interface
type Service struct {
	config *Config
}

// Config represents JWT service configuration
type Config struct {
	Secret               string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	Issuer               string
	Audience             string
}

// JWT token types
const (
	AccessToken  = "access"
	RefreshToken = "refresh"
)

// Claims represents JWT claims structure
type Claims struct {
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	TeamID    string   `json:"team_id,omitempty"`
	TeamName  string   `json:"team_name,omitempty"`
	TeamPlan  string   `json:"team_plan,omitempty"`
	Scopes    []string `json:"scopes"`
	TokenType string   `json:"token_type"`
	jwt.RegisteredClaims
}

// IsExpired checks if the token is expired
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt != nil {
		return time.Now().After(c.ExpiresAt.Time)
	}
	return false
}

// IsValid checks if the claims are valid
func (c *Claims) IsValid() bool {
	return !c.IsExpired() && c.UserID != "" && c.Email != ""
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
	SessionID             string    `json:"session_id,omitempty"`
}

// New creates a new JWT service instance
func New(config *Config) *Service {
	if config == nil {
		config = &Config{
			AccessTokenDuration:  time.Hour,
			RefreshTokenDuration: 24 * time.Hour,
			Issuer:               "n8n-pro",
			Audience:             "n8n-pro-api",
		}
	}
	return &Service{config: config}
}

// GenerateTokenPair creates a new access and refresh token pair
func (s *Service) GenerateTokenPair(userID, email, role, teamID, teamName, teamPlan string, scopes []string) (*TokenPair, error) {
	now := time.Now()

	// Create access token
	accessClaims := &Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TeamID:    teamID,
		TeamName:  teamName,
		TeamPlan:  teamPlan,
		Scopes:    scopes,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
			Subject:   userID,
			Audience:  []string{s.config.Audience},
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create refresh token
	refreshClaims := &Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TeamID:    teamID,
		TeamName:  teamName,
		TeamPlan:  teamPlan,
		Scopes:    scopes,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
			Subject:   userID,
			Audience:  []string{s.config.Audience},
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessTokenString,
		RefreshToken:          refreshTokenString,
		AccessTokenExpiresAt:  now.Add(s.config.AccessTokenDuration),
		RefreshTokenExpiresAt: now.Add(s.config.RefreshTokenDuration),
		TokenType:             "Bearer",
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidateRefreshToken validates specifically a refresh token
func (s *Service) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}

	return claims, nil
}

// ValidateAccessToken validates specifically an access token
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "access" {
		return nil, errors.New("token is not an access token")
	}

	return claims, nil
}