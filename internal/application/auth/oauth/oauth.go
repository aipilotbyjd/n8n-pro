package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/shared"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// Provider represents different OAuth providers
type Provider string

const (
	// ProviderGoogle represents Google OAuth
	ProviderGoogle Provider = "google"
	// ProviderGitHub represents GitHub OAuth
	ProviderGitHub Provider = "github"
	// ProviderMicrosoft represents Microsoft OAuth
	ProviderMicrosoft Provider = "microsoft"
	// ProviderSlack represents Slack OAuth
	ProviderSlack Provider = "slack"
)

// Config holds OAuth configuration
type Config struct {
	Providers map[Provider]*ProviderConfig `json:"providers" yaml:"providers"`
	BaseURL   string                       `json:"base_url" yaml:"base_url"`
	JWTSecret string                       `json:"jwt_secret" yaml:"jwt_secret"`
}

// ProviderConfig holds configuration for a specific OAuth provider
type ProviderConfig struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
	AuthURL      string   `json:"auth_url" yaml:"auth_url"`
	TokenURL     string   `json:"token_url" yaml:"token_url"`
	UserInfoURL  string   `json:"user_info_url" yaml:"user_info_url"`
	Enabled      bool     `json:"enabled" yaml:"enabled"`
}

// DefaultProviderConfigs returns default configurations for supported providers
func DefaultProviderConfigs() map[Provider]*ProviderConfig {
	return map[Provider]*ProviderConfig{
		ProviderGoogle: {
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:    "https://oauth2.googleapis.com/token",
			UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
			Scopes:      []string{"openid", "email", "profile"},
		},
		ProviderGitHub: {
			AuthURL:     "https://github.com/login/oauth/authorize",
			TokenURL:    "https://github.com/login/oauth/access_token",
			UserInfoURL: "https://api.github.com/user",
			Scopes:      []string{"user:email"},
		},
		ProviderMicrosoft: {
			AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL: "https://graph.microsoft.com/v1.0/me",
			Scopes:      []string{"openid", "email", "profile"},
		},
		ProviderSlack: {
			AuthURL:     "https://slack.com/oauth/v2/authorize",
			TokenURL:    "https://slack.com/api/oauth.v2.access",
			UserInfoURL: "https://slack.com/api/users.identity",
			Scopes:      []string{"identity.basic", "identity.email"},
		},
	}
}

// AuthRequest represents an OAuth authorization request
type AuthRequest struct {
	Provider     Provider  `json:"provider"`
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	RedirectURL  string    `json:"redirect_url"`
	CreatedAt    time.Time `json:"created_at"`
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	FirstName     string   `json:"first_name,omitempty"`
	LastName      string   `json:"last_name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Verified      bool     `json:"verified"`
	Provider      Provider `json:"provider"`
	ProviderToken string   `json:"provider_token,omitempty"`
}

// Service provides OAuth functionality
type Service struct {
	config     *Config
	jwtService *jwt.Service
	httpClient *http.Client
	logger     logger.Logger
	states     map[string]*AuthRequest // In production, use Redis or database
}

// New creates a new OAuth service
func New(config *Config, jwtService *jwt.Service, log logger.Logger) *Service {
	if config == nil {
		config = &Config{
			Providers: DefaultProviderConfigs(),
		}
	}

	return &Service{
		config:     config,
		jwtService: jwtService,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     log,
		states:     make(map[string]*AuthRequest),
	}
}

// GetAuthorizationURL generates OAuth authorization URL
func (s *Service) GetAuthorizationURL(provider Provider, redirectURL string) (string, string, error) {
	providerConfig, exists := s.config.Providers[provider]
	if !exists || !providerConfig.Enabled {
		return "", "", errors.NewValidationError("OAuth provider not supported or disabled")
	}

	// Generate state parameter for CSRF protection
	state := generateRandomString(32)

	// Generate PKCE parameters
	codeVerifier := generateRandomString(128)
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store auth request
	authRequest := &AuthRequest{
		Provider:     provider,
		State:        state,
		CodeVerifier: codeVerifier,
		RedirectURL:  redirectURL,
		CreatedAt:    time.Now(),
	}
	s.states[state] = authRequest

	// Build authorization URL
	params := url.Values{}
	params.Set("client_id", providerConfig.ClientID)
	params.Set("redirect_uri", providerConfig.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(providerConfig.Scopes, " "))
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	// Provider-specific parameters
	switch provider {
	case ProviderGoogle:
		params.Set("access_type", "offline")
		params.Set("prompt", "consent")
	case ProviderMicrosoft:
		params.Set("response_mode", "query")
		params.Set("prompt", "consent")
	}

	authURL := fmt.Sprintf("%s?%s", providerConfig.AuthURL, params.Encode())

	s.logger.Info("Generated OAuth authorization URL",
		"provider", string(provider),
		"state", state,
		"redirect_url", redirectURL,
	)

	return authURL, state, nil
}

// HandleCallback processes OAuth callback
func (s *Service) HandleCallback(provider Provider, code, state string) (*common.User, *jwt.TokenPair, error) {
	// Validate state parameter
	authRequest, exists := s.states[state]
	if !exists {
		return nil, nil, errors.NewValidationError("Invalid or expired state parameter")
	}

	// Remove state from storage
	delete(s.states, state)

	// Check if state matches and hasn't expired (15 minutes)
	if authRequest.Provider != provider {
		return nil, nil, errors.NewValidationError("Provider mismatch")
	}

	if time.Since(authRequest.CreatedAt) > 15*time.Minute {
		return nil, nil, errors.NewValidationError("OAuth state has expired")
	}

	// Exchange authorization code for token
	tokenResponse, err := s.exchangeCodeForToken(provider, code, authRequest.CodeVerifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.getUserInfo(provider, tokenResponse.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	s.logger.Info("OAuth callback processed successfully",
		"provider", string(provider),
		"user_email", userInfo.Email,
		"user_id", userInfo.ID,
	)

	// Create or update user (this would typically involve database operations)
	user := &common.User{
		ID:       userInfo.ID,
		Email:    userInfo.Email,
		Name:     userInfo.Name,
		Role:     "user", // Default role
		IsActive: true,
		Provider: string(provider),
		Verified: userInfo.Verified,
		Picture:  userInfo.Picture,
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		user.TeamID,
		"",                        // team name
		"",                        // team plan
		[]string{"read", "write"}, // default scopes
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	return user, tokenPair, nil
}

// exchangeCodeForToken exchanges authorization code for access token
func (s *Service) exchangeCodeForToken(provider Provider, code, codeVerifier string) (*TokenResponse, error) {
	providerConfig := s.config.Providers[provider]

	// Prepare token request
	data := url.Values{}
	data.Set("client_id", providerConfig.ClientID)
	data.Set("client_secret", providerConfig.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", providerConfig.RedirectURL)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", providerConfig.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Provider-specific headers
	switch provider {
	case ProviderGitHub:
		req.Header.Set("Accept", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// getUserInfo retrieves user information from OAuth provider
func (s *Service) getUserInfo(provider Provider, accessToken string) (*UserInfo, error) {
	providerConfig := s.config.Providers[provider]

	req, err := http.NewRequest("GET", providerConfig.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user info request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	// Parse user info based on provider
	userInfo, err := s.parseUserInfo(provider, body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	userInfo.Provider = provider
	userInfo.ProviderToken = accessToken

	return userInfo, nil
}

// parseUserInfo parses user information from different providers
func (s *Service) parseUserInfo(provider Provider, data []byte) (*UserInfo, error) {
	var userInfo UserInfo

	switch provider {
	case ProviderGoogle:
		var googleUser struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			VerifiedEmail bool   `json:"verified_email"`
			Name          string `json:"name"`
			GivenName     string `json:"given_name"`
			FamilyName    string `json:"family_name"`
			Picture       string `json:"picture"`
		}

		if err := json.Unmarshal(data, &googleUser); err != nil {
			return nil, err
		}

		userInfo = UserInfo{
			ID:        googleUser.ID,
			Email:     googleUser.Email,
			Name:      googleUser.Name,
			FirstName: googleUser.GivenName,
			LastName:  googleUser.FamilyName,
			Picture:   googleUser.Picture,
			Verified:  googleUser.VerifiedEmail,
		}

	case ProviderGitHub:
		var githubUser struct {
			ID        int    `json:"id"`
			Login     string `json:"login"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		}

		if err := json.Unmarshal(data, &githubUser); err != nil {
			return nil, err
		}

		// GitHub might not return email in user endpoint, need to fetch separately
		if githubUser.Email == "" {
			githubUser.Email = s.getGitHubUserEmail(userInfo.ProviderToken)
		}

		userInfo = UserInfo{
			ID:       fmt.Sprintf("%d", githubUser.ID),
			Email:    githubUser.Email,
			Name:     githubUser.Name,
			Picture:  githubUser.AvatarURL,
			Verified: true, // GitHub accounts are considered verified
		}

	case ProviderMicrosoft:
		var msUser struct {
			ID                string `json:"id"`
			Mail              string `json:"mail"`
			UserPrincipalName string `json:"userPrincipalName"`
			DisplayName       string `json:"displayName"`
			GivenName         string `json:"givenName"`
			Surname           string `json:"surname"`
		}

		if err := json.Unmarshal(data, &msUser); err != nil {
			return nil, err
		}

		email := msUser.Mail
		if email == "" {
			email = msUser.UserPrincipalName
		}

		userInfo = UserInfo{
			ID:        msUser.ID,
			Email:     email,
			Name:      msUser.DisplayName,
			FirstName: msUser.GivenName,
			LastName:  msUser.Surname,
			Verified:  true,
		}

	case ProviderSlack:
		var slackResponse struct {
			OK   bool `json:"ok"`
			User struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"user"`
		}

		if err := json.Unmarshal(data, &slackResponse); err != nil {
			return nil, err
		}

		if !slackResponse.OK {
			return nil, fmt.Errorf("slack API error")
		}

		userInfo = UserInfo{
			ID:       slackResponse.User.ID,
			Email:    slackResponse.User.Email,
			Name:     slackResponse.User.Name,
			Verified: true,
		}

	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	return &userInfo, nil
}

// getGitHubUserEmail fetches user email from GitHub API
func (s *Service) getGitHubUserEmail(accessToken string) string {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return ""
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}

	// Return primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email
		}
	}

	return ""
}

// RefreshToken refreshes OAuth access token (if supported by provider)
func (s *Service) RefreshToken(provider Provider, refreshToken string) (*TokenResponse, error) {
	providerConfig := s.config.Providers[provider]

	data := url.Values{}
	data.Set("client_id", providerConfig.ClientID)
	data.Set("client_secret", providerConfig.ClientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", providerConfig.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	return &tokenResponse, nil
}

// CleanupExpiredStates removes expired OAuth states
func (s *Service) CleanupExpiredStates() {
	now := time.Now()
	for state, authRequest := range s.states {
		if now.Sub(authRequest.CreatedAt) > 15*time.Minute {
			delete(s.states, state)
		}
	}
}

// Helper functions

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

// IsProviderSupported checks if a provider is supported
func (s *Service) IsProviderSupported(provider Provider) bool {
	config, exists := s.config.Providers[provider]
	return exists && config.Enabled
}

// GetSupportedProviders returns list of supported providers
func (s *Service) GetSupportedProviders() []Provider {
	var providers []Provider
	for provider, config := range s.config.Providers {
		if config.Enabled {
			providers = append(providers, provider)
		}
	}
	return providers
}

// ValidateProviderConfig validates OAuth provider configuration
func (s *Service) ValidateProviderConfig(provider Provider) error {
	config, exists := s.config.Providers[provider]
	if !exists {
		return errors.NewValidationError("Provider not configured")
	}

	if config.ClientID == "" {
		return errors.NewValidationError("Client ID is required")
	}

	if config.ClientSecret == "" {
		return errors.NewValidationError("Client secret is required")
	}

	if config.RedirectURL == "" {
		return errors.NewValidationError("Redirect URL is required")
	}

	return nil
}
