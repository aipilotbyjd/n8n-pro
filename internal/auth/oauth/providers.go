package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/github"
)

// Provider represents an OAuth2/SSO provider
type Provider interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
	GetProviderName() string
	GetConfig() *oauth2.Config
}

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale,omitempty"`
	Provider      string `json:"provider"`
}

// OAuthService manages OAuth providers
type OAuthService struct {
	providers map[string]Provider
	logger    logger.Logger
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(logger logger.Logger) *OAuthService {
	return &OAuthService{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// RegisterProvider registers an OAuth provider
func (s *OAuthService) RegisterProvider(name string, provider Provider) {
	s.providers[name] = provider
	s.logger.Info("OAuth provider registered", "provider", name)
}

// GetProvider gets an OAuth provider by name
func (s *OAuthService) GetProvider(name string) (Provider, error) {
	provider, exists := s.providers[name]
	if !exists {
		return nil, fmt.Errorf("OAuth provider not found: %s", name)
	}
	return provider, nil
}

// GetSupportedProviders returns list of supported providers
func (s *OAuthService) GetSupportedProviders() []string {
	var providers []string
	for name := range s.providers {
		providers = append(providers, name)
	}
	return providers
}

// GenerateState generates a secure state parameter for OAuth flow
func (s *OAuthService) GenerateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Google OAuth Provider
type GoogleProvider struct {
	config *oauth2.Config
	logger logger.Logger
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string, logger logger.Logger) *GoogleProvider {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &GoogleProvider{
		config: config,
		logger: logger,
	}
}

func (p *GoogleProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Locale        string `json:"locale"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, err
	}

	return &UserInfo{
		ID:            googleUser.ID,
		Email:         googleUser.Email,
		FirstName:     googleUser.GivenName,
		LastName:      googleUser.FamilyName,
		Name:          googleUser.Name,
		Picture:       googleUser.Picture,
		EmailVerified: googleUser.VerifiedEmail,
		Locale:        googleUser.Locale,
		Provider:      "google",
	}, nil
}

func (p *GoogleProvider) GetProviderName() string {
	return "google"
}

func (p *GoogleProvider) GetConfig() *oauth2.Config {
	return p.config
}

// Microsoft OAuth Provider
type MicrosoftProvider struct {
	config *oauth2.Config
	logger logger.Logger
}

func NewMicrosoftProvider(clientID, clientSecret, redirectURL string, logger logger.Logger) *MicrosoftProvider {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://graph.microsoft.com/user.read",
		},
		Endpoint: microsoft.AzureADEndpoint("common"),
	}

	return &MicrosoftProvider{
		config: config,
		logger: logger,
	}
}

func (p *MicrosoftProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *MicrosoftProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *MicrosoftProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var msUser struct {
		ID                string `json:"id"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
	}

	if err := json.Unmarshal(body, &msUser); err != nil {
		return nil, err
	}

	email := msUser.Mail
	if email == "" {
		email = msUser.UserPrincipalName
	}

	return &UserInfo{
		ID:            msUser.ID,
		Email:         email,
		FirstName:     msUser.GivenName,
		LastName:      msUser.Surname,
		Name:          msUser.DisplayName,
		EmailVerified: true, // Microsoft emails are typically verified
		Provider:      "microsoft",
	}, nil
}

func (p *MicrosoftProvider) GetProviderName() string {
	return "microsoft"
}

func (p *MicrosoftProvider) GetConfig() *oauth2.Config {
	return p.config
}

// GitHub OAuth Provider
type GitHubProvider struct {
	config *oauth2.Config
	logger logger.Logger
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string, logger logger.Logger) *GitHubProvider {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"user:email",
		},
		Endpoint: github.Endpoint,
	}

	return &GitHubProvider{
		config: config,
		logger: logger,
	}
}

func (p *GitHubProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *GitHubProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)

	// Get user info
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var githubUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, err
	}

	// Get primary email if not available in user info
	email := githubUser.Email
	if email == "" {
		email, err = p.getPrimaryEmail(client)
		if err != nil {
			p.logger.Warn("Failed to get GitHub primary email", "error", err)
		}
	}

	// Parse name into first and last name
	firstName, lastName := parseName(githubUser.Name)

	return &UserInfo{
		ID:            fmt.Sprintf("%d", githubUser.ID),
		Email:         email,
		FirstName:     firstName,
		LastName:      lastName,
		Name:          githubUser.Name,
		Picture:       githubUser.AvatarURL,
		EmailVerified: true, // GitHub emails are verified
		Provider:      "github",
	}, nil
}

func (p *GitHubProvider) getPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no primary verified email found")
}

func (p *GitHubProvider) GetProviderName() string {
	return "github"
}

func (p *GitHubProvider) GetConfig() *oauth2.Config {
	return p.config
}

// Generic OIDC Provider
type OIDCProvider struct {
	config       *oauth2.Config
	userInfoURL  string
	providerName string
	logger       logger.Logger
}

func NewOIDCProvider(clientID, clientSecret, redirectURL, authURL, tokenURL, userInfoURL, providerName string, scopes []string, logger logger.Logger) *OIDCProvider {
	if scopes == nil {
		scopes = []string{"openid", "profile", "email"}
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	return &OIDCProvider{
		config:       config,
		userInfoURL:  userInfoURL,
		providerName: providerName,
		logger:       logger,
	}
}

func (p *OIDCProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var oidcUser struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		Picture           string `json:"picture"`
		Locale            string `json:"locale"`
		PreferredUsername string `json:"preferred_username"`
	}

	if err := json.Unmarshal(body, &oidcUser); err != nil {
		return nil, err
	}

	firstName := oidcUser.GivenName
	lastName := oidcUser.FamilyName
	if firstName == "" || lastName == "" {
		firstName, lastName = parseName(oidcUser.Name)
	}

	return &UserInfo{
		ID:            oidcUser.Sub,
		Email:         oidcUser.Email,
		FirstName:     firstName,
		LastName:      lastName,
		Name:          oidcUser.Name,
		Picture:       oidcUser.Picture,
		EmailVerified: oidcUser.EmailVerified,
		Locale:        oidcUser.Locale,
		Provider:      p.providerName,
	}, nil
}

func (p *OIDCProvider) GetProviderName() string {
	return p.providerName
}

func (p *OIDCProvider) GetConfig() *oauth2.Config {
	return p.config
}

// OAuth Configuration
type OAuthConfig struct {
	Providers map[string]ProviderConfig `json:"providers"`
}

type ProviderConfig struct {
	Enabled      bool     `json:"enabled"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes,omitempty"`
	// For OIDC providers
	AuthURL     string `json:"auth_url,omitempty"`
	TokenURL    string `json:"token_url,omitempty"`
	UserInfoURL string `json:"user_info_url,omitempty"`
}

// InitializeProviders initializes OAuth providers from configuration
func (s *OAuthService) InitializeProviders(config *OAuthConfig) error {
	for providerName, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			continue
		}

		var provider Provider
		var err error

		switch strings.ToLower(providerName) {
		case "google":
			provider = NewGoogleProvider(
				providerConfig.ClientID,
				providerConfig.ClientSecret,
				providerConfig.RedirectURL,
				s.logger,
			)
		case "microsoft":
			provider = NewMicrosoftProvider(
				providerConfig.ClientID,
				providerConfig.ClientSecret,
				providerConfig.RedirectURL,
				s.logger,
			)
		case "github":
			provider = NewGitHubProvider(
				providerConfig.ClientID,
				providerConfig.ClientSecret,
				providerConfig.RedirectURL,
				s.logger,
			)
		default:
			// Generic OIDC provider
			if providerConfig.AuthURL == "" || providerConfig.TokenURL == "" || providerConfig.UserInfoURL == "" {
				return fmt.Errorf("OIDC provider %s requires auth_url, token_url, and user_info_url", providerName)
			}
			provider = NewOIDCProvider(
				providerConfig.ClientID,
				providerConfig.ClientSecret,
				providerConfig.RedirectURL,
				providerConfig.AuthURL,
				providerConfig.TokenURL,
				providerConfig.UserInfoURL,
				providerName,
				providerConfig.Scopes,
				s.logger,
			)
		}

		if err != nil {
			return fmt.Errorf("failed to initialize provider %s: %w", providerName, err)
		}

		s.RegisterProvider(providerName, provider)
	}

	return nil
}

// Helper functions

// parseName splits a full name into first and last name
func parseName(fullName string) (firstName, lastName string) {
	if fullName == "" {
		return "", ""
	}

	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return "", ""
	} else if len(parts) == 1 {
		return parts[0], ""
	} else {
		return parts[0], strings.Join(parts[1:], " ")
	}
}

// OAuth Integration Service
type OAuthIntegration struct {
	authService  *auth.EnhancedAuthService
	oauthService *OAuthService
	logger       logger.Logger
}

// NewOAuthIntegration creates a new OAuth integration service
func NewOAuthIntegration(authService *auth.EnhancedAuthService, oauthService *OAuthService, logger logger.Logger) *OAuthIntegration {
	return &OAuthIntegration{
		authService:  authService,
		oauthService: oauthService,
		logger:       logger,
	}
}

// HandleOAuthCallback handles OAuth callback and creates/authenticates user
func (o *OAuthIntegration) HandleOAuthCallback(ctx context.Context, providerName, code, state string, ipAddress string) (*auth.LoginResponse, error) {
	provider, err := o.oauthService.GetProvider(providerName)
	if err != nil {
		return nil, errors.NewValidationError("Invalid OAuth provider")
	}

	// Exchange authorization code for token
	token, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		o.logger.Error("Failed to exchange OAuth code", "provider", providerName, "error", err)
		return nil, errors.NewValidationError("Failed to authenticate with OAuth provider")
	}

	// Get user info from provider
	userInfo, err := provider.GetUserInfo(ctx, token)
	if err != nil {
		o.logger.Error("Failed to get user info from OAuth provider", "provider", providerName, "error", err)
		return nil, errors.NewValidationError("Failed to get user information")
	}

	// Check if user already exists
	existingUser, err := o.authService.GetUserByEmail(ctx, userInfo.Email)
	if err == nil {
		// User exists, authenticate them
		return o.authenticateExistingUser(ctx, existingUser, userInfo, ipAddress)
	}

	// User doesn't exist, create new account
	return o.createUserFromOAuth(ctx, userInfo, ipAddress)
}

// authenticateExistingUser authenticates an existing user via OAuth
func (o *OAuthIntegration) authenticateExistingUser(ctx context.Context, user *auth.User, userInfo *UserInfo, ipAddress string) (*auth.LoginResponse, error) {
	// Update last login
	if err := o.authService.UpdateLastLogin(ctx, user.ID, ipAddress); err != nil {
		o.logger.Error("Failed to update last login", "user_id", user.ID, "error", err)
	}

	// Create audit log
	o.authService.CreateAuditLog(ctx, user.OrganizationID, &user.ID, "user.oauth_login", "user", user.ID, map[string]interface{}{
		"provider": userInfo.Provider,
		"email":    userInfo.Email,
	}, ipAddress, "oauth-login")

	// Generate session and tokens (would need to implement this based on your auth service)
	// This is a placeholder - you'd need to adapt this to your enhanced auth service
	return &auth.LoginResponse{
		// Populate with actual user and organization data
	}, nil
}

// createUserFromOAuth creates a new user from OAuth information
func (o *OAuthIntegration) createUserFromOAuth(ctx context.Context, userInfo *UserInfo, ipAddress string) (*auth.LoginResponse, error) {
	// Create registration request from OAuth info
	regReq := &auth.RegisterRequest{
		FirstName:       userInfo.FirstName,
		LastName:        userInfo.LastName,
		Email:           userInfo.Email,
		Password:        generateRandomPassword(), // Generate a random password for OAuth users
		InvitationToken: "", // No invitation for OAuth registration
	}

	// Register the user
	loginResponse, err := o.authService.Register(ctx, regReq, ipAddress)
	if err != nil {
		o.logger.Error("Failed to register OAuth user", "email", userInfo.Email, "provider", userInfo.Provider, "error", err)
		return nil, err
	}

	// Mark email as verified since it came from OAuth provider
	if userInfo.EmailVerified {
		if err := o.authService.VerifyEmailByUserID(ctx, loginResponse.User.ID); err != nil {
			o.logger.Error("Failed to verify OAuth user email", "user_id", loginResponse.User.ID, "error", err)
		}
	}

	// Create audit log for OAuth registration
	o.authService.CreateAuditLog(ctx, loginResponse.Organization.ID, &loginResponse.User.ID, "user.oauth_registered", "user", loginResponse.User.ID, map[string]interface{}{
		"provider": userInfo.Provider,
		"email":    userInfo.Email,
	}, ipAddress, "oauth-registration")

	o.logger.Info("OAuth user registered successfully", "user_id", loginResponse.User.ID, "email", userInfo.Email, "provider", userInfo.Provider)

	return loginResponse, nil
}

// generateRandomPassword generates a secure random password for OAuth users
func generateRandomPassword() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// GetOAuthProviders returns available OAuth providers for frontend
func (o *OAuthIntegration) GetOAuthProviders() []ProviderInfo {
	var providers []ProviderInfo
	for _, name := range o.oauthService.GetSupportedProviders() {
		providers = append(providers, ProviderInfo{
			Name:        name,
			DisplayName: getProviderDisplayName(name),
		})
	}
	return providers
}

// ProviderInfo represents OAuth provider information for frontend
type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// getProviderDisplayName returns user-friendly provider name
func getProviderDisplayName(name string) string {
	switch strings.ToLower(name) {
	case "google":
		return "Google"
	case "microsoft":
		return "Microsoft"
	case "github":
		return "GitHub"
	default:
		return strings.Title(name)
	}
}