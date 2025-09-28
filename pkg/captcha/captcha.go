package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
)

// Service interface for CAPTCHA operations
type Service interface {
	Verify(ctx context.Context, token string, action string) (float64, error)
	VerifyWithThreshold(ctx context.Context, token string, action string, threshold float64) (bool, error)
}

// Provider represents different CAPTCHA providers
type Provider string

const (
	ProviderGoogle   Provider = "google"
	ProviderHCaptcha Provider = "hcaptcha"
	ProviderTurnstile Provider = "turnstile" // Cloudflare Turnstile
)

// Config contains CAPTCHA service configuration
type Config struct {
	Provider      Provider      `json:"provider"`
	SiteKey       string        `json:"site_key"`
	SecretKey     string        `json:"secret_key"`
	ScoreThreshold float64      `json:"score_threshold"`
	Timeout       time.Duration `json:"timeout"`
	SkipVerify    bool          `json:"skip_verify"` // For testing
	AllowedActions []string     `json:"allowed_actions"`
}

// DefaultConfig returns default CAPTCHA configuration
func DefaultConfig() *Config {
	return &Config{
		Provider:       ProviderGoogle,
		ScoreThreshold: 0.5,
		Timeout:        5 * time.Second,
		SkipVerify:     false,
		AllowedActions: []string{"login", "register", "password_reset"},
	}
}

// GoogleRecaptchaService implements Google reCAPTCHA v3
type GoogleRecaptchaService struct {
	config     *Config
	httpClient *http.Client
	logger     logger.Logger
}

// NewGoogleRecaptchaService creates a new Google reCAPTCHA service
func NewGoogleRecaptchaService(config *Config) *GoogleRecaptchaService {
	if config == nil {
		config = DefaultConfig()
	}

	return &GoogleRecaptchaService{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger.New("recaptcha"),
	}
}

// GoogleResponse represents the response from Google reCAPTCHA API
type GoogleResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
}

// Verify verifies a reCAPTCHA token and returns the score
func (s *GoogleRecaptchaService) Verify(ctx context.Context, token string, action string) (float64, error) {
	// Skip verification in test mode
	if s.config.SkipVerify {
		s.logger.Warn("CAPTCHA verification skipped (test mode)")
		return 1.0, nil
	}

	// Validate inputs
	if token == "" {
		return 0, fmt.Errorf("captcha token is required")
	}

	if s.config.SecretKey == "" {
		return 0, fmt.Errorf("captcha secret key not configured")
	}

	// Check if action is allowed
	if !s.isActionAllowed(action) {
		return 0, fmt.Errorf("action '%s' is not allowed", action)
	}

	// Prepare request
	verifyURL := "https://www.google.com/recaptcha/api/siteverify"
	
	form := url.Values{}
	form.Set("secret", s.config.SecretKey)
	form.Set("response", token)
	
	// Add remote IP if available from context
	if remoteIP, ok := ctx.Value("remote_ip").(string); ok && remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("Failed to verify captcha", "error", err)
		return 0, fmt.Errorf("failed to verify captcha: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var googleResp GoogleResponse
	if err := json.Unmarshal(body, &googleResp); err != nil {
		s.logger.Error("Failed to parse captcha response", "error", err, "body", string(body))
		return 0, fmt.Errorf("failed to parse captcha response: %w", err)
	}

	// Check for errors
	if !googleResp.Success {
		errorMsg := "captcha verification failed"
		if len(googleResp.ErrorCodes) > 0 {
			errorMsg = fmt.Sprintf("%s: %s", errorMsg, strings.Join(googleResp.ErrorCodes, ", "))
		}
		s.logger.Error("Captcha verification failed", "errors", googleResp.ErrorCodes)
		return 0, fmt.Errorf(errorMsg)
	}

	// Verify action matches
	if googleResp.Action != action {
		s.logger.Warn("Captcha action mismatch", "expected", action, "got", googleResp.Action)
		return 0, fmt.Errorf("captcha action mismatch")
	}

	// Log successful verification
	s.logger.Info("Captcha verified successfully", 
		"action", action, 
		"score", googleResp.Score,
		"hostname", googleResp.Hostname)

	return googleResp.Score, nil
}

// VerifyWithThreshold verifies a token and checks if score meets threshold
func (s *GoogleRecaptchaService) VerifyWithThreshold(ctx context.Context, token string, action string, threshold float64) (bool, error) {
	score, err := s.Verify(ctx, token, action)
	if err != nil {
		return false, err
	}

	if threshold <= 0 {
		threshold = s.config.ScoreThreshold
	}

	passed := score >= threshold
	
	if !passed {
		s.logger.Warn("Captcha score below threshold", 
			"score", score, 
			"threshold", threshold,
			"action", action)
	}

	return passed, nil
}

// isActionAllowed checks if an action is in the allowed list
func (s *GoogleRecaptchaService) isActionAllowed(action string) bool {
	if len(s.config.AllowedActions) == 0 {
		return true // No restrictions
	}

	for _, allowed := range s.config.AllowedActions {
		if allowed == action || allowed == "*" {
			return true
		}
	}

	return false
}

// HCaptchaService implements hCaptcha
type HCaptchaService struct {
	config     *Config
	httpClient *http.Client
	logger     logger.Logger
}

// NewHCaptchaService creates a new hCaptcha service
func NewHCaptchaService(config *Config) *HCaptchaService {
	if config == nil {
		config = DefaultConfig()
		config.Provider = ProviderHCaptcha
	}

	return &HCaptchaService{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger.New("hcaptcha"),
	}
}

// HCaptchaResponse represents the response from hCaptcha API
type HCaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Credit      bool     `json:"credit,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	Score       float64  `json:"score,omitempty"` // Enterprise only
	ScoreReasons []string `json:"score_reason,omitempty"`
}

// Verify verifies an hCaptcha token
func (s *HCaptchaService) Verify(ctx context.Context, token string, action string) (float64, error) {
	// Skip verification in test mode
	if s.config.SkipVerify {
		s.logger.Warn("CAPTCHA verification skipped (test mode)")
		return 1.0, nil
	}

	// Validate inputs
	if token == "" {
		return 0, fmt.Errorf("captcha token is required")
	}

	if s.config.SecretKey == "" {
		return 0, fmt.Errorf("captcha secret key not configured")
	}

	// Prepare request
	verifyURL := "https://hcaptcha.com/siteverify"
	
	form := url.Values{}
	form.Set("secret", s.config.SecretKey)
	form.Set("response", token)
	
	// Add remote IP if available
	if remoteIP, ok := ctx.Value("remote_ip").(string); ok && remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	// Add sitekey
	if s.config.SiteKey != "" {
		form.Set("sitekey", s.config.SiteKey)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("Failed to verify captcha", "error", err)
		return 0, fmt.Errorf("failed to verify captcha: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var hcaptchaResp HCaptchaResponse
	if err := json.Unmarshal(body, &hcaptchaResp); err != nil {
		s.logger.Error("Failed to parse captcha response", "error", err, "body", string(body))
		return 0, fmt.Errorf("failed to parse captcha response: %w", err)
	}

	// Check for errors
	if !hcaptchaResp.Success {
		errorMsg := "captcha verification failed"
		if len(hcaptchaResp.ErrorCodes) > 0 {
			errorMsg = fmt.Sprintf("%s: %s", errorMsg, strings.Join(hcaptchaResp.ErrorCodes, ", "))
		}
		s.logger.Error("Captcha verification failed", "errors", hcaptchaResp.ErrorCodes)
		return 0, fmt.Errorf(errorMsg)
	}

	// Log successful verification
	s.logger.Info("Captcha verified successfully", 
		"hostname", hcaptchaResp.Hostname,
		"credit", hcaptchaResp.Credit)

	// hCaptcha doesn't return scores for non-enterprise
	// Return 1.0 for successful verification
	if hcaptchaResp.Score > 0 {
		return hcaptchaResp.Score, nil
	}

	return 1.0, nil
}

// VerifyWithThreshold verifies a token and checks if it passes
func (s *HCaptchaService) VerifyWithThreshold(ctx context.Context, token string, action string, threshold float64) (bool, error) {
	score, err := s.Verify(ctx, token, action)
	if err != nil {
		return false, err
	}

	// For hCaptcha, success means score is 1.0
	return score >= threshold, nil
}

// MockCaptchaService for testing
type MockCaptchaService struct {
	ShouldPass bool
	Score      float64
}

// NewMockCaptchaService creates a mock service for testing
func NewMockCaptchaService(shouldPass bool, score float64) *MockCaptchaService {
	return &MockCaptchaService{
		ShouldPass: shouldPass,
		Score:      score,
	}
}

// Verify mocks verification
func (m *MockCaptchaService) Verify(ctx context.Context, token string, action string) (float64, error) {
	if !m.ShouldPass {
		return 0, fmt.Errorf("mock captcha verification failed")
	}
	return m.Score, nil
}

// VerifyWithThreshold mocks verification with threshold
func (m *MockCaptchaService) VerifyWithThreshold(ctx context.Context, token string, action string, threshold float64) (bool, error) {
	if !m.ShouldPass {
		return false, fmt.Errorf("mock captcha verification failed")
	}
	return m.Score >= threshold, nil
}

// Factory function to create appropriate service based on provider
func NewService(config *Config) (Service, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	switch config.Provider {
	case ProviderGoogle:
		return NewGoogleRecaptchaService(config), nil
	case ProviderHCaptcha:
		return NewHCaptchaService(config), nil
	case ProviderTurnstile:
		// Cloudflare Turnstile can be implemented similarly
		return nil, fmt.Errorf("turnstile provider not yet implemented")
	default:
		return nil, fmt.Errorf("unknown captcha provider: %s", config.Provider)
	}
}