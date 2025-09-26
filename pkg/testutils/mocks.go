package testutils

import (
	"context"
	"time"

	"n8n-pro/internal/auth"
)

// MockAuthService provides a mock implementation of the authentication service
type MockAuthService struct {
	LoginFunc         func(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error)
	RefreshTokenFunc  func(ctx context.Context, refreshToken string) (*auth.LoginResponse, error)
	LogoutFunc        func(ctx context.Context, sessionID string) error
	LogoutAllFunc     func(ctx context.Context, userID string) error
	ChangePasswordFunc func(ctx context.Context, userID, currentPassword, newPassword string) error
	ResetPasswordFunc func(ctx context.Context, req *auth.ResetPasswordRequest) error
	GetUserFunc       func(ctx context.Context, userID string) (*auth.User, error)
	UpdateUserFunc    func(ctx context.Context, userID string, req *auth.UpdateUserRequest) (*auth.User, error)
	DeleteUserFunc    func(ctx context.Context, userID string) error
	ListUsersFunc     func(ctx context.Context, req *auth.ListUsersRequest) (*auth.ListUsersResponse, error)
	
	// Call tracking
	LoginCalls         []auth.LoginRequest
	RefreshTokenCalls  []string
	LogoutCalls        []string
	LogoutAllCalls     []string
	ChangePasswordCalls []struct {
		UserID, CurrentPassword, NewPassword string
	}
}

// NewMockAuthService creates a new mock authentication service
func NewMockAuthService() *MockAuthService {
	return &MockAuthService{
		LoginCalls:          make([]auth.LoginRequest, 0),
		RefreshTokenCalls:   make([]string, 0),
		LogoutCalls:         make([]string, 0),
		LogoutAllCalls:      make([]string, 0),
		ChangePasswordCalls: make([]struct{ UserID, CurrentPassword, NewPassword string }, 0),
	}
}

// Login mocks user login
func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	m.LoginCalls = append(m.LoginCalls, *req)
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, req)
	}
	
	// Default successful response
	return &auth.LoginResponse{
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		ExpiresIn:    3600,
		User: &auth.User{
			ID:             "user-123",
			Email:          req.Email,
			Name:           "Test User",
			OrganizationID: "org-123",
			Role:           "member",
		},
		SessionID: "session-123",
	}, nil
}

// RefreshToken mocks token refresh
func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*auth.LoginResponse, error) {
	m.RefreshTokenCalls = append(m.RefreshTokenCalls, refreshToken)
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(ctx, refreshToken)
	}
	
	return &auth.LoginResponse{
		AccessToken:  "new-mock-access-token",
		RefreshToken: "new-mock-refresh-token",
		ExpiresIn:    3600,
		User: &auth.User{
			ID:             "user-123",
			Email:          "test@example.com",
			Name:           "Test User",
			OrganizationID: "org-123",
			Role:           "member",
		},
		SessionID: "session-123",
	}, nil
}

// Logout mocks user logout
func (m *MockAuthService) Logout(ctx context.Context, sessionID string) error {
	m.LogoutCalls = append(m.LogoutCalls, sessionID)
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, sessionID)
	}
	return nil
}

// LogoutAll mocks logging out all user sessions
func (m *MockAuthService) LogoutAll(ctx context.Context, userID string) error {
	m.LogoutAllCalls = append(m.LogoutAllCalls, userID)
	if m.LogoutAllFunc != nil {
		return m.LogoutAllFunc(ctx, userID)
	}
	return nil
}

// ChangePassword mocks password change
func (m *MockAuthService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	m.ChangePasswordCalls = append(m.ChangePasswordCalls, struct {
		UserID, CurrentPassword, NewPassword string
	}{userID, currentPassword, newPassword})
	
	if m.ChangePasswordFunc != nil {
		return m.ChangePasswordFunc(ctx, userID, currentPassword, newPassword)
	}
	return nil
}

// GetCallCount returns the number of calls made to a specific method
func (m *MockAuthService) GetCallCount(method string) int {
	switch method {
	case "Login":
		return len(m.LoginCalls)
	case "RefreshToken":
		return len(m.RefreshTokenCalls)
	case "Logout":
		return len(m.LogoutCalls)
	case "LogoutAll":
		return len(m.LogoutAllCalls)
	case "ChangePassword":
		return len(m.ChangePasswordCalls)
	default:
		return 0
	}
}

// Reset clears all call tracking
func (m *MockAuthService) Reset() {
	m.LoginCalls = make([]auth.LoginRequest, 0)
	m.RefreshTokenCalls = make([]string, 0)
	m.LogoutCalls = make([]string, 0)
	m.LogoutAllCalls = make([]string, 0)
	m.ChangePasswordCalls = make([]struct{ UserID, CurrentPassword, NewPassword string }, 0)
}

// MockAPIKeyService provides a mock implementation of the API key service
type MockAPIKeyService struct {
	CreateAPIKeyFunc func(ctx context.Context, req *auth.CreateAPIKeyRequest) (*auth.CreateAPIKeyResponse, error)
	GetAPIKeyFunc    func(ctx context.Context, keyID, userID string) (*auth.APIKey, error)
	ListAPIKeysFunc  func(ctx context.Context, userID string) ([]*auth.APIKey, error)
	UpdateAPIKeyFunc func(ctx context.Context, keyID, userID string, req *auth.UpdateAPIKeyRequest) (*auth.APIKey, error)
	RevokeAPIKeyFunc func(ctx context.Context, keyID, userID string) error
	ValidateAPIKeyFunc func(ctx context.Context, rawKey string) (*auth.APIKey, error)
	
	// Call tracking
	CreateAPIKeyCalls   []auth.CreateAPIKeyRequest
	GetAPIKeyCalls      []struct{ KeyID, UserID string }
	ListAPIKeysCalls    []string
	UpdateAPIKeyCalls   []struct{ KeyID, UserID string; Request auth.UpdateAPIKeyRequest }
	RevokeAPIKeyCalls   []struct{ KeyID, UserID string }
	ValidateAPIKeyCalls []string
}

// NewMockAPIKeyService creates a new mock API key service
func NewMockAPIKeyService() *MockAPIKeyService {
	return &MockAPIKeyService{
		CreateAPIKeyCalls:   make([]auth.CreateAPIKeyRequest, 0),
		GetAPIKeyCalls:      make([]struct{ KeyID, UserID string }, 0),
		ListAPIKeysCalls:    make([]string, 0),
		UpdateAPIKeyCalls:   make([]struct{ KeyID, UserID string; Request auth.UpdateAPIKeyRequest }, 0),
		RevokeAPIKeyCalls:   make([]struct{ KeyID, UserID string }, 0),
		ValidateAPIKeyCalls: make([]string, 0),
	}
}

// CreateAPIKey mocks API key creation
func (m *MockAPIKeyService) CreateAPIKey(ctx context.Context, req *auth.CreateAPIKeyRequest) (*auth.CreateAPIKeyResponse, error) {
	m.CreateAPIKeyCalls = append(m.CreateAPIKeyCalls, *req)
	if m.CreateAPIKeyFunc != nil {
		return m.CreateAPIKeyFunc(ctx, req)
	}
	
	return &auth.CreateAPIKeyResponse{
		APIKey: &auth.APIKey{
			ID:             "key-123",
			UserID:         req.UserID,
			OrganizationID: req.OrganizationID,
			Name:           req.Name,
			Permissions:    req.Permissions,
			Scopes:         req.Scopes,
			ExpiresAt:      req.ExpiresAt,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		RawKey: "n8n_" + "mock-raw-key-" + "1234567890abcdef",
	}, nil
}

// ValidateAPIKey mocks API key validation
func (m *MockAPIKeyService) ValidateAPIKey(ctx context.Context, rawKey string) (*auth.APIKey, error) {
	m.ValidateAPIKeyCalls = append(m.ValidateAPIKeyCalls, rawKey)
	if m.ValidateAPIKeyFunc != nil {
		return m.ValidateAPIKeyFunc(ctx, rawKey)
	}
	
	return &auth.APIKey{
		ID:             "key-123",
		UserID:         "user-123",
		OrganizationID: "org-123",
		Name:           "Test API Key",
		Permissions:    []string{"workflows:read", "workflows:write"},
		Scopes:         []string{"api"},
		ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
		LastUsedAt:     &time.Time{},
		UsageCount:     10,
		CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:      time.Now(),
	}, nil
}

// Reset clears all call tracking
func (m *MockAPIKeyService) Reset() {
	m.CreateAPIKeyCalls = make([]auth.CreateAPIKeyRequest, 0)
	m.GetAPIKeyCalls = make([]struct{ KeyID, UserID string }, 0)
	m.ListAPIKeysCalls = make([]string, 0)
	m.UpdateAPIKeyCalls = make([]struct{ KeyID, UserID string; Request auth.UpdateAPIKeyRequest }, 0)
	m.RevokeAPIKeyCalls = make([]struct{ KeyID, UserID string }, 0)
	m.ValidateAPIKeyCalls = make([]string, 0)
}

// MockSessionRepository provides a mock implementation of the session repository
type MockSessionRepository struct {
	CreateFunc                func(ctx context.Context, session *auth.Session) error
	FindByIDFunc             func(ctx context.Context, sessionID string) (*auth.Session, error)
	FindByRefreshTokenFunc   func(ctx context.Context, refreshToken string) (*auth.Session, error)
	FindActiveByUserIDFunc   func(ctx context.Context, userID string) ([]*auth.Session, error)
	UpdateFunc               func(ctx context.Context, session *auth.Session) error
	RevokeFunc               func(ctx context.Context, sessionID string) error
	RevokeAllUserSessionsFunc func(ctx context.Context, userID string) error
	CleanupExpiredSessionsFunc func(ctx context.Context) error
	
	// In-memory storage for testing
	Sessions map[string]*auth.Session
	
	// Call tracking
	CreateCalls                []auth.Session
	FindByIDCalls             []string
	FindByRefreshTokenCalls   []string
	FindActiveByUserIDCalls   []string
	UpdateCalls               []auth.Session
	RevokeCalls               []string
	RevokeAllUserSessionsCalls []string
	CleanupExpiredSessionsCalls int
}

// NewMockSessionRepository creates a new mock session repository
func NewMockSessionRepository() *MockSessionRepository {
	return &MockSessionRepository{
		Sessions:                    make(map[string]*auth.Session),
		CreateCalls:                make([]auth.Session, 0),
		FindByIDCalls:              make([]string, 0),
		FindByRefreshTokenCalls:    make([]string, 0),
		FindActiveByUserIDCalls:    make([]string, 0),
		UpdateCalls:                make([]auth.Session, 0),
		RevokeCalls:                make([]string, 0),
		RevokeAllUserSessionsCalls: make([]string, 0),
	}
}

// Create mocks session creation
func (m *MockSessionRepository) Create(ctx context.Context, session *auth.Session) error {
	m.CreateCalls = append(m.CreateCalls, *session)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, session)
	}
	
	m.Sessions[session.ID] = session
	return nil
}

// FindByRefreshToken mocks finding session by refresh token
func (m *MockSessionRepository) FindByRefreshToken(ctx context.Context, refreshToken string) (*auth.Session, error) {
	m.FindByRefreshTokenCalls = append(m.FindByRefreshTokenCalls, refreshToken)
	if m.FindByRefreshTokenFunc != nil {
		return m.FindByRefreshTokenFunc(ctx, refreshToken)
	}
	
	// Find session with matching refresh token
	for _, session := range m.Sessions {
		if session.RefreshToken == refreshToken && !session.RevokedAt.Valid {
			return session, nil
		}
	}
	
	return nil, auth.ErrSessionNotFound
}

// Reset clears all call tracking and sessions
func (m *MockSessionRepository) Reset() {
	m.Sessions = make(map[string]*auth.Session)
	m.CreateCalls = make([]auth.Session, 0)
	m.FindByIDCalls = make([]string, 0)
	m.FindByRefreshTokenCalls = make([]string, 0)
	m.FindActiveByUserIDCalls = make([]string, 0)
	m.UpdateCalls = make([]auth.Session, 0)
	m.RevokeCalls = make([]string, 0)
	m.RevokeAllUserSessionsCalls = make([]string, 0)
	m.CleanupExpiredSessionsCalls = 0
}

// MockRateLimitService provides a mock implementation of the rate limit service
type MockRateLimitService struct {
	CheckRateLimitFunc         func(ctx context.Context, limitType auth.RateLimitType, key string, metadata map[string]interface{}) (*auth.RateLimitResult, error)
	CheckMultipleRateLimitsFunc func(ctx context.Context, checks []auth.RateLimitCheck) (*auth.RateLimitResult, error)
	GetRateLimitStatusFunc     func(ctx context.Context, limitType auth.RateLimitType, key string) (*auth.RateLimitStatus, error)
	ResetRateLimitFunc         func(ctx context.Context, limitType auth.RateLimitType, key string) error
	
	// Call tracking
	CheckRateLimitCalls         []struct{ LimitType auth.RateLimitType; Key string; Metadata map[string]interface{} }
	CheckMultipleRateLimitsCalls [][]auth.RateLimitCheck
	GetRateLimitStatusCalls     []struct{ LimitType auth.RateLimitType; Key string }
	ResetRateLimitCalls         []struct{ LimitType auth.RateLimitType; Key string }
	
	// Rate limit state for testing
	RateLimits map[string]int
}

// NewMockRateLimitService creates a new mock rate limit service
func NewMockRateLimitService() *MockRateLimitService {
	return &MockRateLimitService{
		CheckRateLimitCalls:          make([]struct{ LimitType auth.RateLimitType; Key string; Metadata map[string]interface{} }, 0),
		CheckMultipleRateLimitsCalls: make([][]auth.RateLimitCheck, 0),
		GetRateLimitStatusCalls:      make([]struct{ LimitType auth.RateLimitType; Key string }, 0),
		ResetRateLimitCalls:          make([]struct{ LimitType auth.RateLimitType; Key string }, 0),
		RateLimits:                   make(map[string]int),
	}
}

// CheckRateLimit mocks rate limit checking
func (m *MockRateLimitService) CheckRateLimit(ctx context.Context, limitType auth.RateLimitType, key string, metadata map[string]interface{}) (*auth.RateLimitResult, error) {
	m.CheckRateLimitCalls = append(m.CheckRateLimitCalls, struct {
		LimitType auth.RateLimitType
		Key       string
		Metadata  map[string]interface{}
	}{limitType, key, metadata})
	
	if m.CheckRateLimitFunc != nil {
		return m.CheckRateLimitFunc(ctx, limitType, key, metadata)
	}
	
	// Default: allow request
	limitKey := string(limitType) + ":" + key
	current := m.RateLimits[limitKey]
	m.RateLimits[limitKey] = current + 1
	
	return &auth.RateLimitResult{
		Allowed:   true,
		Limit:     100,
		Remaining: 99 - current,
		ResetAt:   time.Now().Add(time.Hour),
	}, nil
}

// Reset clears all call tracking and rate limits
func (m *MockRateLimitService) Reset() {
	m.CheckRateLimitCalls = make([]struct{ LimitType auth.RateLimitType; Key string; Metadata map[string]interface{} }, 0)
	m.CheckMultipleRateLimitsCalls = make([][]auth.RateLimitCheck, 0)
	m.GetRateLimitStatusCalls = make([]struct{ LimitType auth.RateLimitType; Key string }, 0)
	m.ResetRateLimitCalls = make([]struct{ LimitType auth.RateLimitType; Key string }, 0)
	m.RateLimits = make(map[string]int)
}

// MockJWTService provides a mock implementation of JWT service
type MockJWTService struct {
	GenerateTokenFunc  func(userID, email, role string) (string, error)
	ValidateTokenFunc  func(token string) (*auth.Claims, error)
	RefreshTokenFunc   func(refreshToken string) (string, string, error)
	RevokeTokenFunc    func(token string) error
	
	// Call tracking
	GenerateTokenCalls []struct{ UserID, Email, Role string }
	ValidateTokenCalls []string
	RefreshTokenCalls  []string
	RevokeTokenCalls   []string
	
	// Token storage for testing
	ValidTokens   map[string]*auth.Claims
	RevokedTokens map[string]bool
}

// NewMockJWTService creates a new mock JWT service
func NewMockJWTService() *MockJWTService {
	return &MockJWTService{
		GenerateTokenCalls: make([]struct{ UserID, Email, Role string }, 0),
		ValidateTokenCalls: make([]string, 0),
		RefreshTokenCalls:  make([]string, 0),
		RevokeTokenCalls:   make([]string, 0),
		ValidTokens:        make(map[string]*auth.Claims),
		RevokedTokens:      make(map[string]bool),
	}
}

// GenerateToken mocks token generation
func (m *MockJWTService) GenerateToken(userID, email, role string) (string, error) {
	m.GenerateTokenCalls = append(m.GenerateTokenCalls, struct{ UserID, Email, Role string }{userID, email, role})
	
	if m.GenerateTokenFunc != nil {
		return m.GenerateTokenFunc(userID, email, role)
	}
	
	token := "mock-jwt-token-" + userID
	claims := &auth.Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	m.ValidTokens[token] = claims
	
	return token, nil
}

// ValidateToken mocks token validation
func (m *MockJWTService) ValidateToken(token string) (*auth.Claims, error) {
	m.ValidateTokenCalls = append(m.ValidateTokenCalls, token)
	
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(token)
	}
	
	// Check if token is revoked
	if m.RevokedTokens[token] {
		return nil, auth.ErrTokenRevoked
	}
	
	// Check if token exists and is valid
	if claims, exists := m.ValidTokens[token]; exists {
		if claims.ExpiresAt.After(time.Now()) {
			return claims, nil
		}
		return nil, auth.ErrTokenExpired
	}
	
	return nil, auth.ErrTokenInvalid
}

// Reset clears all call tracking and tokens
func (m *MockJWTService) Reset() {
	m.GenerateTokenCalls = make([]struct{ UserID, Email, Role string }, 0)
	m.ValidateTokenCalls = make([]string, 0)
	m.RefreshTokenCalls = make([]string, 0)
	m.RevokeTokenCalls = make([]string, 0)
	m.ValidTokens = make(map[string]*auth.Claims)
	m.RevokedTokens = make(map[string]bool)
}

// Test data factory functions

// CreateTestUser creates a test user for testing
func CreateTestUser(overrides ...func(*auth.User)) *auth.User {
	user := &auth.User{
		ID:             "user-123",
		Email:          "test@example.com",
		Name:           "Test User",
		OrganizationID: "org-123",
		Role:           "member",
		EmailVerified:  true,
		Active:         true,
		CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:      time.Now(),
	}
	
	for _, override := range overrides {
		override(user)
	}
	
	return user
}

// CreateTestSession creates a test session for testing
func CreateTestSession(userID string, overrides ...func(*auth.Session)) *auth.Session {
	session := &auth.Session{
		ID:           "session-123",
		UserID:       userID,
		RefreshToken: "refresh-token-123",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0 Test Browser",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	for _, override := range overrides {
		override(session)
	}
	
	return session
}

// CreateTestAPIKey creates a test API key for testing
func CreateTestAPIKey(userID string, overrides ...func(*auth.APIKey)) *auth.APIKey {
	apiKey := &auth.APIKey{
		ID:             "key-123",
		UserID:         userID,
		OrganizationID: "org-123",
		Name:           "Test API Key",
		Permissions:    []string{"workflows:read", "workflows:write"},
		Scopes:         []string{"api"},
		ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
		UsageCount:     0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	
	for _, override := range overrides {
		override(apiKey)
	}
	
	return apiKey
}

// CreateTestLoginRequest creates a test login request
func CreateTestLoginRequest(overrides ...func(*auth.LoginRequest)) *auth.LoginRequest {
	req := &auth.LoginRequest{
		Email:     "test@example.com",
		Password:  "securePassword123!",
		RememberMe: false,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0 Test Browser",
	}
	
	for _, override := range overrides {
		override(req)
	}
	
	return req
}