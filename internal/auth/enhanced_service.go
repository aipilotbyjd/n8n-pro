package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
)

// EnhancedAuthService provides comprehensive authentication services with organization support
type EnhancedAuthService struct {
	userRepo         EnhancedUserRepository
	orgRepo          OrganizationRepository
	teamRepo         TeamRepository
	invitationRepo   InvitationRepository
	apiKeyRepo       APIKeyRepository
	auditLogRepo     AuditLogRepository
	sessionRepo      SessionRepository
	jwtService       *jwt.EnhancedService
	logger           logger.Logger
	db               interface{} // Database connection for cleanup
}

// NewEnhancedAuthService creates a new enhanced authentication service
func NewEnhancedAuthService(
	userRepo EnhancedUserRepository,
	orgRepo OrganizationRepository,
	teamRepo TeamRepository,
	invitationRepo InvitationRepository,
	apiKeyRepo APIKeyRepository,
	auditLogRepo AuditLogRepository,
	sessionRepo SessionRepository,
	jwtService *jwt.EnhancedService,
) *EnhancedAuthService {
	return &EnhancedAuthService{
		userRepo:       userRepo,
		orgRepo:        orgRepo,
		teamRepo:       teamRepo,
		invitationRepo: invitationRepo,
		apiKeyRepo:     apiKeyRepo,
		auditLogRepo:   auditLogRepo,
		sessionRepo:    sessionRepo,
		jwtService:     jwtService,
		logger:         logger.New("enhanced-auth-service"),
	}
}

// RegisterRequest contains user registration data
type RegisterRequest struct {
	FirstName      string `json:"first_name" validate:"required,min=1,max=100"`
	LastName       string `json:"last_name" validate:"required,min=1,max=100"`
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required,min=8"`
	OrganizationName string `json:"organization_name,omitempty" validate:"omitempty,min=1,max=100"`
	InvitationToken  string `json:"invitation_token,omitempty"`
}

// LoginRequest contains user login data
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse contains login result data
type LoginResponse struct {
	AccessToken  string              `json:"access_token"`
	RefreshToken string              `json:"refresh_token"`
	TokenType    string              `json:"token_type"`
	ExpiresIn    int64               `json:"expires_in"`
	User         *EnhancedUserInfo   `json:"user"`
	Organization *OrganizationInfo   `json:"organization"`
	Teams        []TeamInfo          `json:"teams,omitempty"`
	SessionID    string              `json:"session_id"`
}

// Authenticate validates user credentials - interface compatibility method
func (s *EnhancedAuthService) Authenticate(ctx context.Context, email, password, ipAddress string) (interface{}, error) {
	// This is a compatibility method for LDAP/SAML UserService interface
	// Use the Login method internally
	req := &LoginRequest{
		Email:    email,
		Password: password,
	}
	return s.Login(ctx, req, ipAddress)
}

// CreateUser creates a new user - interface compatibility method
func (s *EnhancedAuthService) CreateUser(ctx context.Context, userRequest interface{}) (interface{}, error) {
	// This is a compatibility method for LDAP/SAML UserService interface
	// Convert the request to registration format
	userMap, ok := userRequest.(map[string]interface{})
	if !ok {
		return nil, errors.NewValidationError("Invalid user request format")
	}
	
	req := &RegisterRequest{
		Email:            getString(userMap, "email"),
		FirstName:        getString(userMap, "first_name"),
		LastName:         getString(userMap, "last_name"),
		Password:         getString(userMap, "password"),
		OrganizationName: getString(userMap, "organization_name"),
	}
	
	return s.Register(ctx, req, "")
}

// GetUserByEmail gets a user by email - interface compatibility method
func (s *EnhancedAuthService) GetUserByEmail(ctx context.Context, email string) (interface{}, error) {
	// This is a compatibility method for LDAP/SAML UserService interface
	return s.userRepo.GetUserByEmail(ctx, email)
}

// Helper function to safely get string from map
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// EnhancedUserInfo represents user information for API responses
type EnhancedUserInfo struct {
	ID             string      `json:"id"`
	Email          string      `json:"email"`
	FirstName      string      `json:"first_name"`
	LastName       string      `json:"last_name"`
	FullName       string      `json:"full_name"`
	Role           RoleType    `json:"role"`
	Status         UserStatus  `json:"status"`
	EmailVerified  bool        `json:"email_verified"`
	MFAEnabled     bool        `json:"mfa_enabled"`
	Profile        UserProfile `json:"profile"`
	Settings       UserSettings `json:"settings"`
	CreatedAt      time.Time   `json:"created_at"`
	LastLoginAt    *time.Time  `json:"last_login_at"`
}

// OrganizationInfo represents organization information for API responses
type OrganizationInfo struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Slug       string             `json:"slug"`
	Plan       PlanType           `json:"plan"`
	PlanLimits PlanLimits         `json:"plan_limits"`
	Status     OrganizationStatus `json:"status"`
	CreatedAt  time.Time          `json:"created_at"`
}

// TeamInfo represents team information for API responses
type TeamInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	Role        RoleType  `json:"role"`
	MemberCount int       `json:"member_count"`
	JoinedAt    time.Time `json:"joined_at"`
}

// Register creates a new user account, handling both new organization creation and invitation acceptance
func (s *EnhancedAuthService) Register(ctx context.Context, req *RegisterRequest, ipAddress string) (*LoginResponse, error) {
	// Check if registering via invitation
	var invitation *Invitation
	var organization *Organization
	var defaultTeam *Team
	var err error

	if req.InvitationToken != "" {
		// Accept invitation flow
		invitation, err = s.invitationRepo.GetInvitationByToken(ctx, req.InvitationToken)
		if err != nil {
			s.logger.Warn("Invalid invitation token", "token", req.InvitationToken, "error", err)
			return nil, errors.NewValidationError("Invalid or expired invitation token")
		}

		if invitation.Status != InviteStatusPending {
			return nil, errors.NewValidationError("Invitation has already been used or expired")
		}

		// Get organization from invitation
		organization, err = s.orgRepo.GetOrganizationByID(ctx, invitation.OrganizationID)
		if err != nil {
			return nil, errors.InternalError("Failed to get organization")
		}

		// Check if email matches invitation
		if !strings.EqualFold(req.Email, invitation.Email) {
			return nil, errors.NewValidationError("Email does not match invitation")
		}

		// Get team if specified in invitation
		if invitation.TeamID != nil {
			defaultTeam, err = s.teamRepo.GetTeamByID(ctx, *invitation.TeamID)
			if err != nil {
				return nil, errors.InternalError("Failed to get team")
			}
		}
	} else {
		// New organization registration flow
		if req.OrganizationName == "" {
			req.OrganizationName = fmt.Sprintf("%s %s's Organization", req.FirstName, req.LastName)
		}

		// Create new organization
		organization = &Organization{
			ID:         common.GenerateID(),
			Name:       req.OrganizationName,
			Slug:       generateOrgSlug(req.OrganizationName),
			Plan:       PlanFree,
			PlanLimits: GetPlanLimits(PlanFree),
			Settings:   getDefaultOrganizationSettings(),
			Status:     OrgStatusActive,
		}

		err = s.orgRepo.CreateOrganization(ctx, organization)
		if err != nil {
			s.logger.Error("Failed to create organization", "error", err)
			return nil, errors.InternalError("Failed to create organization")
		}

		// Create default team for the organization
		defaultTeam = &Team{
			ID:             common.GenerateID(),
			OrganizationID: organization.ID,
			Name:           "Default Team",
			Description:    stringPtr("Default team for the organization"),
			Settings:       getDefaultTeamSettings(),
		}

		err = s.teamRepo.CreateTeam(ctx, defaultTeam)
		if err != nil {
			s.logger.Error("Failed to create default team", "error", err)
			return nil, errors.InternalError("Failed to create default team")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err)
		return nil, errors.InternalError("Failed to process password")
	}

	// Determine user role
	var userRole RoleType
	if invitation != nil {
		userRole = invitation.Role
	} else {
		userRole = RoleOwner // First user in new org is owner
	}

	// Create user
	user := &EnhancedUser{
		ID:             common.GenerateID(),
		OrganizationID: organization.ID,
		Email:          strings.ToLower(req.Email),
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		PasswordHash:   string(hashedPassword),
		Status:         UserStatusPending, // Requires email verification
		Role:           userRole,
		EmailVerified:  false,
		Profile:        getDefaultUserProfile(),
		Settings:       getDefaultUserSettings(),
		PasswordChangedAt: time.Now(),
	}

	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create user", "error", err, "email", req.Email)
		if strings.Contains(err.Error(), "email already exists") {
			return nil, errors.NewValidationError("An account with this email already exists")
		}
		return nil, errors.InternalError("Failed to create user account")
	}

	// Add user to default team if one exists
	if defaultTeam != nil {
		membership := &TeamMembership{
			ID:       common.GenerateID(),
			TeamID:   defaultTeam.ID,
			UserID:   user.ID,
			Role:     userRole,
			JoinedAt: time.Now(),
		}

		err = s.teamRepo.AddUserToTeam(ctx, membership)
		if err != nil {
			s.logger.Error("Failed to add user to team", "error", err)
			// Non-fatal error, continue
		}
	}

	// If this was an invitation, mark it as accepted
	if invitation != nil {
		now := time.Now()
		invitation.Status = InviteStatusAccepted
		invitation.AcceptedAt = &now
		err = s.invitationRepo.UpdateInvitation(ctx, invitation)
		if err != nil {
			s.logger.Error("Failed to update invitation status", "error", err)
			// Non-fatal error, continue
		}
	}

	// Generate email verification token
	_, err = s.SetEmailVerificationToken(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to generate email verification token", "error", err)
		// Non-fatal error, continue
	}

	// Create audit log
	s.createAuditLog(ctx, organization.ID, &user.ID, "user.registered", "user", user.ID, map[string]interface{}{
		"email":         user.Email,
		"role":          user.Role,
		"via_invitation": invitation != nil,
	}, ipAddress, "n8n-pro-registration")

	// Login the user immediately after registration
	return s.performLogin(ctx, user, organization, ipAddress)
}

// Login authenticates a user and returns tokens
func (s *EnhancedAuthService) Login(ctx context.Context, req *LoginRequest, ipAddress string) (*LoginResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		s.logger.Warn("Login attempt with invalid email", "email", req.Email, "error", err)
		// Use generic error message to prevent email enumeration
		return nil, errors.NewUnauthorizedError("Invalid email or password")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		s.logger.Warn("Login attempt for locked account", "user_id", user.ID, "locked_until", user.LockedUntil)
		return nil, errors.NewUnauthorizedError("Account is temporarily locked due to too many failed login attempts")
	}

	// Check user status
	if user.Status == UserStatusSuspended {
		s.logger.Warn("Login attempt for suspended user", "user_id", user.ID)
		return nil, errors.NewUnauthorizedError("Account is suspended")
	}

	if user.Status == UserStatusInactive {
		s.logger.Warn("Login attempt for inactive user", "user_id", user.ID)
		return nil, errors.NewUnauthorizedError("Account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.logger.Warn("Login attempt with invalid password", "user_id", user.ID, "email", user.Email)

		// Increment failed login attempts
		if err := s.userRepo.IncrementFailedLogin(ctx, user.ID); err != nil {
			s.logger.Error("Failed to increment failed login attempts", "user_id", user.ID, "error", err)
		}

		return nil, errors.NewUnauthorizedError("Invalid email or password")
	}

	// Get organization
	organization, err := s.orgRepo.GetOrganizationByID(ctx, user.OrganizationID)
	if err != nil {
		s.logger.Error("Failed to get user organization", "user_id", user.ID, "org_id", user.OrganizationID, "error", err)
		return nil, errors.InternalError("Failed to get user organization")
	}

	// Check organization status
	if organization.Status != OrgStatusActive && organization.Status != OrgStatusTrial {
		return nil, errors.NewUnauthorizedError("Organization is not active")
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, ipAddress); err != nil {
		s.logger.Error("Failed to update last login", "user_id", user.ID, "error", err)
		// Non-fatal error, continue
	}

	// Create audit log
	s.createAuditLog(ctx, user.OrganizationID, &user.ID, "user.logged_in", "user", user.ID, map[string]interface{}{
		"email": user.Email,
	}, ipAddress, "user-login")

	return s.performLogin(ctx, user, organization, ipAddress)
}

// performLogin creates session and returns login response
func (s *EnhancedAuthService) performLogin(ctx context.Context, user *EnhancedUser, org *Organization, ipAddress string) (*LoginResponse, error) {
	// Generate session ID
	sessionID := jwt.GenerateSessionID()

	// Get user's team memberships
	memberships, err := s.teamRepo.GetUserTeamMemberships(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to get user team memberships", "user_id", user.ID, "error", err)
		// Non-fatal, continue with empty teams
		memberships = []*TeamMembership{}
	}

	// Get primary team (first team or fallback)
	var primaryTeam *Team
	var teamID, teamName, teamPlan string
	if len(memberships) > 0 {
		primaryTeam = memberships[0].Team
		teamID = primaryTeam.ID
		teamName = primaryTeam.Name
		teamPlan = string(org.Plan) // Use org plan for now
	}

	// Generate tokens
	scopes := convertPermissionsToScopes(user.Permissions)
	tokenPair, err := s.jwtService.GenerateEnhancedTokenPair(
		user.ID, user.Email, string(user.Role), user.OrganizationID,
		teamID, teamName, teamPlan, scopes, sessionID,
	)
	if err != nil {
		s.logger.Error("Failed to generate tokens", "user_id", user.ID, "error", err)
		return nil, errors.InternalError("Failed to generate authentication tokens")
	}

	// Create session record
	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: hashRefreshToken(tokenPair.RefreshToken),
		IPAddress:    ipAddress,
		UserAgent:    "n8n-pro-api", // Would be extracted from request headers in real implementation
		IsActive:     true,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	err = s.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		s.logger.Error("Failed to create session", "user_id", user.ID, "error", err)
		// Non-fatal error, continue
	}

	// Convert team memberships to team info
	teams := make([]TeamInfo, len(memberships))
	for i, membership := range memberships {
		teams[i] = TeamInfo{
			ID:          membership.Team.ID,
			Name:        membership.Team.Name,
			Description: membership.Team.Description,
			Role:        membership.Role,
			MemberCount: membership.Team.MemberCount,
			JoinedAt:    membership.JoinedAt,
		}
	}

	return &LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		User: &EnhancedUserInfo{
			ID:            user.ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			FullName:      user.FirstName + " " + user.LastName,
			Role:          user.Role,
			Status:        user.Status,
			EmailVerified: user.EmailVerified,
			MFAEnabled:    user.MFAEnabled,
			Profile:       user.Profile,
			Settings:      user.Settings,
			CreatedAt:     user.CreatedAt,
			LastLoginAt:   user.LastLoginAt,
		},
		Organization: &OrganizationInfo{
			ID:         org.ID,
			Name:       org.Name,
			Slug:       org.Slug,
			Plan:       org.Plan,
			PlanLimits: org.PlanLimits,
			Status:     org.Status,
			CreatedAt:  org.CreatedAt,
		},
		Teams:     teams,
		SessionID: sessionID,
	}, nil
}

// RefreshTokens creates new tokens from refresh token
func (s *EnhancedAuthService) RefreshTokens(ctx context.Context, refreshToken, ipAddress string) (*LoginResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateEnhancedRefreshToken(refreshToken)
	if err != nil {
		s.logger.Warn("Invalid refresh token", "error", err)
		return nil, errors.NewUnauthorizedError("Invalid refresh token")
	}

	// Get session by refresh token hash
	sessionHash := hashRefreshToken(refreshToken)
	session, err := s.sessionRepo.GetSessionByRefreshToken(ctx, sessionHash)
	if err != nil {
		s.logger.Warn("Session not found for refresh token", "error", err)
		return nil, errors.NewUnauthorizedError("Invalid session")
	}

	// Check session validity
	if !session.IsActive || session.RevokedAt != nil || time.Now().After(session.ExpiresAt) {
		return nil, errors.NewUnauthorizedError("Session has expired or been revoked")
	}

	// Get user
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		s.logger.Warn("User not found for refresh token", "user_id", claims.UserID)
		return nil, errors.NewUnauthorizedError("User not found")
	}

	// Check user status
	if user.Status != UserStatusActive {
		return nil, errors.NewUnauthorizedError("User account is not active")
	}

	// Get organization
	org, err := s.orgRepo.GetOrganizationByID(ctx, user.OrganizationID)
	if err != nil {
		return nil, errors.InternalError("Failed to get organization")
	}

	// Update session last seen
	session.LastSeenAt = time.Now()
	if err := s.sessionRepo.UpdateSession(ctx, session); err != nil {
		s.logger.Error("Failed to update session", "session_id", session.ID, "error", err)
		// Non-fatal error, continue
	}

	// Generate new tokens (keeping same session ID)
	return s.performLogin(ctx, user, org, ipAddress)
}

// Logout revokes a user's session
func (s *EnhancedAuthService) Logout(ctx context.Context, accessToken string) error {
	// Extract claims from access token
	claims, err := s.jwtService.ExtractClaimsWithoutValidation(accessToken)
	if err != nil {
		return errors.NewValidationError("Invalid token")
	}

	// Revoke session if session ID is present
	if claims.SessionID != "" {
		if err := s.sessionRepo.RevokeSession(ctx, claims.SessionID); err != nil {
			s.logger.Error("Failed to revoke session", "session_id", claims.SessionID, "error", err)
			// Continue with logout even if session revocation fails
		}
	}

	// Create audit log
	s.createAuditLog(ctx, claims.OrganizationID, &claims.UserID, "user.logged_out", "user", claims.UserID, map[string]interface{}{
		"session_id": claims.SessionID,
	}, "", "user-logout")

	s.logger.Info("User logged out", "user_id", claims.UserID, "session_id", claims.SessionID)
	return nil
}

// SetEmailVerificationToken generates and sets email verification token
func (s *EnhancedAuthService) SetEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	// Generate secure token
	token, err := s.generateSecureToken()
	if err != nil {
		return "", err
	}

	// Set token and expiry
	expiresAt := time.Now().Add(24 * time.Hour)
	user.EmailVerificationToken = &token
	user.EmailVerificationExpiresAt = &expiresAt

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return "", err
	}

	s.logger.Info("Email verification token generated", "user_id", userID)
	return token, nil
}

// VerifyEmail verifies user email using token
func (s *EnhancedAuthService) VerifyEmail(ctx context.Context, token string) (*EnhancedUser, error) {
	user, err := s.userRepo.GetUserByEmailVerificationToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Update user status
	user.EmailVerified = true
	user.EmailVerificationToken = nil
	user.EmailVerificationExpiresAt = nil

	// If user was pending, make them active
	if user.Status == UserStatusPending {
		user.Status = UserStatusActive
	}

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	// Create audit log
	s.createAuditLog(ctx, user.OrganizationID, &user.ID, "user.email_verified", "user", user.ID, nil, "", "email-verification")

	s.logger.Info("Email verified successfully", "user_id", user.ID, "email", user.Email)
	return user, nil
}

// Helper functions

func (s *EnhancedAuthService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func (s *EnhancedAuthService) createAuditLog(ctx context.Context, orgID string, userID *string, action, resource, resourceID string, details map[string]interface{}, ipAddress, userAgent string) {
	auditLog := &AuditLog{
		ID:             common.GenerateID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         action,
		Resource:       resource,
		ResourceID:     &resourceID,
		Details:        details,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
	}

	if err := s.auditLogRepo.CreateAuditLog(ctx, auditLog); err != nil {
		s.logger.Error("Failed to create audit log", "error", err)
		// Non-fatal error
	}
}

func generateOrgSlug(name string) string {
	// Simple slug generation - in production, should be more robust
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	slug = strings.ReplaceAll(slug, "'", "")
	return slug
}

func hashRefreshToken(token string) string {
	// In production, use proper hashing
	return fmt.Sprintf("hash_%s", token[:32])
}

func convertPermissionsToScopes(permissions []Permission) []string {
	scopes := make([]string, len(permissions))
	for i, perm := range permissions {
		scopes[i] = string(perm)
	}
	return scopes
}

func stringPtr(s string) *string {
	return &s
}

func getDefaultOrganizationSettings() OrganizationSettings {
	return OrganizationSettings{
		DefaultTimezone:          "UTC",
		AllowRegistration:        true,
		RequireEmailVerification: true,
		EnforcePasswordPolicy:    true,
		PasswordPolicy: PasswordPolicy{
			MinLength:     8,
			RequireUpper:  true,
			RequireLower:  true,
			RequireDigit:  true,
			RequireSymbol: false,
			MaxAge:        90,
			PreventReuse:  5,
		},
		SessionTimeoutMinutes: 480,
		EnableMFA:             false,
		WebhookSettings: WebhookSettings{
			MaxRetries:       3,
			RetryDelay:       5,
			TimeoutSeconds:   30,
			AllowedHosts:     []string{},
			BlockedHosts:     []string{},
			EnableRateLimit:  true,
			RateLimitPerHour: 1000,
		},
		SecuritySettings: SecuritySettings{
			IPWhitelist:           []string{},
			IPBlacklist:           []string{},
			MaxLoginAttempts:      5,
			AccountLockoutMinutes: 30,
			EnableAuditLog:        true,
			DataEncryptionEnabled: true,
			ApiKeyRotationDays:    90,
		},
		NotificationSettings: map[string]bool{
			"email_workflow_success": false,
			"email_workflow_failure": true,
			"email_security_alerts":  true,
			"slack_notifications":    false,
		},
		DataRegion:     "us-east-1",
		ComplianceMode: "standard",
	}
}

func getDefaultTeamSettings() TeamSettings {
	return TeamSettings{
		DefaultRole:         RoleMember,
		AllowMemberInvite:   true,
		RequireApproval:     false,
		WorkflowSharing:     "team",
		CredentialSharing:   "team",
	}
}

func getDefaultUserProfile() UserProfile {
	return UserProfile{
		AvatarURL:   nil,
		Bio:         nil,
		Location:    nil,
		Website:     nil,
		PhoneNumber: nil,
		JobTitle:    nil,
		Department:  nil,
	}
}

func getDefaultUserSettings() UserSettings {
	return UserSettings{
		Timezone: "UTC",
		Language: "en",
		Theme:    "light",
		NotificationSettings: map[string]bool{
			"email_workflow_success":  false,
			"email_workflow_failure":  true,
			"email_security_alerts":   true,
			"desktop_notifications":   true,
		},
		WorkflowDefaults:  make(map[string]interface{}),
		KeyboardShortcuts: make(map[string]string),
		PrivacySettings: map[string]bool{
			"show_profile":  true,
			"show_activity": false,
		},
	}
}

// GetAllOrganizations gets all organizations (stub)
func (s *EnhancedAuthService) GetAllOrganizations(ctx context.Context, page, limit int, status, search string) ([]*Organization, int, error) {
	// For now, this is a stub - in production you'd use the org repository
	s.logger.Info("Getting all organizations", "page", page, "limit", limit, "status", status, "search", search)
	return []*Organization{}, 0, nil
}

// UpdateOrganizationStatus updates organization status (stub)
func (s *EnhancedAuthService) UpdateOrganizationStatus(ctx context.Context, orgID string, status OrganizationStatus) error {
	// For now, this is a stub - in production you'd use the org repository
	s.logger.Info("Updating organization status", "org_id", orgID, "status", status)
	return nil
}
