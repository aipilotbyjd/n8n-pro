package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SimpleAuthHandler handles authentication with GORM models directly
type SimpleAuthHandler struct {
	db         *gorm.DB
	jwtService *jwt.Service
	logger     logger.Logger
}

// NewSimpleAuthHandler creates a new simple auth handler
func NewSimpleAuthHandler(db *gorm.DB, jwtService *jwt.Service, logger logger.Logger) *SimpleAuthHandler {
	return &SimpleAuthHandler{
		db:         db,
		jwtService: jwtService,
		logger:     logger,
	}
}

// SimpleLoginRequest represents login request
type SimpleLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

// SimpleRegisterRequest represents registration request
type SimpleRegisterRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	TeamName string `json:"team_name,omitempty"`
}

// SimpleLoginResponse represents login response
type SimpleLoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	TokenType    string           `json:"token_type"`
	ExpiresIn    int64            `json:"expires_in"`
	User         *SimpleUserInfo  `json:"user"`
}

// SimpleUserInfo represents user information in response
type SimpleUserInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	IsActive bool   `json:"is_active"`
}

// SimpleLogin handles user login
func (h *SimpleAuthHandler) SimpleLogin(w http.ResponseWriter, r *http.Request) {
	var req SimpleLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get user by email using GORM directly
	var user models.User
	result := h.db.Where("email = ? AND deleted_at IS NULL", req.Email).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			h.logger.Warn("Login attempt with invalid email", "email", req.Email)
			writeError(w, errors.NewUnauthorizedError("Invalid credentials"))
			return
		}
		h.logger.Error("Database error during login", "error", result.Error)
		writeError(w, errors.InternalError("Authentication failed"))
		return
	}

	// Check if user is active
	if user.Status != "active" {
		h.logger.Warn("Login attempt for inactive user", "user_id", user.ID, "status", user.Status)
		writeError(w, errors.NewUnauthorizedError("Account is disabled"))
		return
	}

	// Verify password using correct field name (PasswordHash)
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		h.logger.Warn("Login attempt with invalid password", "user_id", user.ID, "email", user.Email)
		
		// Increment failed login attempts
		h.db.Model(&user).UpdateColumn("failed_login_attempts", gorm.Expr("failed_login_attempts + 1"))
		
		writeError(w, errors.NewUnauthorizedError("Invalid credentials"))
		return
	}

	// Generate tokens
	userName := strings.TrimSpace(user.FirstName + " " + user.LastName)
	tokenPair, err := h.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		"", // team_id - we'll get from team_members table later
		"Default Team",
		"premium",
		[]string{"workflows:read", "workflows:write", "workflows:delete", "executions:read"},
	)
	if err != nil {
		h.logger.Error("Failed to generate tokens", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to generate authentication tokens"))
		return
	}

	// Update last login information
	now := time.Now()
	clientIP := getClientIP(r)
	h.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at":         &now,
		"last_login_ip":         clientIP,
		"login_count":           gorm.Expr("login_count + 1"),
		"failed_login_attempts": 0,
		"locked_until":          nil,
	})

	response := SimpleLoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		User: &SimpleUserInfo{
			ID:       user.ID,
			Name:     userName,
			Email:    user.Email,
			Role:     user.Role,
			Status:   user.Status,
			IsActive: user.Status == "active",
		},
	}

	h.logger.Info("User logged in successfully", "user_id", user.ID, "email", user.Email, "ip", clientIP)
	writeSuccess(w, http.StatusOK, response)
}

// SimpleRegister handles user registration
func (h *SimpleAuthHandler) SimpleRegister(w http.ResponseWriter, r *http.Request) {
	var req SimpleRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		writeError(w, errors.NewValidationError("Password must be at least 8 characters long"))
		return
	}

	// Check if user already exists
	var existingUser models.User
	result := h.db.Where("email = ? AND deleted_at IS NULL", req.Email).First(&existingUser)
	if result.Error == nil {
		writeError(w, errors.NewValidationError("User with this email already exists"))
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		writeError(w, errors.InternalError("Failed to process password"))
		return
	}

	// Parse name into first and last name
	nameParts := strings.Fields(req.Name)
	firstName := nameParts[0]
	lastName := ""
	if len(nameParts) > 1 {
		lastName = strings.Join(nameParts[1:], " ")
	}

	// Create organization first
	org := &models.Organization{
		Name:     req.TeamName,
		Slug:     strings.ToLower(strings.ReplaceAll(req.TeamName, " ", "-")),
		Plan:     "free",
		Status:   "active",
		PlanLimits: models.JSONB{
			"max_users":                10,
			"max_workflows":            100,
			"max_executions_per_month": 1000,
		},
		Settings: models.JSONB{
			"timezone":             "UTC",
			"allow_registration":   false,
			"require_verification": true,
		},
	}
	
	if req.TeamName == "" {
		org.Name = firstName + "'s Team"
		org.Slug = strings.ToLower(firstName) + "-team"
	}

	if err := h.db.Create(org).Error; err != nil {
		h.logger.Error("Failed to create organization", "error", err)
		writeError(w, errors.InternalError("Failed to create organization"))
		return
	}

	// Create user
	user := &models.User{
		OrganizationID: org.ID,
		Email:          req.Email,
		FirstName:      firstName,
		LastName:       lastName,
		PasswordHash:   string(hashedPassword),
		Status:         "active", // Auto-activate for now
		Role:           "owner",  // First user is owner
		EmailVerified:  false,    // Will be verified later
		Profile: models.JSONB{
			"job_title": "Owner",
		},
		Settings: models.JSONB{
			"timezone": "UTC",
			"language": "en",
		},
	}

	if err := h.db.Create(user).Error; err != nil {
		h.logger.Error("Failed to create user", "email", req.Email, "error", err)
		writeError(w, errors.InternalError("Failed to create user account"))
		return
	}

	response := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    firstName + " " + lastName,
		"org_id":  user.OrganizationID,
		"message": "User registered successfully",
	}

	h.logger.Info("User registered successfully", "user_id", user.ID, "email", user.Email)
	writeSuccess(w, http.StatusCreated, response)
}

// getClientIP extracts the real client IP from request headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		for i, c := range xff {
			if c == ',' {
				return strings.TrimSpace(xff[:i])
			}
		}
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to remote address
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}
