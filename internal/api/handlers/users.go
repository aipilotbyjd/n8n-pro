package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	authService *auth.Service
	logger      logger.Logger
}

func NewUserHandler(authService *auth.Service, logger logger.Logger) *UserHandler {
	return &UserHandler{
		authService: authService,
		logger:      logger,
	}
}

type UpdateUserRequest struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type UserResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TeamID   string `json:"team_id"`
	IsActive bool   `json:"is_active"`
}

func (h *UserHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get full user details
	fullUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user details", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	userResponse := UserResponse{
		ID:       fullUser.ID,
		Name:     fullUser.Name,
		Email:    fullUser.Email,
		Role:     fullUser.Role,
		TeamID:   fullUser.TeamID,
		IsActive: fullUser.Active,
	}

	writeSuccess(w, http.StatusOK, userResponse)
}

func (h *UserHandler) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get current user details
	currentUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user for update", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	// Update fields if provided
	updated := false
	if req.Name != "" && req.Name != currentUser.Name {
		currentUser.Name = strings.TrimSpace(req.Name)
		updated = true
	}

	if req.Email != "" && req.Email != currentUser.Email {
		// Validate email format (basic validation)
		if !isValidEmail(req.Email) {
			writeError(w, errors.NewValidationError("Invalid email format"))
			return
		}

		// Check if email is already taken
		existingUser, _ := h.authService.GetUserByEmail(r.Context(), req.Email)
		if existingUser != nil && existingUser.ID != user.ID {
			writeError(w, errors.NewValidationError("Email already exists"))
			return
		}

		currentUser.Email = strings.ToLower(strings.TrimSpace(req.Email))
		updated = true
	}

	if !updated {
		writeError(w, errors.NewValidationError("No fields to update"))
		return
	}

	// Update user
	if err := h.authService.UpdateUser(r.Context(), currentUser); err != nil {
		h.logger.Error("Failed to update user", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to update user"))
		return
	}

	userResponse := UserResponse{
		ID:       currentUser.ID,
		Name:     currentUser.Name,
		Email:    currentUser.Email,
		Role:     currentUser.Role,
		TeamID:   currentUser.TeamID,
		IsActive: currentUser.Active,
	}

	h.logger.Info("User updated successfully", "user_id", user.ID)
	writeSuccess(w, http.StatusOK, userResponse)
}

func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get current user
	currentUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user for password change", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(req.CurrentPassword)); err != nil {
		h.logger.Warn("Invalid current password attempt", "user_id", user.ID)
		writeError(w, errors.NewUnauthorizedError("Current password is incorrect"))
		return
	}

	// Validate new password strength
	if len(req.NewPassword) < 8 {
		writeError(w, errors.NewValidationError("Password must be at least 8 characters long"))
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash new password", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to process new password"))
		return
	}

	// Update password
	currentUser.Password = string(hashedPassword)
	if err := h.authService.UpdateUser(r.Context(), currentUser); err != nil {
		h.logger.Error("Failed to update password", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to update password"))
		return
	}

	response := map[string]interface{}{
		"message": "Password changed successfully",
	}

	h.logger.Info("Password changed successfully", "user_id", user.ID)
	writeSuccess(w, http.StatusOK, response)
}

func (h *UserHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Note: In a real implementation, you might want to:
	// 1. Transfer ownership of workflows to another team member
	// 2. Cancel active executions
	// 3. Clean up associated data
	// 4. Send confirmation email

	// For now, we'll just deactivate the account
	currentUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user for deletion", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	currentUser.Active = false
	if err := h.authService.UpdateUser(r.Context(), currentUser); err != nil {
		h.logger.Error("Failed to deactivate account", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to deactivate account"))
		return
	}

	response := map[string]interface{}{
		"message": "Account deactivated successfully",
	}

	h.logger.Info("Account deactivated", "user_id", user.ID)
	writeSuccess(w, http.StatusOK, response)
}

// Helper function to validate email format
func isValidEmail(email string) bool {
	// Basic email validation - in production, use a proper email validation library
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}
