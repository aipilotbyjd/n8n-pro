package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/logger"

	"gorm.io/gorm"
)

// RBACMiddleware provides role-based access control middleware
type RBACMiddleware struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(db *gorm.DB, logger logger.Logger) *RBACMiddleware {
	return &RBACMiddleware{
		db:     db,
		logger: logger,
	}
}

// RequirePermission requires a specific permission
func (m *RBACMiddleware) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := m.checkPermission(r.Context(), permission); err != nil {
				m.writeForbiddenResponse(w, err.Error())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission requires any one of the specified permissions
func (m *RBACMiddleware) RequireAnyPermission(permissions ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var lastErr error
			for _, permission := range permissions {
				if err := m.checkPermission(r.Context(), permission); err == nil {
					next.ServeHTTP(w, r)
					return
				} else {
					lastErr = err
				}
			}
			m.writeForbiddenResponse(w, lastErr.Error())
		})
	}
}

// RequireAllPermissions requires all of the specified permissions
func (m *RBACMiddleware) RequireAllPermissions(permissions ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, permission := range permissions {
				if err := m.checkPermission(r.Context(), permission); err != nil {
					m.writeForbiddenResponse(w, err.Error())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole requires a specific role or higher
func (m *RBACMiddleware) RequireRole(requiredRole RoleType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := GetRole(r.Context())
			if !ok {
				m.writeUnauthorizedResponse(w, "Role information not available")
				return
			}

			if !m.hasRequiredRole(RoleType(userRole), requiredRole) {
				m.writeForbiddenResponse(w, "Insufficient role privileges")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTeamPermission checks permission within a team context
func (m *RBACMiddleware) RequireTeamPermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract team ID from URL parameters or context
			teamID := m.extractTeamIDFromRequest(r)
			if teamID == "" {
				m.writeBadRequestResponse(w, "Team ID is required")
				return
			}

			if err := m.checkTeamPermission(r.Context(), teamID, permission); err != nil {
				m.writeForbiddenResponse(w, err.Error())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireResourceOwnership checks if user owns the resource or has appropriate permissions
func (m *RBACMiddleware) RequireResourceOwnership(resourceType string, fallbackPermission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				m.writeUnauthorizedResponse(w, "User authentication required")
				return
			}

			resourceID := m.extractResourceIDFromRequest(r)
			if resourceID == "" {
				m.writeBadRequestResponse(w, "Resource ID is required")
				return
			}

			// Check if user owns the resource
			if m.isResourceOwner(userID, resourceType, resourceID) {
				next.ServeHTTP(w, r)
				return
			}

			// If not owner, check fallback permission
			if err := m.checkPermission(r.Context(), fallbackPermission); err != nil {
				m.writeForbiddenResponse(w, "Access denied: you must own this resource or have appropriate permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganizationMember ensures user is a member of the organization
func (m *RBACMiddleware) RequireOrganizationMember() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				m.writeUnauthorizedResponse(w, "User authentication required")
				return
			}

			orgID, ok := GetOrganizationID(r.Context())
			if !ok {
				// Try to get from request context or URL
				orgID = m.extractOrganizationIDFromRequest(r)
				if orgID == "" {
					m.writeBadRequestResponse(w, "Organization context is required")
					return
				}
			}

			if !m.isOrganizationMember(userID, orgID) {
				m.writeForbiddenResponse(w, "Access denied: organization membership required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTeamMember ensures user is a member of the team
func (m *RBACMiddleware) RequireTeamMember() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				m.writeUnauthorizedResponse(w, "User authentication required")
				return
			}

			teamID := m.extractTeamIDFromRequest(r)
			if teamID == "" {
				m.writeBadRequestResponse(w, "Team ID is required")
				return
			}

			if !m.isTeamMember(userID, teamID) {
				m.writeForbiddenResponse(w, "Access denied: team membership required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper methods

func (m *RBACMiddleware) checkPermission(ctx context.Context, permission Permission) error {
	userID, ok := GetUserID(ctx)
	if !ok {
		return &RBACError{Code: "AUTHENTICATION_REQUIRED", Message: "User authentication required"}
	}

	role, ok := GetRole(ctx)
	if !ok {
		return &RBACError{Code: "ROLE_REQUIRED", Message: "Role information not available"}
	}

	// Get user's permissions based on role
	userPermissions := GetRolePermissions(RoleType(role))

	// Check if user has the required permission
	if !userPermissions.Has(permission) {
		m.logger.Warn("Permission denied",
			"user_id", userID,
			"role", role,
			"required_permission", string(permission),
		)
		return &RBACError{
			Code:    "INSUFFICIENT_PERMISSIONS",
			Message: "Insufficient permissions for this operation",
		}
	}

	return nil
}

func (m *RBACMiddleware) checkTeamPermission(ctx context.Context, teamID string, permission Permission) error {
	userID, ok := GetUserID(ctx)
	if !ok {
		return &RBACError{Code: "AUTHENTICATION_REQUIRED", Message: "User authentication required"}
	}

	// First check if user has organization-level permission
	if err := m.checkPermission(ctx, permission); err == nil {
		return nil // User has org-level permission
	}

	// Check team-level permission
	var teamMember models.TeamMember
	if err := m.db.Where("team_id = ? AND user_id = ?", teamID, userID).First(&teamMember).Error; err != nil {
		return &RBACError{Code: "TEAM_ACCESS_DENIED", Message: "Access denied to team"}
	}

	teamPermissions := GetRolePermissions(RoleType(teamMember.Role))
	if !teamPermissions.Has(permission) {
		return &RBACError{
			Code:    "INSUFFICIENT_TEAM_PERMISSIONS",
			Message: "Insufficient team permissions for this operation",
		}
	}

	return nil
}

func (m *RBACMiddleware) hasRequiredRole(userRole, requiredRole RoleType) bool {
	roleHierarchy := map[RoleType]int{
		RoleGuest:   1,
		RoleViewer:  2,
		RoleMember:  3,
		RoleAdmin:   4,
		RoleOwner:   5,
		RoleAPIOnly: 2, // Similar to viewer for most purposes
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, requiredExists := roleHierarchy[requiredRole]

	if !userExists || !requiredExists {
		return false
	}

	return userLevel >= requiredLevel
}

func (m *RBACMiddleware) isResourceOwner(userID, resourceType, resourceID string) bool {
	var count int64
	
	switch resourceType {
	case "workflow":
		m.db.Model(&models.Workflow{}).Where("id = ? AND owner_id = ?", resourceID, userID).Count(&count)
	case "team":
		// Check if user is team owner/admin
		m.db.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ? AND role IN (?)", 
			resourceID, userID, []string{"owner", "admin"}).Count(&count)
	default:
		return false
	}

	return count > 0
}

func (m *RBACMiddleware) isOrganizationMember(userID, orgID string) bool {
	var count int64
	m.db.Model(&models.User{}).Where("id = ? AND organization_id = ? AND deleted_at IS NULL", 
		userID, orgID).Count(&count)
	return count > 0
}

func (m *RBACMiddleware) isTeamMember(userID, teamID string) bool {
	var count int64
	m.db.Model(&models.TeamMember{}).Where("user_id = ? AND team_id = ?", 
		userID, teamID).Count(&count)
	return count > 0
}

func (m *RBACMiddleware) extractTeamIDFromRequest(r *http.Request) string {
	// Try to get from URL path parameters
	if teamID := r.PathValue("teamID"); teamID != "" {
		return teamID
	}
	if teamID := r.PathValue("team_id"); teamID != "" {
		return teamID
	}

	// Try to get from query parameters
	if teamID := r.URL.Query().Get("team_id"); teamID != "" {
		return teamID
	}

	// Try to get from context (if set by previous middleware)
	if teamID, ok := GetTeamID(r.Context()); ok {
		return teamID
	}

	return ""
}

func (m *RBACMiddleware) extractResourceIDFromRequest(r *http.Request) string {
	// Try common resource ID patterns
	patterns := []string{"id", "resourceID", "resource_id", "workflowID", "workflow_id", "userID", "user_id"}
	
	for _, pattern := range patterns {
		if id := r.PathValue(pattern); id != "" {
			return id
		}
	}

	return ""
}

func (m *RBACMiddleware) extractOrganizationIDFromRequest(r *http.Request) string {
	// Try to get from URL path parameters
	if orgID := r.PathValue("orgID"); orgID != "" {
		return orgID
	}
	if orgID := r.PathValue("organizationID"); orgID != "" {
		return orgID
	}

	// Try to get from query parameters
	if orgID := r.URL.Query().Get("organization_id"); orgID != "" {
		return orgID
	}

	return ""
}

// Response helpers

func (m *RBACMiddleware) writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	m.writeErrorResponse(w, http.StatusUnauthorized, "Unauthorized", "UNAUTHORIZED", message)
}

func (m *RBACMiddleware) writeForbiddenResponse(w http.ResponseWriter, message string) {
	m.writeErrorResponse(w, http.StatusForbidden, "Forbidden", "FORBIDDEN", message)
}

func (m *RBACMiddleware) writeBadRequestResponse(w http.ResponseWriter, message string) {
	m.writeErrorResponse(w, http.StatusBadRequest, "Bad Request", "BAD_REQUEST", message)
}

func (m *RBACMiddleware) writeErrorResponse(w http.ResponseWriter, statusCode int, error, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":   error,
		"code":    code,
		"message": message,
	}
	
	json.NewEncoder(w).Encode(response)
}

// RBACError represents an RBAC-specific error
type RBACError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RBACError) Error() string {
	return e.Message
}

// Permission checking functions (standalone)

// CheckUserPermission checks if a user has a specific permission
func CheckUserPermission(db *gorm.DB, userID string, permission Permission) error {
	var user models.User
	if err := db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return &RBACError{Code: "USER_NOT_FOUND", Message: "User not found"}
	}

	if user.Status != "active" {
		return &RBACError{Code: "USER_INACTIVE", Message: "User account is not active"}
	}

	userPermissions := GetRolePermissions(RoleType(user.Role))
	if !userPermissions.Has(permission) {
		return &RBACError{
			Code:    "INSUFFICIENT_PERMISSIONS",
			Message: "User does not have required permission",
		}
	}

	return nil
}

// CheckTeamPermission checks if a user has a specific permission within a team
func CheckTeamPermission(db *gorm.DB, userID, teamID string, permission Permission) error {
	// First check organization-level permission
	if err := CheckUserPermission(db, userID, permission); err == nil {
		return nil
	}

	// Check team-level permission
	var teamMember models.TeamMember
	if err := db.Where("team_id = ? AND user_id = ?", teamID, userID).First(&teamMember).Error; err != nil {
		return &RBACError{Code: "TEAM_ACCESS_DENIED", Message: "Access denied to team"}
	}

	teamPermissions := GetRolePermissions(RoleType(teamMember.Role))
	if !teamPermissions.Has(permission) {
		return &RBACError{
			Code:    "INSUFFICIENT_TEAM_PERMISSIONS", 
			Message: "Insufficient team permissions",
		}
	}

	return nil
}

// GetUserPermissions returns all permissions for a user
func GetUserPermissions(db *gorm.DB, userID string) (PermissionSet, error) {
	var user models.User
	if err := db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return nil, &RBACError{Code: "USER_NOT_FOUND", Message: "User not found"}
	}

	return GetRolePermissions(RoleType(user.Role)), nil
}

// FilterResourcesByPermission filters resources based on user permissions
func FilterResourcesByPermission(db *gorm.DB, userID string, resourceType string, permission Permission) ([]string, error) {
	var user models.User
	if err := db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return nil, &RBACError{Code: "USER_NOT_FOUND", Message: "User not found"}
	}

	userPermissions := GetRolePermissions(RoleType(user.Role))

	// If user has admin or the specific permission, return all accessible resources
	if userPermissions.Has(permission) {
		return getAllAccessibleResources(db, userID, resourceType)
	}

	// Otherwise, return only owned resources
	return getOwnedResources(db, userID, resourceType)
}

func getAllAccessibleResources(db *gorm.DB, userID, resourceType string) ([]string, error) {
	var ids []string
	var err error

	switch resourceType {
	case "workflow":
		err = db.Model(&models.Workflow{}).
			Joins("LEFT JOIN team_members ON workflows.team_id = team_members.team_id").
			Where("team_members.user_id = ? OR workflows.owner_id = ?", userID, userID).
			Pluck("workflows.id", &ids).Error
	case "team":
		err = db.Model(&models.TeamMember{}).
			Where("user_id = ?", userID).
			Pluck("team_id", &ids).Error
	default:
		return nil, &RBACError{Code: "UNSUPPORTED_RESOURCE", Message: "Unsupported resource type"}
	}

	return ids, err
}

func getOwnedResources(db *gorm.DB, userID, resourceType string) ([]string, error) {
	var ids []string
	var err error

	switch resourceType {
	case "workflow":
		err = db.Model(&models.Workflow{}).
			Where("owner_id = ?", userID).
			Pluck("id", &ids).Error
	case "team":
		err = db.Model(&models.TeamMember{}).
			Where("user_id = ? AND role IN (?)", userID, []string{"owner", "admin"}).
			Pluck("team_id", &ids).Error
	default:
		return nil, &RBACError{Code: "UNSUPPORTED_RESOURCE", Message: "Unsupported resource type"}
	}

	return ids, err
}