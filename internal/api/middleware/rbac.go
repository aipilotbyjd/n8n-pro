package middleware

import (
	"net/http"

	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/gorilla/mux"
)

// RBACMiddleware provides role-based access control middleware
type RBACMiddleware struct {
	rbacService *auth.RBACService
	logger      logger.Logger
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(rbacService *auth.RBACService, logger logger.Logger) *RBACMiddleware {
	return &RBACMiddleware{
		rbacService: rbacService,
		logger:      logger,
	}
}

// RequirePermission creates middleware that requires a specific permission
func (m *RBACMiddleware) RequirePermission(permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			err := m.rbacService.CheckPermission(r.Context(), user.ID, permission)
			if err != nil {
				m.logger.Warn("RBAC permission denied", 
					"user_id", user.ID, 
					"permission", permission, 
					"path", r.URL.Path, 
					"method", r.Method, 
					"error", err.Error())
				writeError(w, err)
				return
			}

			m.logger.Debug("RBAC permission granted", 
				"user_id", user.ID, 
				"permission", permission, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermissions creates middleware that requires all specified permissions
func (m *RBACMiddleware) RequirePermissions(permissions ...auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			err := m.rbacService.CheckPermissions(r.Context(), user.ID, permissions...)
			if err != nil {
				m.logger.Warn("RBAC permissions denied", 
					"user_id", user.ID, 
					"permissions", permissions, 
					"path", r.URL.Path, 
					"method", r.Method, 
					"error", err.Error())
				writeError(w, err)
				return
			}

			m.logger.Debug("RBAC permissions granted", 
				"user_id", user.ID, 
				"permissions", permissions, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates middleware that requires any of the specified permissions
func (m *RBACMiddleware) RequireAnyPermission(permissions ...auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			err := m.rbacService.CheckAnyPermission(r.Context(), user.ID, permissions...)
			if err != nil {
				m.logger.Warn("RBAC any permission denied", 
					"user_id", user.ID, 
					"permissions", permissions, 
					"path", r.URL.Path, 
					"method", r.Method, 
					"error", err.Error())
				writeError(w, err)
				return
			}

			m.logger.Debug("RBAC any permission granted", 
				"user_id", user.ID, 
				"permissions", permissions, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole creates middleware that requires a specific role or higher
func (m *RBACMiddleware) RequireRole(minimumRole auth.RoleType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC role check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			// Convert string role to RoleType
			userRoleType := auth.RoleType(user.Role)
			if !auth.IsHigherRole(userRoleType, minimumRole) && userRoleType != minimumRole {
				m.logger.Warn("RBAC role denied", 
					"user_id", user.ID, 
					"user_role", user.Role, 
					"required_role", minimumRole, 
					"path", r.URL.Path, 
					"method", r.Method)
				writeError(w, errors.NewForbiddenError("Insufficient role privileges"))
				return
			}

			m.logger.Debug("RBAC role granted", 
				"user_id", user.ID, 
				"user_role", user.Role, 
				"required_role", minimumRole, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTeamPermission creates middleware that requires a team-specific permission
func (m *RBACMiddleware) RequireTeamPermission(permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC team check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			// Extract team ID from URL parameters
			vars := mux.Vars(r)
			teamID := vars["teamID"]
			if teamID == "" {
				m.logger.Warn("RBAC team check failed: no team ID in URL", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewValidationError("Team ID is required"))
				return
			}

			err := m.rbacService.CheckTeamPermission(r.Context(), user.ID, teamID, permission)
			if err != nil {
				m.logger.Warn("RBAC team permission denied", 
					"user_id", user.ID, 
					"team_id", teamID, 
					"permission", permission, 
					"path", r.URL.Path, 
					"method", r.Method, 
					"error", err.Error())
				writeError(w, err)
				return
			}

			m.logger.Debug("RBAC team permission granted", 
				"user_id", user.ID, 
				"team_id", teamID, 
				"permission", permission, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireResourceOwnership creates middleware that requires resource ownership or specific permission
func (m *RBACMiddleware) RequireResourceOwnership(resourceType string, permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.logger.Warn("RBAC resource check failed: no user in context", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewUnauthorizedError("Authentication required"))
				return
			}

			// Extract resource ID from URL parameters
			vars := mux.Vars(r)
			resourceID := vars["id"]
			if resourceID == "" {
				// Try other common parameter names
				resourceID = vars["resourceID"]
				if resourceID == "" {
					resourceID = vars["workflowID"]
				}
				if resourceID == "" {
					resourceID = vars["executionID"]
				}
				if resourceID == "" {
					resourceID = vars["credentialID"]
				}
			}

			if resourceID == "" {
				m.logger.Warn("RBAC resource check failed: no resource ID in URL", "path", r.URL.Path, "method", r.Method)
				writeError(w, errors.NewValidationError("Resource ID is required"))
				return
			}

			// TODO: Implement resource ownership check
			// For now, just check the permission
			err := m.rbacService.CheckPermission(r.Context(), user.ID, permission)
			if err != nil {
				m.logger.Warn("RBAC resource permission denied", 
					"user_id", user.ID, 
					"resource_id", resourceID, 
					"resource_type", resourceType, 
					"permission", permission, 
					"path", r.URL.Path, 
					"method", r.Method, 
					"error", err.Error())
				writeError(w, err)
				return
			}

			m.logger.Debug("RBAC resource permission granted", 
				"user_id", user.ID, 
				"resource_id", resourceID, 
				"resource_type", resourceType, 
				"permission", permission, 
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnerOrAdmin creates middleware for owner/admin only operations
func (m *RBACMiddleware) RequireOwnerOrAdmin() func(http.Handler) http.Handler {
	return m.RequireAnyPermission(auth.PermissionAdminAll, auth.PermissionOrgManageMembers)
}

// RequireAdminOrTeamAdmin creates middleware for admin or team admin operations
func (m *RBACMiddleware) RequireAdminOrTeamAdmin() func(http.Handler) http.Handler {
	return m.RequireAnyPermission(
		auth.PermissionAdminAll, 
		auth.PermissionTeamManageMembers,
		auth.PermissionOrgManageMembers,
	)
}

// LogPermissions creates middleware that logs user permissions (for debugging)
func (m *RBACMiddleware) LogPermissions() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user != nil {
				permissions, err := m.rbacService.GetUserPermissions(r.Context(), user.ID)
				if err == nil {
					m.logger.Debug("User permissions", 
						"user_id", user.ID, 
						"role", user.Role, 
						"permissions", permissions.ToSlice(), 
						"path", r.URL.Path)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Helper function to write error responses (duplicated from other middleware for consistency)
func writeError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	
	if apiError, ok := err.(*errors.APIError); ok {
		w.WriteHeader(apiError.HTTPStatus())
		w.Write([]byte(`{"error": "` + apiError.Message + `", "code": "` + string(apiError.Code) + `"}`))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error", "code": "INTERNAL_ERROR"}`))
	}
}