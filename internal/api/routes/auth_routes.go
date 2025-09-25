package routes

import (
	"net/http"

	"n8n-pro/internal/api/handlers"
	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/pkg/logger"

	"github.com/gorilla/mux"
)

// AuthRoutes sets up all authentication-related routes
func SetupAuthRoutes(
	router *mux.Router,
	authHandler *handlers.AuthHandler,
	orgHandler *handlers.OrganizationHandler,
	teamHandler *handlers.TeamHandler,
	authMiddleware *middleware.AuthMiddleware,
	rbacMiddleware *middleware.RBACMiddleware,
	logger logger.Logger,
) {
	// Create subrouters
	publicRouter := router.PathPrefix("/api/v1").Subrouter()
	protectedRouter := router.PathPrefix("/api/v1").Subrouter()

	// Apply authentication middleware to protected routes
	protectedRouter.Use(authMiddleware.RequireAuth)

	// Public authentication endpoints (no auth required)
	setupPublicAuthRoutes(publicRouter, authHandler)

	// Protected user management endpoints
	setupUserRoutes(protectedRouter, authHandler, rbacMiddleware)

	// Organization management endpoints
	setupOrganizationRoutes(protectedRouter, orgHandler, rbacMiddleware)

	// Team management endpoints
	setupTeamRoutes(protectedRouter, teamHandler, rbacMiddleware)

	// API key management endpoints
	setupAPIKeyRoutes(protectedRouter, authHandler, rbacMiddleware)

	// Audit log endpoints
	setupAuditRoutes(protectedRouter, authHandler, rbacMiddleware)
}

// setupPublicAuthRoutes sets up public authentication routes
func setupPublicAuthRoutes(router *mux.Router, authHandler *handlers.AuthHandler) {
	auth := router.PathPrefix("/auth").Subrouter()

	// Authentication endpoints
	auth.HandleFunc("/login", authHandler.Login).Methods("POST")
	auth.HandleFunc("/register", authHandler.Register).Methods("POST")
	auth.HandleFunc("/refresh", authHandler.RefreshToken).Methods("POST")
	auth.HandleFunc("/forgot-password", authHandler.ForgotPassword).Methods("POST")
	auth.HandleFunc("/reset-password", authHandler.ResetPassword).Methods("POST")
	auth.HandleFunc("/verify-email", authHandler.VerifyEmail).Methods("POST")

	// Health check
	auth.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "service": "auth"}`))
	}).Methods("GET")
}

// setupUserRoutes sets up user management routes
func setupUserRoutes(
	router *mux.Router,
	authHandler *handlers.AuthHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	users := router.PathPrefix("/users").Subrouter()

	// Current user endpoints (self-access)
	users.HandleFunc("/me", authHandler.GetCurrentUser).Methods("GET")
	users.HandleFunc("/me", authHandler.UpdateProfile).Methods("PUT", "PATCH")
	users.HandleFunc("/me/password", authHandler.ChangePassword).Methods("PUT")
	users.HandleFunc("/me/sessions", authHandler.GetUserSessions).Methods("GET")
	users.HandleFunc("/me/sessions/{sessionID}", authHandler.RevokeSession).Methods("DELETE")

	// Email management
	users.HandleFunc("/me/send-verification", authHandler.SendVerificationEmail).Methods("POST")
	users.HandleFunc("/me/change-email", authHandler.ChangeEmail).Methods("PUT")

	// MFA endpoints
	users.HandleFunc("/me/mfa/setup", authHandler.SetupMFA).Methods("POST")
	users.HandleFunc("/me/mfa/verify", authHandler.VerifyMFA).Methods("POST")
	users.HandleFunc("/me/mfa/disable", authHandler.DisableMFA).Methods("DELETE")
	users.HandleFunc("/me/mfa/backup-codes", authHandler.GenerateBackupCodes).Methods("POST")

	// User management endpoints (admin+ only)
	adminUsers := users.PathPrefix("").Subrouter()
	adminUsers.Use(rbacMiddleware.RequirePermission(auth.PermissionUserRead))
	adminUsers.HandleFunc("", authHandler.GetUsers).Methods("GET")
	adminUsers.HandleFunc("/{userID}", authHandler.GetUser).Methods("GET")

	// User modification endpoints (admin+ only)
	modifyUsers := users.PathPrefix("").Subrouter()
	modifyUsers.Use(rbacMiddleware.RequirePermission(auth.PermissionUserWrite))
	modifyUsers.HandleFunc("/{userID}", authHandler.UpdateUser).Methods("PUT", "PATCH")
	modifyUsers.HandleFunc("/{userID}/status", authHandler.UpdateUserStatus).Methods("PUT")
	modifyUsers.HandleFunc("/{userID}/role", authHandler.UpdateUserRole).Methods("PUT")

	// User deletion endpoints (admin+ only)
	deleteUsers := users.PathPrefix("").Subrouter()
	deleteUsers.Use(rbacMiddleware.RequirePermission(auth.PermissionUserDelete))
	deleteUsers.HandleFunc("/{userID}", authHandler.DeleteUser).Methods("DELETE")

	// Auth management
	users.HandleFunc("/logout", authHandler.Logout).Methods("POST")
	users.HandleFunc("/logout-all", authHandler.LogoutAll).Methods("POST")
}

// setupOrganizationRoutes sets up organization management routes
func setupOrganizationRoutes(
	router *mux.Router,
	orgHandler *handlers.OrganizationHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	orgs := router.PathPrefix("/organizations").Subrouter()

	// Current organization endpoints
	orgs.HandleFunc("/current", orgHandler.GetCurrentOrganization).Methods("GET")

	// Organization modification (owner/admin only)
	modifyOrg := orgs.PathPrefix("/current").Subrouter()
	modifyOrg.Use(rbacMiddleware.RequirePermission(auth.PermissionOrgWrite))
	modifyOrg.HandleFunc("", orgHandler.UpdateOrganization).Methods("PUT", "PATCH")

	// Member management endpoints
	memberRoutes := orgs.PathPrefix("/current/members").Subrouter()
	
	// View members (member+ role)
	viewMembers := memberRoutes.PathPrefix("").Subrouter()
	viewMembers.Use(rbacMiddleware.RequirePermission(auth.PermissionOrgRead))
	viewMembers.HandleFunc("", orgHandler.GetOrganizationMembers).Methods("GET")

	// Invite users (admin+ only)
	inviteUsers := memberRoutes.PathPrefix("").Subrouter()
	inviteUsers.Use(rbacMiddleware.RequirePermission(auth.PermissionOrgInviteUsers))
	inviteUsers.HandleFunc("/invite", orgHandler.InviteUser).Methods("POST")

	// Manage members (admin+ only)
	manageMembers := memberRoutes.PathPrefix("").Subrouter()
	manageMembers.Use(rbacMiddleware.RequirePermission(auth.PermissionOrgManageMembers))
	manageMembers.HandleFunc("/{memberID}/role", orgHandler.UpdateMemberRole).Methods("PUT")
	manageMembers.HandleFunc("/{memberID}", orgHandler.RemoveMember).Methods("DELETE")

	// Organization settings (owner/admin only)
	settingsRoutes := orgs.PathPrefix("/current/settings").Subrouter()
	settingsRoutes.Use(rbacMiddleware.RequirePermission(auth.PermissionSettingsWrite))
	settingsRoutes.HandleFunc("", orgHandler.GetOrganizationSettings).Methods("GET")
	settingsRoutes.HandleFunc("", orgHandler.UpdateOrganizationSettings).Methods("PUT", "PATCH")
}

// setupTeamRoutes sets up team management routes
func setupTeamRoutes(
	router *mux.Router,
	teamHandler *handlers.TeamHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	teams := router.PathPrefix("/teams").Subrouter()

	// User's teams (authenticated user)
	teams.HandleFunc("/my", teamHandler.GetUserTeams).Methods("GET")

	// All organization teams (admin+ only)
	allTeams := teams.PathPrefix("").Subrouter()
	allTeams.Use(rbacMiddleware.RequirePermission(auth.PermissionTeamRead))
	allTeams.HandleFunc("", teamHandler.GetOrganizationTeams).Methods("GET")

	// Create team (admin+ only)
	createTeam := teams.PathPrefix("").Subrouter()
	createTeam.Use(rbacMiddleware.RequirePermission(auth.PermissionTeamWrite))
	createTeam.HandleFunc("", teamHandler.CreateTeam).Methods("POST")

	// Team-specific routes
	teamRoutes := teams.PathPrefix("/{teamID}").Subrouter()

	// View team (team member+ or admin+)
	viewTeam := teamRoutes.PathPrefix("").Subrouter()
	viewTeam.Use(rbacMiddleware.RequireTeamPermission(auth.PermissionTeamRead))
	viewTeam.HandleFunc("", teamHandler.GetTeam).Methods("GET")
	viewTeam.HandleFunc("/members", teamHandler.GetTeamMembers).Methods("GET")

	// Modify team (team admin+ only)
	modifyTeam := teamRoutes.PathPrefix("").Subrouter()
	modifyTeam.Use(rbacMiddleware.RequireTeamPermission(auth.PermissionTeamWrite))
	modifyTeam.HandleFunc("", teamHandler.UpdateTeam).Methods("PUT", "PATCH")

	// Manage team members (team admin+ only)
	manageTeamMembers := teamRoutes.PathPrefix("/members").Subrouter()
	manageTeamMembers.Use(rbacMiddleware.RequireTeamPermission(auth.PermissionTeamManageMembers))
	manageTeamMembers.HandleFunc("", teamHandler.AddTeamMember).Methods("POST")
	manageTeamMembers.HandleFunc("/{memberID}/role", teamHandler.UpdateTeamMemberRole).Methods("PUT")
	manageTeamMembers.HandleFunc("/{memberID}", teamHandler.RemoveTeamMember).Methods("DELETE")

	// Delete team (team owner only)
	deleteTeam := teamRoutes.PathPrefix("").Subrouter()
	deleteTeam.Use(rbacMiddleware.RequireTeamPermission(auth.PermissionTeamDelete))
	deleteTeam.HandleFunc("", teamHandler.DeleteTeam).Methods("DELETE")
}

// setupAPIKeyRoutes sets up API key management routes
func setupAPIKeyRoutes(
	router *mux.Router,
	authHandler *handlers.AuthHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	apiKeys := router.PathPrefix("/api-keys").Subrouter()

	// User's own API keys
	userKeys := apiKeys.PathPrefix("").Subrouter()
	userKeys.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyRead))
	userKeys.HandleFunc("", authHandler.GetUserAPIKeys).Methods("GET")

	// Create API key
	createKeys := apiKeys.PathPrefix("").Subrouter()
	createKeys.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyWrite))
	createKeys.HandleFunc("", authHandler.CreateAPIKey).Methods("POST")

	// Manage specific API key
	keyRoutes := apiKeys.PathPrefix("/{keyID}").Subrouter()
	keyRoutes.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyRead))
	keyRoutes.HandleFunc("", authHandler.GetAPIKey).Methods("GET")

	// Update API key
	updateKeys := keyRoutes.PathPrefix("").Subrouter()
	updateKeys.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyWrite))
	updateKeys.HandleFunc("", authHandler.UpdateAPIKey).Methods("PUT", "PATCH")

	// Delete API key
	deleteKeys := keyRoutes.PathPrefix("").Subrouter()
	deleteKeys.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyDelete))
	deleteKeys.HandleFunc("", authHandler.RevokeAPIKey).Methods("DELETE")

	// Organization API keys (admin+ only)
	orgKeys := apiKeys.PathPrefix("/organization").Subrouter()
	orgKeys.Use(rbacMiddleware.RequirePermission(auth.PermissionAPIKeyRead))
	orgKeys.HandleFunc("", authHandler.GetOrganizationAPIKeys).Methods("GET")
}

// setupAuditRoutes sets up audit log routes
func setupAuditRoutes(
	router *mux.Router,
	authHandler *handlers.AuthHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	audit := router.PathPrefix("/audit").Subrouter()
	audit.Use(rbacMiddleware.RequirePermission(auth.PermissionAuditRead))

	// Audit logs
	audit.HandleFunc("/logs", authHandler.GetAuditLogs).Methods("GET")
	audit.HandleFunc("/logs/export", authHandler.ExportAuditLogs).Methods("GET")

	// User-specific audit logs
	audit.HandleFunc("/users/{userID}/logs", authHandler.GetUserAuditLogs).Methods("GET")

	// Resource-specific audit logs
	audit.HandleFunc("/resources/{resourceType}/{resourceID}/logs", authHandler.GetResourceAuditLogs).Methods("GET")
}

// SetupInvitationRoutes sets up invitation-specific routes (public access)
func SetupInvitationRoutes(router *mux.Router, authHandler *handlers.AuthHandler) {
	invites := router.PathPrefix("/api/v1/invitations").Subrouter()

	// Public invitation endpoints
	invites.HandleFunc("/{token}", authHandler.GetInvitation).Methods("GET")
	invites.HandleFunc("/{token}/accept", authHandler.AcceptInvitation).Methods("POST")
	invites.HandleFunc("/{token}/decline", authHandler.DeclineInvitation).Methods("POST")
}

// SetupWebhookRoutes sets up webhook authentication routes
func SetupWebhookRoutes(router *mux.Router, authHandler *handlers.AuthHandler) {
	webhooks := router.PathPrefix("/webhooks/auth").Subrouter()

	// OAuth callbacks
	webhooks.HandleFunc("/oauth/{provider}/callback", authHandler.OAuthCallback).Methods("GET")

	// SAML endpoints
	webhooks.HandleFunc("/saml/acs", authHandler.SAMLAssertionConsumerService).Methods("POST")
	webhooks.HandleFunc("/saml/metadata", authHandler.SAMLMetadata).Methods("GET")

	// LDAP test endpoint
	webhooks.HandleFunc("/ldap/test", authHandler.TestLDAPConnection).Methods("POST")
}

// SetupAdminRoutes sets up admin-only routes
func SetupAdminRoutes(
	router *mux.Router,
	authHandler *handlers.AuthHandler,
	orgHandler *handlers.OrganizationHandler,
	rbacMiddleware *middleware.RBACMiddleware,
) {
	admin := router.PathPrefix("/api/v1/admin").Subrouter()
	admin.Use(rbacMiddleware.RequirePermission(auth.PermissionAdminAll))

	// System statistics
	admin.HandleFunc("/stats", authHandler.GetSystemStats).Methods("GET")

	// Organization management
	admin.HandleFunc("/organizations", orgHandler.GetAllOrganizations).Methods("GET")
	admin.HandleFunc("/organizations/{orgID}", orgHandler.GetOrganization).Methods("GET")
	admin.HandleFunc("/organizations/{orgID}", orgHandler.AdminUpdateOrganization).Methods("PUT", "PATCH")
	admin.HandleFunc("/organizations/{orgID}/suspend", orgHandler.SuspendOrganization).Methods("POST")
	admin.HandleFunc("/organizations/{orgID}/activate", orgHandler.ActivateOrganization).Methods("POST")

	// User management
	admin.HandleFunc("/users", authHandler.GetAllUsers).Methods("GET")
	admin.HandleFunc("/users/{userID}/impersonate", authHandler.ImpersonateUser).Methods("POST")

	// System settings
	admin.HandleFunc("/settings", authHandler.GetSystemSettings).Methods("GET")
	admin.HandleFunc("/settings", authHandler.UpdateSystemSettings).Methods("PUT", "PATCH")

	// Security
	admin.HandleFunc("/security/sessions", authHandler.GetAllActiveSessions).Methods("GET")
	admin.HandleFunc("/security/sessions/{sessionID}/revoke", authHandler.AdminRevokeSession).Methods("DELETE")
}