package auth

import (
	"context"
	"fmt"

	"n8n-pro/pkg/errors"
)

// Permission types and PermissionSet are defined in models.go

// RBAC service for checking permissions
type RBACService struct {
	authService *EnhancedAuthService
}

// NewRBACService creates a new RBAC service
func NewRBACService(authService *EnhancedAuthService) *RBACService {
	return &RBACService{
		authService: authService,
	}
}

// CheckPermission checks if a user has a specific permission
func (r *RBACService) CheckPermission(ctx context.Context, userID string, permission Permission) error {
	user, err := r.authService.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.NewUnauthorizedError("User not found")
	}

	if user.Status != UserStatusActive {
		return errors.NewUnauthorizedError("User account is not active")
	}

	userPermissions := GetRolePermissions(user.Role)
	if !userPermissions.Has(permission) {
		return errors.NewForbiddenError(fmt.Sprintf("Insufficient permissions: %s required", permission))
	}

	return nil
}

// CheckPermissions checks if a user has all of the specified permissions
func (r *RBACService) CheckPermissions(ctx context.Context, userID string, permissions ...Permission) error {
	user, err := r.authService.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.NewUnauthorizedError("User not found")
	}

	if user.Status != UserStatusActive {
		return errors.NewUnauthorizedError("User account is not active")
	}

	userPermissions := GetRolePermissions(user.Role)
	if !userPermissions.HasAll(permissions...) {
		return errors.NewForbiddenError("Insufficient permissions")
	}

	return nil
}

// CheckAnyPermission checks if a user has any of the specified permissions
func (r *RBACService) CheckAnyPermission(ctx context.Context, userID string, permissions ...Permission) error {
	user, err := r.authService.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.NewUnauthorizedError("User not found")
	}

	if user.Status != UserStatusActive {
		return errors.NewUnauthorizedError("User account is not active")
	}

	userPermissions := GetRolePermissions(user.Role)
	if !userPermissions.HasAny(permissions...) {
		return errors.NewForbiddenError("Insufficient permissions")
	}

	return nil
}

// CheckTeamPermission checks if a user has a specific permission within a team context
func (r *RBACService) CheckTeamPermission(ctx context.Context, userID, teamID string, permission Permission) error {
	// First check organization-level permission
	if err := r.CheckPermission(ctx, userID, permission); err == nil {
		return nil // User has organization-level permission
	}

	// Check team-level permission
	membership, err := r.authService.teamRepo.GetTeamMembership(ctx, teamID, userID)
	if err != nil {
		return errors.NewForbiddenError("Access denied to team")
	}

	teamPermissions := GetRolePermissions(membership.Role)
	if !teamPermissions.Has(permission) {
		return errors.NewForbiddenError(fmt.Sprintf("Insufficient team permissions: %s required", permission))
	}

	return nil
}

// GetUserPermissions returns all permissions for a user
func (r *RBACService) GetUserPermissions(ctx context.Context, userID string) (PermissionSet, error) {
	user, err := r.authService.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return GetRolePermissions(user.Role), nil
}

// GetTeamUserPermissions returns permissions for a user within a specific team
func (r *RBACService) GetTeamUserPermissions(ctx context.Context, userID, teamID string) (PermissionSet, error) {
	// Get organization-level permissions
	orgPermissions, err := r.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	// If user has admin permissions, return those
	if orgPermissions.Has(PermissionAdminAll) {
		return orgPermissions, nil
	}

	// Get team-specific permissions
	membership, err := r.authService.teamRepo.GetTeamMembership(ctx, teamID, userID)
	if err != nil {
		// User not in team, return organization permissions only
		return orgPermissions, nil
	}

	teamPermissions := GetRolePermissions(membership.Role)

	// Merge permissions (take the more permissive one)
	mergedPermissions := make(PermissionSet)
	for perm := range orgPermissions {
		mergedPermissions[perm] = true
	}
	for perm := range teamPermissions {
		mergedPermissions[perm] = true
	}

	return mergedPermissions, nil
}

// CanAccessResource checks if a user can access a resource based on ownership and permissions
func (r *RBACService) CanAccessResource(ctx context.Context, userID, resourceOwnerID string, permission Permission) error {
	// If user owns the resource, they can access it (with basic read permission)
	if userID == resourceOwnerID && (permission == PermissionWorkflowsRead || 
		permission == PermissionExecutionsRead || permission == PermissionCredentialsRead) {
		return nil
	}

	// Otherwise, check standard permissions
	return r.CheckPermission(ctx, userID, permission)
}

// FilterResourcesByPermission filters a list of resources based on user permissions
func (r *RBACService) FilterResourcesByPermission(ctx context.Context, userID string, resources []ResourceInfo, permission Permission) ([]ResourceInfo, error) {
	user, err := r.authService.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	userPermissions := GetRolePermissions(user.Role)
	
	// If user has admin or the specific permission, return all resources
	if userPermissions.Has(permission) {
		return resources, nil
	}

	// Filter resources based on ownership or team access
	var filtered []ResourceInfo
	for _, resource := range resources {
		// Check if user owns the resource
		if resource.OwnerID == userID {
			filtered = append(filtered, resource)
			continue
		}

		// Check if user has team-level access to the resource
		if resource.TeamID != nil {
			if err := r.CheckTeamPermission(ctx, userID, *resource.TeamID, permission); err == nil {
				filtered = append(filtered, resource)
				continue
			}
		}
	}

	return filtered, nil
}

// ResourceInfo represents basic resource information for access control
type ResourceInfo struct {
	ID      string  `json:"id"`
	OwnerID string  `json:"owner_id"`
	TeamID  *string `json:"team_id,omitempty"`
	Type    string  `json:"type"`
}

// Permission validation helper functions

// ValidateRoleHierarchy validates that a user can assign/modify roles based on hierarchy
func ValidateRoleHierarchy(userRole, targetRole RoleType) error {
	roleLevel := map[RoleType]int{
		RoleViewer: 1,
		RoleMember: 2,
		RoleAdmin:  3,
		RoleOwner:  4,
	}

	userLevel := roleLevel[userRole]
	targetLevel := roleLevel[targetRole]

	if userLevel <= targetLevel {
		return errors.NewForbiddenError("Cannot assign role with equal or higher privileges")
	}

	return nil
}

// IsHigherRole checks if role1 is higher than role2 in hierarchy
func IsHigherRole(role1, role2 RoleType) bool {
	roleLevel := map[RoleType]int{
		RoleViewer: 1,
		RoleMember: 2,
		RoleAdmin:  3,
		RoleOwner:  4,
	}

	return roleLevel[role1] > roleLevel[role2]
}

// GetMinimumRoleForPermission returns the minimum role required for a permission
func GetMinimumRoleForPermission(permission Permission) RoleType {
	// Check each role from lowest to highest
	roles := []RoleType{RoleViewer, RoleMember, RoleAdmin, RoleOwner}
	
	for _, role := range roles {
		permissions := GetRolePermissions(role)
		if permissions.Has(permission) {
			return role
		}
	}

	// If no role has the permission, require Owner
	return RoleOwner
}

// convertPermissionsToScopes is defined in enhanced_service.go

// Helper function to check if a permission string is valid
func IsValidPermission(permissionStr string) bool {
	validPermissions := []Permission{
		PermissionUsersRead, PermissionUsersWrite, PermissionUsersDelete,
		PermissionWorkflowsRead, PermissionWorkflowsWrite, PermissionWorkflowsDelete, PermissionWorkflowsShare,
		PermissionExecutionsRead, PermissionExecutionsWrite, PermissionExecutionsDelete,
		PermissionCredentialsRead, PermissionCredentialsWrite, PermissionCredentialsDelete, PermissionCredentialsShare,
		PermissionOrganizationRead, PermissionOrganizationWrite, PermissionOrganizationSettings, PermissionOrganizationBilling,
		PermissionTeamsRead, PermissionTeamsWrite, PermissionTeamsDelete,
		PermissionAuditLogs, PermissionSystemConfig, PermissionAPIKeys,
		PermissionAdminAll,
	}

	for _, perm := range validPermissions {
		if string(perm) == permissionStr {
			return true
		}
	}
	return false
}

// ParsePermissions converts a slice of permission strings to a PermissionSet
func ParsePermissions(permissionStrings []string) PermissionSet {
	permissions := make(PermissionSet)
	for _, permStr := range permissionStrings {
		if IsValidPermission(permStr) {
			permissions[Permission(permStr)] = true
		}
	}
	return permissions
}