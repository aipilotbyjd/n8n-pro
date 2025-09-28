package ldap

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig contains LDAP configuration settings
type LDAPConfig struct {
	Host                string `json:"host"`
	Port                int    `json:"port"`
	UseSSL              bool   `json:"use_ssl"`
	UseStartTLS         bool   `json:"use_start_tls"`
	SkipVerify          bool   `json:"skip_verify"`
	BindDN              string `json:"bind_dn"`
	BindPassword        string `json:"bind_password"`
	BaseDN              string `json:"base_dn"`
	UserFilter          string `json:"user_filter"`          // e.g., "(uid=%s)" or "(sAMAccountName=%s)"
	GroupBaseDN         string `json:"group_base_dn"`
	GroupFilter         string `json:"group_filter"`         // e.g., "(member=%s)" or "(memberOf=%s)"
	AttributeMappings   LDAPAttributeMappings `json:"attribute_mappings"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	ReadTimeout         time.Duration `json:"read_timeout"`
	DefaultOrganizationID string `json:"default_organization_id,omitempty"`
	AutoCreateUsers     bool   `json:"auto_create_users"`
	SyncGroups          bool   `json:"sync_groups"`
}

// LDAPAttributeMappings defines how LDAP attributes map to user fields
type LDAPAttributeMappings struct {
	Email     string `json:"email"`     // e.g., "mail", "userPrincipalName"
	FirstName string `json:"first_name"` // e.g., "givenName"
	LastName  string `json:"last_name"`  // e.g., "sn"
	FullName  string `json:"full_name"`  // e.g., "cn", "displayName"
	UserID    string `json:"user_id"`    // e.g., "uid", "sAMAccountName"
	Groups    string `json:"groups"`     // e.g., "memberOf"
}

// LDAPUserInfo represents user information retrieved from LDAP
type LDAPUserInfo struct {
	DN        string   `json:"dn"`
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	FullName  string   `json:"full_name"`
	Groups    []string `json:"groups"`
	Attributes map[string][]string `json:"attributes"`
}

// UserService interface for user operations to break circular dependency
type UserService interface {
	GetUserByEmail(ctx context.Context, email string) (interface{}, error)
	CreateUser(ctx context.Context, userRequest interface{}) (interface{}, error)
	Authenticate(ctx context.Context, email, password, ipAddress string) (interface{}, error)
}

// LoginResponse represents the response from authentication
type LoginResponse struct {
	Token        string                 `json:"token"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	User         interface{}            `json:"user"`
	ExpiresAt    int64                  `json:"expires_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// LDAPService manages LDAP authentication
type LDAPService struct {
	config      *LDAPConfig
	logger      logger.Logger
	userService UserService
}

// NewLDAPService creates a new LDAP service
func NewLDAPService(config *LDAPConfig, userService UserService, logger logger.Logger) *LDAPService {
	// Set default timeouts if not specified
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 10 * time.Second
	}

	// Set default port if not specified
	if config.Port == 0 {
		if config.UseSSL {
			config.Port = 636
		} else {
			config.Port = 389
		}
	}

	return &LDAPService{
		config:      config,
		logger:      logger,
		userService: userService,
	}
}

// Authenticate authenticates a user against LDAP and returns login response
func (l *LDAPService) Authenticate(ctx context.Context, username, password, ipAddress string) (*LoginResponse, error) {
	// Connect to LDAP server
	conn, err := l.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Search for user
	userInfo, err := l.searchUser(conn, username)
	if err != nil {
		l.logger.Warn("LDAP user not found", "username", username, "error", err)
		return nil, errors.NewValidationError("Invalid credentials")
	}

	// Authenticate user by binding with their credentials
	if err := l.authenticateUser(conn, userInfo.DN, password); err != nil {
		l.logger.Warn("LDAP authentication failed", "username", username, "dn", userInfo.DN, "error", err)
		return nil, errors.NewValidationError("Invalid credentials")
	}

	// Get user groups if group synchronization is enabled
	if l.config.SyncGroups {
		groups, err := l.getUserGroups(conn, userInfo)
		if err != nil {
			l.logger.Warn("Failed to get user groups from LDAP", "username", username, "error", err)
		} else {
			userInfo.Groups = groups
		}
	}

	l.logger.Info("LDAP authentication successful", "username", username, "email", userInfo.Email)

	// Check if user exists in our system
	existingUser, err := l.userService.GetUserByEmail(ctx, userInfo.Email)
	if err == nil {
		// User exists, authenticate them
		return l.authenticateExistingUser(ctx, existingUser, userInfo, ipAddress)
	}

	// User doesn't exist
	if l.config.AutoCreateUsers {
		return l.createUserFromLDAP(ctx, userInfo, ipAddress)
	}

	return nil, errors.NewValidationError("User not found and auto-creation is disabled")
}

// connect establishes a connection to the LDAP server
func (l *LDAPService) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", l.config.Host, l.config.Port)

	var conn *ldap.Conn
	var err error

	if l.config.UseSSL {
		// SSL/LDAPS connection
		tlsConfig := &tls.Config{
			ServerName:         l.config.Host,
			InsecureSkipVerify: l.config.SkipVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Plain connection
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		// Start TLS if configured
		if l.config.UseStartTLS {
			tlsConfig := &tls.Config{
				ServerName:         l.config.Host,
				InsecureSkipVerify: l.config.SkipVerify,
			}
			if err := conn.StartTLS(tlsConfig); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	// Set timeouts
	conn.SetTimeout(l.config.ConnectionTimeout)

	// Bind with service account if configured
	if l.config.BindDN != "" {
		if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	return conn, nil
}

// searchUser searches for a user in LDAP directory
func (l *LDAPService) searchUser(conn *ldap.Conn, username string) (*LDAPUserInfo, error) {
	// Build search filter
	searchFilter := fmt.Sprintf(l.config.UserFilter, username)

	// Define attributes to retrieve
	attributes := []string{
		l.config.AttributeMappings.Email,
		l.config.AttributeMappings.FirstName,
		l.config.AttributeMappings.LastName,
		l.config.AttributeMappings.FullName,
		l.config.AttributeMappings.UserID,
	}

	// Add groups attribute if configured
	if l.config.AttributeMappings.Groups != "" {
		attributes = append(attributes, l.config.AttributeMappings.Groups)
	}

	// Remove empty attributes
	var validAttributes []string
	for _, attr := range attributes {
		if attr != "" {
			validAttributes = append(validAttributes, attr)
		}
	}

	// Perform search
	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit
		int(l.config.ReadTimeout.Seconds()),
		false,
		searchFilter,
		validAttributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	entry := result.Entries[0]
	userInfo := &LDAPUserInfo{
		DN:         entry.DN,
		Attributes: make(map[string][]string),
	}

	// Extract user attributes
	for _, attr := range entry.Attributes {
		userInfo.Attributes[attr.Name] = attr.Values

		// Map specific attributes
		switch attr.Name {
		case l.config.AttributeMappings.Email:
			if len(attr.Values) > 0 {
				userInfo.Email = attr.Values[0]
			}
		case l.config.AttributeMappings.FirstName:
			if len(attr.Values) > 0 {
				userInfo.FirstName = attr.Values[0]
			}
		case l.config.AttributeMappings.LastName:
			if len(attr.Values) > 0 {
				userInfo.LastName = attr.Values[0]
			}
		case l.config.AttributeMappings.FullName:
			if len(attr.Values) > 0 {
				userInfo.FullName = attr.Values[0]
			}
		case l.config.AttributeMappings.UserID:
			if len(attr.Values) > 0 {
				userInfo.UserID = attr.Values[0]
			}
		case l.config.AttributeMappings.Groups:
			userInfo.Groups = attr.Values
		}
	}

	// Use UserID as fallback for email if email is not set
	if userInfo.Email == "" && userInfo.UserID != "" {
		userInfo.Email = userInfo.UserID
	}

	// Split full name if first/last name are not available
	if userInfo.FirstName == "" || userInfo.LastName == "" {
		if userInfo.FullName != "" {
			parts := strings.Fields(userInfo.FullName)
			if len(parts) >= 2 {
				if userInfo.FirstName == "" {
					userInfo.FirstName = parts[0]
				}
				if userInfo.LastName == "" {
					userInfo.LastName = parts[len(parts)-1]
				}
			}
		}
	}

	if userInfo.Email == "" {
		return nil, fmt.Errorf("email not found for user")
	}

	return userInfo, nil
}

// authenticateUser authenticates a user by binding with their credentials
func (l *LDAPService) authenticateUser(conn *ldap.Conn, userDN, password string) error {
	// Try to bind with user credentials
	if err := conn.Bind(userDN, password); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Rebind with service account for subsequent operations
	if l.config.BindDN != "" {
		if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
			return fmt.Errorf("failed to rebind with service account: %w", err)
		}
	}

	return nil
}

// getUserGroups retrieves user group memberships from LDAP
func (l *LDAPService) getUserGroups(conn *ldap.Conn, userInfo *LDAPUserInfo) ([]string, error) {
	// If groups are already in user attributes, return them
	if len(userInfo.Groups) > 0 {
		return userInfo.Groups, nil
	}

	// If no group filter configured, return empty
	if l.config.GroupFilter == "" || l.config.GroupBaseDN == "" {
		return nil, nil
	}

	// Search for groups
	groupFilter := fmt.Sprintf(l.config.GroupFilter, userInfo.DN)
	
	searchRequest := ldap.NewSearchRequest(
		l.config.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		int(l.config.ReadTimeout.Seconds()),
		false,
		groupFilter,
		[]string{"cn", "dn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group search failed: %w", err)
	}

	var groups []string
	for _, entry := range result.Entries {
		// Use CN (common name) if available, otherwise use DN
		if cn := entry.GetAttributeValue("cn"); cn != "" {
			groups = append(groups, cn)
		} else {
			groups = append(groups, entry.DN)
		}
	}

	return groups, nil
}

// authenticateExistingUser authenticates an existing user via LDAP
func (l *LDAPService) authenticateExistingUser(ctx context.Context, user interface{}, userInfo *LDAPUserInfo, ipAddress string) (*LoginResponse, error) {
	// Use the user service to authenticate the existing user
	result, err := l.userService.Authenticate(ctx, userInfo.Email, "", ipAddress)
	if err != nil {
		return nil, err
	}

	// Create a proper response
	if loginResp, ok := result.(*LoginResponse); ok {
		return loginResp, nil
	}

	// Fallback response creation
	return &LoginResponse{
		User:      result,
		Metadata: map[string]interface{}{
			"ldap_dn":    userInfo.DN,
			"ldap_uid":   userInfo.UserID,
			"email":      userInfo.Email,
			"groups":     userInfo.Groups,
			"auth_type":  "ldap",
		},
	}, nil
}

// createUserFromLDAP creates a new user from LDAP information
func (l *LDAPService) createUserFromLDAP(ctx context.Context, userInfo *LDAPUserInfo, ipAddress string) (*LoginResponse, error) {
	if !l.config.AutoCreateUsers {
		return nil, errors.NewForbiddenError("User auto-creation is disabled")
	}

	// Create user request from LDAP info
	userRequest := map[string]interface{}{
		"first_name": userInfo.FirstName,
		"last_name":  userInfo.LastName,
		"email":      userInfo.Email,
		"password":   generateRandomPassword(), // Random password for LDAP users
		"verified":   true,                     // LDAP users are pre-verified
		"ldap_dn":    userInfo.DN,
		"ldap_uid":   userInfo.UserID,
	}

	// Create the user
	result, err := l.userService.CreateUser(ctx, userRequest)
	if err != nil {
		l.logger.Error("Failed to create LDAP user", "email", userInfo.Email, "error", err)
		return nil, err
	}

	l.logger.Info("LDAP user created successfully", "email", userInfo.Email)

	// Return login response
	return &LoginResponse{
		User: result,
		Metadata: map[string]interface{}{
			"ldap_dn":    userInfo.DN,
			"ldap_uid":   userInfo.UserID,
			"email":      userInfo.Email,
			"groups":     userInfo.Groups,
			"auth_type":  "ldap",
			"created":    true,
		},
	}, nil
}

// TestConnection tests the LDAP connection and configuration
func (l *LDAPService) TestConnection() error {
	conn, err := l.connect()
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Try a simple search to test the configuration
	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		int(l.config.ReadTimeout.Seconds()),
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("search test failed: %w", err)
	}

	return nil
}

// SearchUsers searches for users in LDAP directory (for admin purposes)
func (l *LDAPService) SearchUsers(searchQuery string, limit int) ([]*LDAPUserInfo, error) {
	conn, err := l.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Build search filter for multiple attributes
	var searchFilters []string
	if l.config.AttributeMappings.Email != "" {
		searchFilters = append(searchFilters, fmt.Sprintf("(%s=*%s*)", l.config.AttributeMappings.Email, searchQuery))
	}
	if l.config.AttributeMappings.FirstName != "" {
		searchFilters = append(searchFilters, fmt.Sprintf("(%s=*%s*)", l.config.AttributeMappings.FirstName, searchQuery))
	}
	if l.config.AttributeMappings.LastName != "" {
		searchFilters = append(searchFilters, fmt.Sprintf("(%s=*%s*)", l.config.AttributeMappings.LastName, searchQuery))
	}
	if l.config.AttributeMappings.UserID != "" {
		searchFilters = append(searchFilters, fmt.Sprintf("(%s=*%s*)", l.config.AttributeMappings.UserID, searchQuery))
	}

	var searchFilter string
	if len(searchFilters) > 1 {
		searchFilter = fmt.Sprintf("(|%s)", strings.Join(searchFilters, ""))
	} else if len(searchFilters) == 1 {
		searchFilter = searchFilters[0]
	} else {
		return nil, fmt.Errorf("no searchable attributes configured")
	}

	// Define attributes to retrieve
	attributes := []string{
		l.config.AttributeMappings.Email,
		l.config.AttributeMappings.FirstName,
		l.config.AttributeMappings.LastName,
		l.config.AttributeMappings.FullName,
		l.config.AttributeMappings.UserID,
	}

	// Remove empty attributes
	var validAttributes []string
	for _, attr := range attributes {
		if attr != "" {
			validAttributes = append(validAttributes, attr)
		}
	}

	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		limit,
		int(l.config.ReadTimeout.Seconds()),
		false,
		searchFilter,
		validAttributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var users []*LDAPUserInfo
	for _, entry := range result.Entries {
		userInfo := &LDAPUserInfo{
			DN:         entry.DN,
			Attributes: make(map[string][]string),
		}

		// Extract user attributes
		for _, attr := range entry.Attributes {
			userInfo.Attributes[attr.Name] = attr.Values

			// Map specific attributes
			switch attr.Name {
			case l.config.AttributeMappings.Email:
				if len(attr.Values) > 0 {
					userInfo.Email = attr.Values[0]
				}
			case l.config.AttributeMappings.FirstName:
				if len(attr.Values) > 0 {
					userInfo.FirstName = attr.Values[0]
				}
			case l.config.AttributeMappings.LastName:
				if len(attr.Values) > 0 {
					userInfo.LastName = attr.Values[0]
				}
			case l.config.AttributeMappings.FullName:
				if len(attr.Values) > 0 {
					userInfo.FullName = attr.Values[0]
				}
			case l.config.AttributeMappings.UserID:
				if len(attr.Values) > 0 {
					userInfo.UserID = attr.Values[0]
				}
			}
		}

		users = append(users, userInfo)
	}

	return users, nil
}

// Utility functions

func generateRandomPassword() string {
	// Same implementation as in SAML
	bytes := make([]byte, 32)
	// Using crypto/rand for secure random generation
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based seed if crypto/rand fails
		return fmt.Sprintf("ldap-user-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("ldap-%d", time.Now().UnixNano())
}

// Default LDAP configurations for common providers

// GetActiveDirectoryConfig returns a default configuration for Active Directory
func GetActiveDirectoryConfig(host string, baseDN string) *LDAPConfig {
	return &LDAPConfig{
		Host:              host,
		Port:              389,
		UseSSL:            false,
		UseStartTLS:       true,
		SkipVerify:        false,
		BaseDN:            baseDN,
		UserFilter:        "(sAMAccountName=%s)",
		GroupBaseDN:       baseDN,
		GroupFilter:       "(member=%s)",
		AttributeMappings: LDAPAttributeMappings{
			Email:     "userPrincipalName",
			FirstName: "givenName",
			LastName:  "sn",
			FullName:  "displayName",
			UserID:    "sAMAccountName",
			Groups:    "memberOf",
		},
		ConnectionTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		AutoCreateUsers:   false,
		SyncGroups:        true,
	}
}

// GetOpenLDAPConfig returns a default configuration for OpenLDAP
func GetOpenLDAPConfig(host string, baseDN string) *LDAPConfig {
	return &LDAPConfig{
		Host:              host,
		Port:              389,
		UseSSL:            false,
		UseStartTLS:       true,
		SkipVerify:        false,
		BaseDN:            baseDN,
		UserFilter:        "(uid=%s)",
		GroupBaseDN:       baseDN,
		GroupFilter:       "(memberUid=%s)",
		AttributeMappings: LDAPAttributeMappings{
			Email:     "mail",
			FirstName: "givenName",
			LastName:  "sn",
			FullName:  "cn",
			UserID:    "uid",
			Groups:    "",
		},
		ConnectionTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		AutoCreateUsers:   false,
		SyncGroups:        true,
	}
}

// GetApacheDSConfig returns a default configuration for Apache Directory Server
func GetApacheDSConfig(host string, baseDN string) *LDAPConfig {
	return &LDAPConfig{
		Host:              host,
		Port:              10389,
		UseSSL:            false,
		UseStartTLS:       false,
		SkipVerify:        true,
		BaseDN:            baseDN,
		UserFilter:        "(uid=%s)",
		GroupBaseDN:       baseDN,
		GroupFilter:       "(uniqueMember=%s)",
		AttributeMappings: LDAPAttributeMappings{
			Email:     "mail",
			FirstName: "givenName",
			LastName:  "sn",
			FullName:  "cn",
			UserID:    "uid",
			Groups:    "",
		},
		ConnectionTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		AutoCreateUsers:   false,
		SyncGroups:        true,
	}
}