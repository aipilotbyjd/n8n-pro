package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// SAMLProvider represents a SAML identity provider configuration
type SAMLProvider struct {
	EntityID                string `json:"entity_id"`
	SSOURL                  string `json:"sso_url"`
	SLOUrl                  string `json:"slo_url,omitempty"`
	Certificate             string `json:"certificate"`
	SignAuthnRequests       bool   `json:"sign_authn_requests"`
	RequireSignedAssertions bool   `json:"require_signed_assertions"`
	AttributeMappings       AttributeMappings `json:"attribute_mappings"`
}

// AttributeMappings defines how SAML attributes map to user fields
type AttributeMappings struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Groups    string `json:"groups,omitempty"`
}

// SAMLService manages SAML authentication
type SAMLService struct {
	serviceProvider *samlsp.Middleware
	config          *SAMLConfig
	logger          logger.Logger
	authService     *auth.EnhancedAuthService
}

// SAMLConfig contains SAML service configuration
type SAMLConfig struct {
	EntityID                string `json:"entity_id"`
	BaseURL                 string `json:"base_url"`
	Certificate             string `json:"certificate"`
	PrivateKey              string `json:"private_key"`
	SignRequests            bool   `json:"sign_requests"`
	EncryptAssertions       bool   `json:"encrypt_assertions"`
	AttributeMappings       AttributeMappings `json:"attribute_mappings"`
	DefaultOrganizationID   string `json:"default_organization_id,omitempty"`
	AutoCreateUsers         bool   `json:"auto_create_users"`
	RequireEncryptedAssertions bool `json:"require_encrypted_assertions"`
}

// UserInfo represents extracted user information from SAML assertion
type UserInfo struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Groups    []string `json:"groups,omitempty"`
	Provider  string   `json:"provider"`
}

// NewSAMLService creates a new SAML service
func NewSAMLService(config *SAMLConfig, authService *auth.EnhancedAuthService, logger logger.Logger) (*SAMLService, error) {
	// Parse certificate and private key
	keyPair, err := parseCertificateAndKey(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate and key: %w", err)
	}

	// Parse base URL
	rootURL, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Create SAML service provider options
	samlOptions := samlsp.Options{
		EntityID: config.EntityID,
		URL:      *rootURL,
		Key:      keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		SignRequest: config.SignRequests,
		ForceAuthn:  false, // Allow SSO
		IDPMetadata: nil,   // Will be set when configuring IdP
	}

	// Create service provider middleware
	serviceProvider, err := samlsp.New(samlOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML service provider: %w", err)
	}

	return &SAMLService{
		serviceProvider: serviceProvider,
		config:          config,
		logger:          logger,
		authService:     authService,
	}, nil
}

// ConfigureIdentityProvider configures a SAML identity provider
func (s *SAMLService) ConfigureIdentityProvider(provider *SAMLProvider) error {
	// Parse IdP certificate
	idpCert, err := parseCertificate(provider.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse IdP certificate: %w", err)
	}

	// Create IdP metadata
	idpMetadata := &saml.EntityDescriptor{
		EntityID: provider.EntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									Certificate: base64.StdEncoding.EncodeToString(idpCert.Raw),
								},
							},
						},
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: provider.SSOURL,
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: provider.SSOURL,
					},
				},
			},
		},
	}

	// Add SLO service if configured
	if provider.SLOUrl != "" {
		idpMetadata.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{
			{
				Binding:  saml.HTTPRedirectBinding,
				Location: provider.SLOUrl,
			},
			{
				Binding:  saml.HTTPPostBinding,
				Location: provider.SLOUrl,
			},
		}
	}

	s.serviceProvider.ServiceProvider.IDPMetadata = idpMetadata

	s.logger.Info("SAML IdP configured", "entity_id", provider.EntityID)
	return nil
}

// GetMetadata returns the service provider metadata XML
func (s *SAMLService) GetMetadata() ([]byte, error) {
	metadata := s.serviceProvider.ServiceProvider.Metadata()
	return metadata.MarshalIndent("", "  ")
}

// GetAuthURL generates a SAML authentication URL
func (s *SAMLService) GetAuthURL(relayState string) (string, error) {
	if s.serviceProvider.ServiceProvider.IDPMetadata == nil {
		return "", errors.NewValidationError("SAML IdP not configured")
	}

	req, err := s.serviceProvider.ServiceProvider.MakeAuthenticationRequest(
		s.serviceProvider.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return "", err
	}

	// Add RelayState if provided
	if relayState != "" {
		req.RelayState = relayState
	}

	// Create redirect URL
	redirectURL := req.Redirect(s.serviceProvider.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	return redirectURL.String(), nil
}

// HandleSAMLResponse processes SAML response and authenticates user
func (s *SAMLService) HandleSAMLResponse(ctx context.Context, r *http.Request, ipAddress string) (*auth.LoginResponse, error) {
	// Parse and validate SAML response
	assertion, err := s.serviceProvider.ServiceProvider.ParseResponse(r, []string{})
	if err != nil {
		s.logger.Error("Failed to parse SAML response", "error", err)
		return nil, errors.NewValidationError("Invalid SAML response")
	}

	// Extract user information from assertion
	userInfo, err := s.extractUserInfo(assertion)
	if err != nil {
		s.logger.Error("Failed to extract user info from SAML assertion", "error", err)
		return nil, errors.NewValidationError("Failed to extract user information")
	}

	// Check if user exists
	existingUser, err := s.authService.GetUserByEmail(ctx, userInfo.Email)
	if err == nil {
		// User exists, authenticate them
		return s.authenticateExistingUser(ctx, existingUser, userInfo, ipAddress)
	}

	// User doesn't exist
	if s.config.AutoCreateUsers {
		return s.createUserFromSAML(ctx, userInfo, ipAddress)
	}

	return nil, errors.NewValidationError("User not found and auto-creation is disabled")
}

// extractUserInfo extracts user information from SAML assertion
func (s *SAMLService) extractUserInfo(assertion *saml.Assertion) (*UserInfo, error) {
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return nil, fmt.Errorf("no subject or NameID in assertion")
	}

	userInfo := &UserInfo{
		ID:       assertion.Subject.NameID.Value,
		Provider: "saml",
	}

	// Extract attributes
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attribute := range attributeStatement.Attributes {
			attributeName := attribute.Name
			var attributeValue string

			if len(attribute.AttributeValues) > 0 {
				attributeValue = attribute.AttributeValues[0].Value
			}

			// Map attributes to user fields
			switch attributeName {
			case s.config.AttributeMappings.Email:
				userInfo.Email = attributeValue
			case s.config.AttributeMappings.FirstName:
				userInfo.FirstName = attributeValue
			case s.config.AttributeMappings.LastName:
				userInfo.LastName = attributeValue
			case s.config.AttributeMappings.Groups:
				// Groups can be multi-valued
				for _, attrValue := range attribute.AttributeValues {
					userInfo.Groups = append(userInfo.Groups, attrValue.Value)
				}
			}
		}
	}

	// Validate required fields
	if userInfo.Email == "" {
		return nil, fmt.Errorf("email not found in SAML assertion")
	}

	// Use NameID as email if email attribute is not configured
	if userInfo.Email == "" {
		userInfo.Email = userInfo.ID
	}

	return userInfo, nil
}

// authenticateExistingUser authenticates an existing user via SAML
func (s *SAMLService) authenticateExistingUser(ctx context.Context, user *auth.User, userInfo *UserInfo, ipAddress string) (*auth.LoginResponse, error) {
	// Update last login
	if err := s.authService.UpdateLastLogin(ctx, user.ID, ipAddress); err != nil {
		s.logger.Error("Failed to update last login", "user_id", user.ID, "error", err)
	}

	// Create audit log
	s.authService.CreateAuditLog(ctx, user.OrganizationID, &user.ID, "user.saml_login", "user", user.ID, map[string]interface{}{
		"saml_subject": userInfo.ID,
		"email":       userInfo.Email,
		"groups":      userInfo.Groups,
	}, ipAddress, "saml-login")

	// TODO: Implement session creation and return proper LoginResponse
	// This is a placeholder - you'd need to integrate with your enhanced auth service
	return &auth.LoginResponse{
		// Populate with actual user and organization data
	}, nil
}

// createUserFromSAML creates a new user from SAML assertion
func (s *SAMLService) createUserFromSAML(ctx context.Context, userInfo *UserInfo, ipAddress string) (*auth.LoginResponse, error) {
	if !s.config.AutoCreateUsers {
		return nil, errors.NewForbiddenError("User auto-creation is disabled")
	}

	// Create registration request from SAML info
	regReq := &auth.RegisterRequest{
		FirstName:       userInfo.FirstName,
		LastName:        userInfo.LastName,
		Email:           userInfo.Email,
		Password:        generateRandomPassword(), // Generate a random password for SAML users
		InvitationToken: "",                       // No invitation for SAML registration
	}

	// If default organization is specified, handle invitation flow
	if s.config.DefaultOrganizationID != "" {
		// TODO: Create invitation token for default organization
		// This would require implementing organization invitation logic
	}

	// Register the user
	loginResponse, err := s.authService.Register(ctx, regReq, ipAddress)
	if err != nil {
		s.logger.Error("Failed to register SAML user", "email", userInfo.Email, "error", err)
		return nil, err
	}

	// Mark email as verified since it came from SAML provider
	if err := s.authService.VerifyEmailByUserID(ctx, loginResponse.User.ID); err != nil {
		s.logger.Error("Failed to verify SAML user email", "user_id", loginResponse.User.ID, "error", err)
	}

	// Create audit log for SAML registration
	s.authService.CreateAuditLog(ctx, loginResponse.Organization.ID, &loginResponse.User.ID, "user.saml_registered", "user", loginResponse.User.ID, map[string]interface{}{
		"saml_subject": userInfo.ID,
		"email":       userInfo.Email,
		"groups":      userInfo.Groups,
	}, ipAddress, "saml-registration")

	s.logger.Info("SAML user registered successfully", "user_id", loginResponse.User.ID, "email", userInfo.Email)

	return loginResponse, nil
}

// InitiateSLO initiates Single Logout
func (s *SAMLService) InitiateSLO(ctx context.Context, userID string) (string, error) {
	if s.serviceProvider.ServiceProvider.IDPMetadata == nil {
		return "", errors.NewValidationError("SAML IdP not configured")
	}

	// Check if SLO is supported
	sloServices := s.serviceProvider.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices
	if len(sloServices) == 0 {
		return "", errors.NewValidationError("Single Logout not supported by IdP")
	}

	// Create logout request
	req, err := s.serviceProvider.ServiceProvider.MakeLogoutRequest(
		sloServices[0].Location,
		userID,
	)
	if err != nil {
		return "", err
	}

	// Create redirect URL
	redirectURL := req.Redirect(sloServices[0].Location)
	return redirectURL.String(), nil
}

// HandleSLOResponse processes Single Logout response
func (s *SAMLService) HandleSLOResponse(ctx context.Context, r *http.Request) error {
	// Parse SLO response
	_, err := s.serviceProvider.ServiceProvider.ParseLogoutResponse(r)
	if err != nil {
		s.logger.Error("Failed to parse SAML SLO response", "error", err)
		return errors.NewValidationError("Invalid SAML SLO response")
	}

	s.logger.Info("SAML SLO completed successfully")
	return nil
}

// Utility functions

// parseCertificateAndKey parses certificate and private key from PEM strings
func parseCertificateAndKey(certPEM, keyPEM string) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

// parseCertificate parses a certificate from PEM string
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// generateRandomPassword generates a secure random password for SAML users
func generateRandomPassword() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// SAML Handler for HTTP endpoints
type SAMLHandler struct {
	samlService *SAMLService
	logger      logger.Logger
}

// NewSAMLHandler creates a new SAML handler
func NewSAMLHandler(samlService *SAMLService, logger logger.Logger) *SAMLHandler {
	return &SAMLHandler{
		samlService: samlService,
		logger:      logger,
	}
}

// GetMetadata returns SAML metadata
func (h *SAMLHandler) GetMetadata(w http.ResponseWriter, r *http.Request) {
	metadata, err := h.samlService.GetMetadata()
	if err != nil {
		h.logger.Error("Failed to get SAML metadata", "error", err)
		http.Error(w, "Failed to generate metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	w.Write(metadata)
}

// InitiateSSO initiates SAML SSO
func (h *SAMLHandler) InitiateSSO(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	
	authURL, err := h.samlService.GetAuthURL(relayState)
	if err != nil {
		h.logger.Error("Failed to generate SAML auth URL", "error", err)
		http.Error(w, "Failed to initiate SSO", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// AssertionConsumerService handles SAML responses
func (h *SAMLHandler) AssertionConsumerService(w http.ResponseWriter, r *http.Request) {
	ipAddress := getClientIP(r)
	
	loginResponse, err := h.samlService.HandleSAMLResponse(r.Context(), r, ipAddress)
	if err != nil {
		h.logger.Error("SAML authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Return success response or redirect
	// In a real implementation, you might want to:
	// 1. Set session cookies
	// 2. Redirect to application
	// 3. Return JWT tokens
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "SAML authentication successful"}`))
}

// SingleLogoutService handles SAML logout requests
func (h *SAMLHandler) SingleLogoutService(w http.ResponseWriter, r *http.Request) {
	if err := h.samlService.HandleSLOResponse(r.Context(), r); err != nil {
		h.logger.Error("SAML SLO failed", "error", err)
		http.Error(w, "Logout failed", http.StatusBadRequest)
		return
	}

	// Clear session and redirect to logout page
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Logged out successfully"}`))
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to remote address
	return r.RemoteAddr
}

// SAML Configuration Templates
var DefaultAttributeMappings = AttributeMappings{
	Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
	LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
	Groups:    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
}

// Common IdP configurations
func GetAzureADAttributeMappings() AttributeMappings {
	return AttributeMappings{
		Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		Groups:    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
	}
}

func GetOktaAttributeMappings() AttributeMappings {
	return AttributeMappings{
		Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		Groups:    "http://schemas.xmlsoap.org/claims/Group",
	}
}