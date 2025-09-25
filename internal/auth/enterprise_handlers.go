package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"n8n-pro/internal/auth/ldap"
	"n8n-pro/internal/auth/saml"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"

	"github.com/gorilla/mux"
)

// EnterpriseAuthHandler handles enterprise authentication features
type EnterpriseAuthHandler struct {
	authService  *EnhancedAuthService
	samlService  *saml.SAMLService
	ldapService  *ldap.LDAPService
	samlHandler  *saml.SAMLHandler
	logger       logger.Logger
	validator    *validator.Validator
}

// NewEnterpriseAuthHandler creates a new enterprise auth handler
func NewEnterpriseAuthHandler(
	authService *EnhancedAuthService,
	samlService *saml.SAMLService,
	ldapService *ldap.LDAPService,
	logger logger.Logger,
	validator *validator.Validator,
) *EnterpriseAuthHandler {
	var samlHandler *saml.SAMLHandler
	if samlService != nil {
		samlHandler = saml.NewSAMLHandler(samlService, logger)
	}

	return &EnterpriseAuthHandler{
		authService: authService,
		samlService: samlService,
		ldapService: ldapService,
		samlHandler: samlHandler,
		logger:      logger,
		validator:   validator,
	}
}

// SAML Authentication Endpoints

// SAMLMetadata returns SAML metadata
func (h *EnterpriseAuthHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if h.samlHandler == nil {
		http.Error(w, "SAML not configured", http.StatusNotImplemented)
		return
	}
	h.samlHandler.GetMetadata(w, r)
}

// SAMLLogin initiates SAML SSO
func (h *EnterpriseAuthHandler) SAMLLogin(w http.ResponseWriter, r *http.Request) {
	if h.samlHandler == nil {
		http.Error(w, "SAML not configured", http.StatusNotImplemented)
		return
	}
	h.samlHandler.InitiateSSO(w, r)
}

// SAMLCallback handles SAML assertion consumer service
func (h *EnterpriseAuthHandler) SAMLCallback(w http.ResponseWriter, r *http.Request) {
	if h.samlHandler == nil {
		http.Error(w, "SAML not configured", http.StatusNotImplemented)
		return
	}
	h.samlHandler.AssertionConsumerService(w, r)
}

// SAMLLogout handles SAML single logout
func (h *EnterpriseAuthHandler) SAMLLogout(w http.ResponseWriter, r *http.Request) {
	if h.samlHandler == nil {
		http.Error(w, "SAML not configured", http.StatusNotImplemented)
		return
	}
	h.samlHandler.SingleLogoutService(w, r)
}

// LDAP Authentication Endpoints

// LDAPLoginRequest represents LDAP login request
type LDAPLoginRequest struct {
	Username string `json:"username" validate:"required,min=1,max=255"`
	Password string `json:"password" validate:"required,min=1"`
}

// LDAPLogin authenticates user via LDAP
func (h *EnterpriseAuthHandler) LDAPLogin(w http.ResponseWriter, r *http.Request) {
	if h.ldapService == nil {
		h.writeErrorResponse(w, errors.NewValidationError("LDAP not configured"), http.StatusNotImplemented)
		return
	}

	var req LDAPLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	ipAddress := getClientIP(r)

	loginResponse, err := h.ldapService.Authenticate(r.Context(), req.Username, req.Password, ipAddress)
	if err != nil {
		h.logger.Error("LDAP login failed", "username", req.Username, "error", err)
		h.writeErrorResponse(w, err, http.StatusUnauthorized)
		return
	}

	h.writeJSONResponse(w, loginResponse, http.StatusOK)
}

// LDAPTestConnectionRequest represents LDAP test connection request
type LDAPTestConnectionRequest struct {
	Host                string                        `json:"host" validate:"required"`
	Port                int                           `json:"port" validate:"min=1,max=65535"`
	UseSSL              bool                          `json:"use_ssl"`
	UseStartTLS         bool                          `json:"use_start_tls"`
	SkipVerify          bool                          `json:"skip_verify"`
	BindDN              string                        `json:"bind_dn"`
	BindPassword        string                        `json:"bind_password"`
	BaseDN              string                        `json:"base_dn" validate:"required"`
	UserFilter          string                        `json:"user_filter" validate:"required"`
	AttributeMappings   ldap.LDAPAttributeMappings    `json:"attribute_mappings"`
}

// LDAPTestConnection tests LDAP connection and configuration
func (h *EnterpriseAuthHandler) LDAPTestConnection(w http.ResponseWriter, r *http.Request) {
	var req LDAPTestConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Create temporary LDAP config for testing
	config := &ldap.LDAPConfig{
		Host:              req.Host,
		Port:              req.Port,
		UseSSL:            req.UseSSL,
		UseStartTLS:       req.UseStartTLS,
		SkipVerify:        req.SkipVerify,
		BindDN:            req.BindDN,
		BindPassword:      req.BindPassword,
		BaseDN:            req.BaseDN,
		UserFilter:        req.UserFilter,
		AttributeMappings: req.AttributeMappings,
	}

	// Create temporary LDAP service for testing
	testService := ldap.NewLDAPService(config, h.authService, h.logger)

	if err := testService.TestConnection(); err != nil {
		h.logger.Error("LDAP connection test failed", "error", err)
		h.writeErrorResponse(w, errors.NewValidationError("Connection test failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	h.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "LDAP connection test successful",
	}, http.StatusOK)
}

// LDAPSearchUsersRequest represents LDAP user search request
type LDAPSearchUsersRequest struct {
	Query string `json:"query" validate:"required,min=1"`
	Limit int    `json:"limit,omitempty"`
}

// LDAPSearchUsers searches for users in LDAP directory
func (h *EnterpriseAuthHandler) LDAPSearchUsers(w http.ResponseWriter, r *http.Request) {
	if h.ldapService == nil {
		h.writeErrorResponse(w, errors.NewValidationError("LDAP not configured"), http.StatusNotImplemented)
		return
	}

	var req LDAPSearchUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Set default limit if not provided
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	users, err := h.ldapService.SearchUsers(req.Query, req.Limit)
	if err != nil {
		h.logger.Error("LDAP user search failed", "query", req.Query, "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("User search failed"), http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, map[string]interface{}{
		"users": users,
		"total": len(users),
		"query": req.Query,
		"limit": req.Limit,
	}, http.StatusOK)
}

// Enterprise Configuration Management

// SAMLConfigRequest represents SAML configuration request
type SAMLConfigRequest struct {
	EntityID          string                    `json:"entity_id" validate:"required"`
	BaseURL           string                    `json:"base_url" validate:"required,url"`
	Certificate       string                    `json:"certificate" validate:"required"`
	PrivateKey        string                    `json:"private_key" validate:"required"`
	SignRequests      bool                      `json:"sign_requests"`
	AttributeMappings saml.AttributeMappings    `json:"attribute_mappings"`
	AutoCreateUsers   bool                      `json:"auto_create_users"`
}

// ConfigureSAML configures SAML authentication
func (h *EnterpriseAuthHandler) ConfigureSAML(w http.ResponseWriter, r *http.Request) {
	var req SAMLConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Create SAML configuration
	samlConfig := &saml.SAMLConfig{
		EntityID:          req.EntityID,
		BaseURL:           req.BaseURL,
		Certificate:       req.Certificate,
		PrivateKey:        req.PrivateKey,
		SignRequests:      req.SignRequests,
		AttributeMappings: req.AttributeMappings,
		AutoCreateUsers:   req.AutoCreateUsers,
	}

	// Create new SAML service
	samlService, err := saml.NewSAMLService(samlConfig, h.authService, h.logger)
	if err != nil {
		h.logger.Error("Failed to create SAML service", "error", err)
		h.writeErrorResponse(w, errors.NewValidationError("SAML configuration failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Update handler references
	h.samlService = samlService
	h.samlHandler = saml.NewSAMLHandler(samlService, h.logger)

	// TODO: Persist SAML configuration to database or configuration store

	h.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "SAML configured successfully",
	}, http.StatusOK)
}

// SAMLProviderConfigRequest represents SAML identity provider configuration
type SAMLProviderConfigRequest struct {
	EntityID                string                    `json:"entity_id" validate:"required"`
	SSOURL                  string                    `json:"sso_url" validate:"required,url"`
	SLOUrl                  string                    `json:"slo_url,omitempty"`
	Certificate             string                    `json:"certificate" validate:"required"`
	SignAuthnRequests       bool                      `json:"sign_authn_requests"`
	RequireSignedAssertions bool                      `json:"require_signed_assertions"`
	AttributeMappings       saml.AttributeMappings    `json:"attribute_mappings"`
}

// ConfigureSAMLProvider configures SAML identity provider
func (h *EnterpriseAuthHandler) ConfigureSAMLProvider(w http.ResponseWriter, r *http.Request) {
	if h.samlService == nil {
		h.writeErrorResponse(w, errors.NewValidationError("SAML service not configured"), http.StatusPreconditionFailed)
		return
	}

	var req SAMLProviderConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Create SAML provider configuration
	provider := &saml.SAMLProvider{
		EntityID:                req.EntityID,
		SSOURL:                  req.SSOURL,
		SLOUrl:                  req.SLOUrl,
		Certificate:             req.Certificate,
		SignAuthnRequests:       req.SignAuthnRequests,
		RequireSignedAssertions: req.RequireSignedAssertions,
		AttributeMappings:       req.AttributeMappings,
	}

	if err := h.samlService.ConfigureIdentityProvider(provider); err != nil {
		h.logger.Error("Failed to configure SAML identity provider", "error", err)
		h.writeErrorResponse(w, errors.NewValidationError("SAML provider configuration failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// TODO: Persist SAML provider configuration to database or configuration store

	h.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "SAML identity provider configured successfully",
	}, http.StatusOK)
}

// LDAPConfigRequest represents LDAP configuration request
type LDAPConfigRequest struct {
	Host                      string                        `json:"host" validate:"required"`
	Port                      int                           `json:"port" validate:"min=1,max=65535"`
	UseSSL                    bool                          `json:"use_ssl"`
	UseStartTLS               bool                          `json:"use_start_tls"`
	SkipVerify                bool                          `json:"skip_verify"`
	BindDN                    string                        `json:"bind_dn"`
	BindPassword              string                        `json:"bind_password"`
	BaseDN                    string                        `json:"base_dn" validate:"required"`
	UserFilter                string                        `json:"user_filter" validate:"required"`
	GroupBaseDN               string                        `json:"group_base_dn"`
	GroupFilter               string                        `json:"group_filter"`
	AttributeMappings         ldap.LDAPAttributeMappings    `json:"attribute_mappings"`
	DefaultOrganizationID     string                        `json:"default_organization_id,omitempty"`
	AutoCreateUsers           bool                          `json:"auto_create_users"`
	SyncGroups                bool                          `json:"sync_groups"`
}

// ConfigureLDAP configures LDAP authentication
func (h *EnterpriseAuthHandler) ConfigureLDAP(w http.ResponseWriter, r *http.Request) {
	var req LDAPConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Create LDAP configuration
	ldapConfig := &ldap.LDAPConfig{
		Host:                  req.Host,
		Port:                  req.Port,
		UseSSL:                req.UseSSL,
		UseStartTLS:           req.UseStartTLS,
		SkipVerify:            req.SkipVerify,
		BindDN:                req.BindDN,
		BindPassword:          req.BindPassword,
		BaseDN:                req.BaseDN,
		UserFilter:            req.UserFilter,
		GroupBaseDN:           req.GroupBaseDN,
		GroupFilter:           req.GroupFilter,
		AttributeMappings:     req.AttributeMappings,
		DefaultOrganizationID: req.DefaultOrganizationID,
		AutoCreateUsers:       req.AutoCreateUsers,
		SyncGroups:            req.SyncGroups,
	}

	// Create new LDAP service
	ldapService := ldap.NewLDAPService(ldapConfig, h.authService, h.logger)

	// Test the connection
	if err := ldapService.TestConnection(); err != nil {
		h.logger.Error("LDAP configuration test failed", "error", err)
		h.writeErrorResponse(w, errors.NewValidationError("LDAP configuration test failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Update handler reference
	h.ldapService = ldapService

	// TODO: Persist LDAP configuration to database or configuration store

	h.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "LDAP configured successfully",
	}, http.StatusOK)
}

// GetEnterpriseStatus returns enterprise authentication status
func (h *EnterpriseAuthHandler) GetEnterpriseStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"saml": map[string]interface{}{
			"enabled":     h.samlService != nil,
			"configured": h.samlService != nil,
		},
		"ldap": map[string]interface{}{
			"enabled":     h.ldapService != nil,
			"configured": h.ldapService != nil,
		},
	}

	h.writeJSONResponse(w, status, http.StatusOK)
}

// Utility functions

func (h *EnterpriseAuthHandler) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

func (h *EnterpriseAuthHandler) writeErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error": err.Error(),
		"code":  statusCode,
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode error response", "error", err)
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if there are multiple
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to remote address
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	
	return r.RemoteAddr
}

// Enterprise route registration helper
func (h *EnterpriseAuthHandler) RegisterRoutes(router *mux.Router) {
	// SAML routes
	samlRouter := router.PathPrefix("/saml").Subrouter()
	samlRouter.HandleFunc("/metadata", h.SAMLMetadata).Methods("GET")
	samlRouter.HandleFunc("/login", h.SAMLLogin).Methods("GET")
	samlRouter.HandleFunc("/acs", h.SAMLCallback).Methods("POST")
	samlRouter.HandleFunc("/sls", h.SAMLLogout).Methods("GET", "POST")

	// LDAP routes
	ldapRouter := router.PathPrefix("/ldap").Subrouter()
	ldapRouter.HandleFunc("/login", h.LDAPLogin).Methods("POST")
	ldapRouter.HandleFunc("/test", h.LDAPTestConnection).Methods("POST")
	ldapRouter.HandleFunc("/search", h.LDAPSearchUsers).Methods("POST")

	// Configuration routes (require admin permissions)
	configRouter := router.PathPrefix("/enterprise").Subrouter()
	configRouter.HandleFunc("/status", h.GetEnterpriseStatus).Methods("GET")
	configRouter.HandleFunc("/saml/configure", h.ConfigureSAML).Methods("POST")
	configRouter.HandleFunc("/saml/provider", h.ConfigureSAMLProvider).Methods("POST")
	configRouter.HandleFunc("/ldap/configure", h.ConfigureLDAP).Methods("POST")
}

// Configuration templates for common providers

// GetAzureADSAMLTemplate returns Azure AD SAML configuration template
func GetAzureADSAMLTemplate(tenantID, appID string) SAMLProviderConfigRequest {
	return SAMLProviderConfigRequest{
		EntityID: fmt.Sprintf("https://sts.windows.net/%s/", tenantID),
		SSOURL:   fmt.Sprintf("https://login.microsoftonline.com/%s/saml2", tenantID),
		SLOUrl:   fmt.Sprintf("https://login.microsoftonline.com/%s/saml2", tenantID),
		SignAuthnRequests:       false,
		RequireSignedAssertions: true,
		AttributeMappings:       saml.GetAzureADAttributeMappings(),
	}
}

// GetOktaSAMLTemplate returns Okta SAML configuration template
func GetOktaSAMLTemplate(oktaDomain, appID string) SAMLProviderConfigRequest {
	return SAMLProviderConfigRequest{
		EntityID: fmt.Sprintf("http://www.okta.com/%s", appID),
		SSOURL:   fmt.Sprintf("https://%s/app/%s/%s/sso/saml", oktaDomain, appID, appID),
		SLOUrl:   fmt.Sprintf("https://%s/app/%s/%s/slo/saml", oktaDomain, appID, appID),
		SignAuthnRequests:       false,
		RequireSignedAssertions: true,
		AttributeMappings:       saml.GetOktaAttributeMappings(),
	}
}

// GetActiveDirectoryLDAPTemplate returns Active Directory LDAP configuration template
func GetActiveDirectoryLDAPTemplate(host, baseDN string) LDAPConfigRequest {
	config := ldap.GetActiveDirectoryConfig(host, baseDN)
	return LDAPConfigRequest{
		Host:              config.Host,
		Port:              config.Port,
		UseSSL:            config.UseSSL,
		UseStartTLS:       config.UseStartTLS,
		SkipVerify:        config.SkipVerify,
		BaseDN:            config.BaseDN,
		UserFilter:        config.UserFilter,
		GroupBaseDN:       config.GroupBaseDN,
		GroupFilter:       config.GroupFilter,
		AttributeMappings: config.AttributeMappings,
		AutoCreateUsers:   config.AutoCreateUsers,
		SyncGroups:        config.SyncGroups,
	}
}

// GetOpenLDAPTemplate returns OpenLDAP configuration template
func GetOpenLDAPTemplate(host, baseDN string) LDAPConfigRequest {
	config := ldap.GetOpenLDAPConfig(host, baseDN)
	return LDAPConfigRequest{
		Host:              config.Host,
		Port:              config.Port,
		UseSSL:            config.UseSSL,
		UseStartTLS:       config.UseStartTLS,
		SkipVerify:        config.SkipVerify,
		BaseDN:            config.BaseDN,
		UserFilter:        config.UserFilter,
		GroupBaseDN:       config.GroupBaseDN,
		GroupFilter:       config.GroupFilter,
		AttributeMappings: config.AttributeMappings,
		AutoCreateUsers:   config.AutoCreateUsers,
		SyncGroups:        config.SyncGroups,
	}
}