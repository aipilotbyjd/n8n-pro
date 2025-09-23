package handlers

import (
	"encoding/json"
	"net/http"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
)

// SettingsHandler handles settings-related HTTP requests
type SettingsHandler struct {
	logger logger.Logger
}

// NewSettingsHandler creates a new settings handler
func NewSettingsHandler(logger logger.Logger) *SettingsHandler {
	return &SettingsHandler{
		logger: logger,
	}
}

// UserSettingsResponse represents user settings in API responses
type UserSettingsResponse struct {
	Theme              string                 `json:"theme"`
	Language           string                 `json:"language"`
	Timezone           string                 `json:"timezone"`
	Notifications      NotificationSettings   `json:"notifications"`
	Privacy            PrivacySettings        `json:"privacy"`
	WorkflowSettings   WorkflowSettings       `json:"workflow_settings"`
	DashboardSettings  DashboardSettings      `json:"dashboard_settings"`
	CustomSettings     map[string]interface{} `json:"custom_settings"`
}

// NotificationSettings represents notification preferences
type NotificationSettings struct {
	Email     EmailNotificationSettings     `json:"email"`
	InApp     InAppNotificationSettings     `json:"in_app"`
	Webhook   WebhookNotificationSettings   `json:"webhook"`
}

// EmailNotificationSettings represents email notification preferences
type EmailNotificationSettings struct {
	Enabled           bool `json:"enabled"`
	WorkflowSuccess   bool `json:"workflow_success"`
	WorkflowFailure   bool `json:"workflow_failure"`
	WorkflowStart     bool `json:"workflow_start"`
	WeeklyReport      bool `json:"weekly_report"`
	SecurityAlerts    bool `json:"security_alerts"`
	TeamInvitations   bool `json:"team_invitations"`
}

// InAppNotificationSettings represents in-app notification preferences
type InAppNotificationSettings struct {
	Enabled         bool `json:"enabled"`
	Sound           bool `json:"sound"`
	Desktop         bool `json:"desktop"`
	WorkflowEvents  bool `json:"workflow_events"`
	TeamActivities  bool `json:"team_activities"`
	SystemUpdates   bool `json:"system_updates"`
}

// WebhookNotificationSettings represents webhook notification preferences
type WebhookNotificationSettings struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"`
	Secret  string `json:"secret,omitempty"`
}

// PrivacySettings represents privacy preferences
type PrivacySettings struct {
	Analytics       bool `json:"analytics"`
	ErrorReporting  bool `json:"error_reporting"`
	UsageStatistics bool `json:"usage_statistics"`
	ProfileVisible  bool `json:"profile_visible"`
}

// WorkflowSettings represents workflow-related preferences
type WorkflowSettings struct {
	AutoSave        bool `json:"auto_save"`
	AutoSaveInterval int  `json:"auto_save_interval"` // minutes
	DefaultTimeout   int  `json:"default_timeout"`    // seconds
	MaxExecutions    int  `json:"max_executions"`
	SaveExecutionData bool `json:"save_execution_data"`
	ExecutionMode    string `json:"execution_mode"` // "queue" or "immediate"
}

// DashboardSettings represents dashboard preferences
type DashboardSettings struct {
	DefaultView   string   `json:"default_view"`   // "workflows", "executions", "analytics"
	WidgetLayout  []string `json:"widget_layout"`
	RefreshRate   int      `json:"refresh_rate"`   // seconds
	ShowWelcome   bool     `json:"show_welcome"`
	CompactView   bool     `json:"compact_view"`
}

// SystemSettingsResponse represents system settings in API responses
type SystemSettingsResponse struct {
	General        GeneralSystemSettings        `json:"general"`
	Security       SecuritySystemSettings       `json:"security"`
	Email          EmailSystemSettings          `json:"email"`
	Storage        StorageSystemSettings        `json:"storage"`
	Execution      ExecutionSystemSettings      `json:"execution"`
	Features       FeatureSystemSettings        `json:"features"`
	Maintenance    MaintenanceSystemSettings    `json:"maintenance"`
}

// GeneralSystemSettings represents general system settings
type GeneralSystemSettings struct {
	SiteName        string `json:"site_name"`
	SiteURL         string `json:"site_url"`
	AdminEmail      string `json:"admin_email"`
	DefaultTimezone string `json:"default_timezone"`
	DefaultLanguage string `json:"default_language"`
}

// SecuritySystemSettings represents security system settings
type SecuritySystemSettings struct {
	PasswordPolicy       PasswordPolicy `json:"password_policy"`
	SessionTimeout       int            `json:"session_timeout"`    // minutes
	MaxLoginAttempts     int            `json:"max_login_attempts"`
	TwoFactorRequired    bool           `json:"two_factor_required"`
	AllowedDomains       []string       `json:"allowed_domains"`
	IPWhitelist          []string       `json:"ip_whitelist"`
}

// PasswordPolicy represents password requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireNumbers bool `json:"require_numbers"`
	RequireSymbols bool `json:"require_symbols"`
}

// EmailSystemSettings represents email system settings
type EmailSystemSettings struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password,omitempty"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name"`
}

// StorageSystemSettings represents storage system settings
type StorageSystemSettings struct {
	MaxFileSize       int64  `json:"max_file_size"`       // bytes
	AllowedFileTypes  []string `json:"allowed_file_types"`
	RetentionDays     int    `json:"retention_days"`
	BackupEnabled     bool   `json:"backup_enabled"`
	BackupFrequency   string `json:"backup_frequency"`    // "daily", "weekly", "monthly"
}

// ExecutionSystemSettings represents execution system settings
type ExecutionSystemSettings struct {
	MaxConcurrentExecutions int    `json:"max_concurrent_executions"`
	DefaultTimeout          int    `json:"default_timeout"`           // seconds
	MaxMemoryUsage          int64  `json:"max_memory_usage"`          // bytes
	ExecutionMode           string `json:"execution_mode"`            // "queue" or "immediate"
	QueueMaxSize            int    `json:"queue_max_size"`
}

// FeatureSystemSettings represents feature flags
type FeatureSystemSettings struct {
	BetaFeatures    bool `json:"beta_features"`
	Analytics       bool `json:"analytics"`
	Marketplace     bool `json:"marketplace"`
	CustomNodes     bool `json:"custom_nodes"`
	APIAccess       bool `json:"api_access"`
	WebhooksEnabled bool `json:"webhooks_enabled"`
}

// MaintenanceSystemSettings represents maintenance settings
type MaintenanceSystemSettings struct {
	MaintenanceMode    bool   `json:"maintenance_mode"`
	MaintenanceMessage string `json:"maintenance_message"`
	ScheduledDowntime  *string `json:"scheduled_downtime,omitempty"`
}

// UpdateUserSettingsRequest represents the request to update user settings
type UpdateUserSettingsRequest struct {
	Theme              *string                `json:"theme,omitempty"`
	Language           *string                `json:"language,omitempty"`
	Timezone           *string                `json:"timezone,omitempty"`
	Notifications      *NotificationSettings  `json:"notifications,omitempty"`
	Privacy            *PrivacySettings       `json:"privacy,omitempty"`
	WorkflowSettings   *WorkflowSettings      `json:"workflow_settings,omitempty"`
	DashboardSettings  *DashboardSettings     `json:"dashboard_settings,omitempty"`
	CustomSettings     map[string]interface{} `json:"custom_settings,omitempty"`
}

// GetUserSettings retrieves current user settings
func (h *SettingsHandler) GetUserSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// In a real implementation, you would fetch this from the database
	// For now, we'll return default settings
	settings := UserSettingsResponse{
		Theme:    "light",
		Language: "en",
		Timezone: "UTC",
		Notifications: NotificationSettings{
			Email: EmailNotificationSettings{
				Enabled:         true,
				WorkflowSuccess: false,
				WorkflowFailure: true,
				WorkflowStart:   false,
				WeeklyReport:    true,
				SecurityAlerts:  true,
				TeamInvitations: true,
			},
			InApp: InAppNotificationSettings{
				Enabled:        true,
				Sound:          true,
				Desktop:        true,
				WorkflowEvents: true,
				TeamActivities: true,
				SystemUpdates:  true,
			},
			Webhook: WebhookNotificationSettings{
				Enabled: false,
			},
		},
		Privacy: PrivacySettings{
			Analytics:       true,
			ErrorReporting:  true,
			UsageStatistics: true,
			ProfileVisible:  true,
		},
		WorkflowSettings: WorkflowSettings{
			AutoSave:         true,
			AutoSaveInterval: 5,
			DefaultTimeout:   300,
			MaxExecutions:    100,
			SaveExecutionData: true,
			ExecutionMode:    "queue",
		},
		DashboardSettings: DashboardSettings{
			DefaultView:  "workflows",
			WidgetLayout: []string{"recent_executions", "workflow_stats", "system_health"},
			RefreshRate:  30,
			ShowWelcome:  true,
			CompactView:  false,
		},
		CustomSettings: make(map[string]interface{}),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings": settings,
	})
}

// UpdateUserSettings updates user settings
func (h *SettingsHandler) UpdateUserSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateUserSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in update user settings request", "error", err)
		errors.WriteErrorResponse(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// In a real implementation, you would update the database
	// For now, we'll just log the update and return success
	h.logger.Info("User settings updated", "user_id", userCtx.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Settings updated successfully",
	})
}

// GetSystemSettings retrieves system settings (admin only)
func (h *SettingsHandler) GetSystemSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user is admin (in a real implementation)
	// For now, we'll just check if user has admin role
	if userCtx.Role != "admin" {
		errors.WriteErrorResponse(w, errors.NewForbiddenError("Admin access required"))
		return
	}

	// Return mock system settings
	settings := SystemSettingsResponse{
		General: GeneralSystemSettings{
			SiteName:        "n8n Pro",
			SiteURL:         "http://localhost:8080",
			AdminEmail:      "admin@example.com",
			DefaultTimezone: "UTC",
			DefaultLanguage: "en",
		},
		Security: SecuritySystemSettings{
			PasswordPolicy: PasswordPolicy{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumbers: true,
				RequireSymbols: false,
			},
			SessionTimeout:    1440, // 24 hours
			MaxLoginAttempts:  5,
			TwoFactorRequired: false,
			AllowedDomains:    []string{},
			IPWhitelist:       []string{},
		},
		Email: EmailSystemSettings{
			SMTPHost:     "smtp.gmail.com",
			SMTPPort:     587,
			SMTPUsername: "noreply@example.com",
			FromEmail:    "noreply@example.com",
			FromName:     "n8n Pro",
		},
		Storage: StorageSystemSettings{
			MaxFileSize:      10485760, // 10MB
			AllowedFileTypes: []string{".json", ".csv", ".txt", ".xml"},
			RetentionDays:    90,
			BackupEnabled:    true,
			BackupFrequency:  "daily",
		},
		Execution: ExecutionSystemSettings{
			MaxConcurrentExecutions: 10,
			DefaultTimeout:          300,
			MaxMemoryUsage:          1073741824, // 1GB
			ExecutionMode:           "queue",
			QueueMaxSize:            1000,
		},
		Features: FeatureSystemSettings{
			BetaFeatures:    false,
			Analytics:       true,
			Marketplace:     true,
			CustomNodes:     true,
			APIAccess:       true,
			WebhooksEnabled: true,
		},
		Maintenance: MaintenanceSystemSettings{
			MaintenanceMode:    false,
			MaintenanceMessage: "",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings": settings,
	})
}

// UpdateSystemSettings updates system settings (admin only)
func (h *SettingsHandler) UpdateSystemSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	if userCtx.Role != "admin" {
		errors.WriteErrorResponse(w, errors.NewForbiddenError("Admin access required"))
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in update system settings request", "error", err)
		errors.WriteErrorResponse(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	// In a real implementation, you would validate and update the database
	h.logger.Info("System settings updated", "admin_id", userCtx.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "System settings updated successfully",
	})
}

// ResetUserSettings resets user settings to defaults
func (h *SettingsHandler) ResetUserSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// In a real implementation, you would reset settings in the database
	h.logger.Info("User settings reset to defaults", "user_id", userCtx.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Settings reset to defaults successfully",
	})
}

// ExportSettings exports user settings as JSON
func (h *SettingsHandler) ExportSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get current settings (mock for now)
	settings := map[string]interface{}{
		"theme":    "light",
		"language": "en",
		"timezone": "UTC",
		// ... other settings
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=settings.json")
	json.NewEncoder(w).Encode(settings)

	h.logger.Info("Settings exported", "user_id", userCtx.ID)
}

// ImportSettings imports user settings from JSON
func (h *SettingsHandler) ImportSettings(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		errors.WriteErrorResponse(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var settings map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		h.logger.Warn("Invalid JSON in import settings request", "error", err)
		errors.WriteErrorResponse(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	// In a real implementation, you would validate and import the settings
	h.logger.Info("Settings imported", "user_id", userCtx.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Settings imported successfully",
		"imported_count": len(settings),
	})
}