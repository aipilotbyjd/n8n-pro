package routes

import (
	"net/http"

	"n8n-pro/internal/application/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/nodes"
	"n8n-pro/internal/teams"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// SetupRoutes configures all API routes
func SetupRoutes(
	router *chi.Mux,
	db *gorm.DB,
	authSvc *auth.Service,
	jwtSvc *jwt.Service,
	teamSvc *teams.Service,
	nodeRegistry *nodes.Registry,
	log logger.Logger,
) {
	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Don't mount /api/v1 here since main.go already mounts it
	// Just add the auth-specific routes that main.go expects
}

// Placeholder handlers - these would be implemented properly
func handleRegister(authSvc *auth.Service, jwtSvc *jwt.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Registration endpoint - coming soon"}`))
	}
}

func handleLogin(authSvc *auth.Service, jwtSvc *jwt.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Login endpoint - coming soon"}`))
	}
}

func handleRefresh(jwtSvc *jwt.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Refresh endpoint - coming soon"}`))
	}
}

func handleForgotPassword(authSvc *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Forgot password endpoint - coming soon"}`))
	}
}

func handleResetPassword(authSvc *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Reset password endpoint - coming soon"}`))
	}
}

func handleVerifyEmail(authSvc *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Email verification endpoint - coming soon"}`))
	}
}

func handleGetCurrentUser(authSvc *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Get current user endpoint - coming soon"}`))
	}
}

func handleUpdateCurrentUser(authSvc *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Update current user endpoint - coming soon"}`))
	}
}

func handleLogout(authSvc *auth.Service, jwtSvc *jwt.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"Logout endpoint - coming soon"}`))
	}
}