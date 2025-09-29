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

// SetupRoutes configures non-auth API routes
// Note: Auth routes are handled separately in main.go to properly use the enhanced auth service
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

	// Version endpoint
	router.Get("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":"1.0.0","status":"running"}`))
	})

	// API v1 routes - only add non-auth routes here
	// (Auth routes are handled in main.go where the enhanced auth service is available)
	router.Route("/api/v1", func(r chi.Router) {
		// Add other routes here, like team routes, node routes, etc.
		// when those handlers are implemented
		
		// For now, just add a placeholder
		r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"api running","service":"api"}`))
		})
		
		// Example of how to add team routes when handlers are ready:
		// r.Route("/teams", func(r chi.Router) {
		// 	r.Get("/", handleGetTeams)
		// 	r.Get("/{id}", handleGetTeam)
		// })
	})
}