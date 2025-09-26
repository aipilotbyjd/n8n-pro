package routes

import (
	"net/http"

	"n8n-pro/internal/api/handlers"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// SetupSimpleAuthRoutes sets up authentication routes with simple handlers
func SetupSimpleAuthRoutes(r chi.Router, db *gorm.DB, jwtService *jwt.Service, logger logger.Logger) {
	// Create simple auth handler
	simpleAuthHandler := handlers.NewSimpleAuthHandler(db, jwtService, logger)
	
	// Auth routes
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", simpleAuthHandler.SimpleLogin)
		r.Post("/register", simpleAuthHandler.SimpleRegister)
		
		// Health check for auth
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "healthy", "service": "auth"}`))
		})
	})
}