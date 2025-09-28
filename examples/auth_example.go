package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"n8n-pro/internal/presentation/http/handlers"
	"n8n-pro/internal/presentation/http/middleware"
	"n8n-pro/internal/application/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Example: Complete Authentication System Usage
// This example shows how to:
// 1. Set up the authentication system
// 2. Create HTTP handlers with auth
// 3. Register and login users
// 4. Make authenticated API calls
// 5. Handle token refresh

func main() {
	fmt.Println("🚀 n8n Pro Authentication System Example")
	fmt.Println("==========================================")

	// 1. Setup the authentication system
	authSystem := setupAuthSystem()

	// 2. Setup HTTP server with auth routes
	server := setupHTTPServer(authSystem)

	// 3. Start server in background
	go func() {
		fmt.Println("🌐 Server starting on http://localhost:8080")
		if err := http.ListenAndServe(":8080", server); err != nil {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// 4. Run practical examples
	runAuthExamples()
}

// AuthSystem holds all authentication components
type AuthSystem struct {
	DB          *gorm.DB
	AuthService *auth.AuthService
	JWTService  *jwt.Service
	Repository  auth.Repository
	Logger      logger.Logger
}

// setupAuthSystem initializes all authentication components
func setupAuthSystem() *AuthSystem {
	fmt.Println("📦 Setting up authentication system...")

	// 1. Setup logger
	logger := logger.New("auth-example")

	// 2. Setup database (in-memory SQLite for this example)
	db, err := gorm.Open(postgres.Open("host=localhost user=postgres password=password dbname=n8n_pro_example port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 3. Auto-migrate tables
	err = db.AutoMigrate(
		&models.User{},
		&models.AuthSession{},
		&models.EmailToken{},
		&models.LoginAttempt{},
		&models.SecurityEvent{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// 4. Setup JWT service
	jwtConfig := &jwt.Config{
		Secret:                "your-super-secret-key-32-characters",
		AccessTokenDuration:   15 * time.Minute,
		RefreshTokenDuration:  7 * 24 * time.Hour,
		Issuer:                "n8n-pro",
		Audience:              "n8n-pro-api",
		EnableRefreshRotation: true,
	}
	jwtService := jwt.New(jwtConfig)

	// 5. Setup auth repository
	repository := auth.NewPostgresRepository(db)

	// 6. Setup auth service
	authConfig := &auth.AuthConfig{
		BcryptCost:               12,
		PasswordMinLength:        8,
		RequireEmailVerification: false, // Disabled for demo
		EmailTokenExpiry:         24 * time.Hour,
		PasswordResetExpiry:      30 * time.Minute,
		MaxLoginAttempts:         5,
		LockoutDuration:          30 * time.Minute,
		RequireMFA:               false,
		RequireCaptcha:           false,
		LogSecurityEvents:        true,
		AllowConcurrentSessions:  true,
		SessionTimeout:           24 * time.Hour,
	}

	// Initialize the auth service with all dependencies
	authService := auth.NewSimpleAuthService(repository, jwtService, authConfig)

	fmt.Println("✅ Authentication system ready!")

	return &AuthSystem{
		DB:          db,
		AuthService: authService,
		JWTService:  jwtService,
		Repository:  repository,
		Logger:      logger,
	}
}

// setupHTTPServer creates HTTP server with authentication routes
func setupHTTPServer(authSystem *AuthSystem) http.Handler {
	fmt.Println("🔧 Setting up HTTP routes...")

	router := chi.NewRouter()

	// Setup auth handlers
	authHandler := handlers.NewAuthHandler(
		authSystem.AuthService,
		authSystem.JWTService,
		authSystem.Logger,
	)

	// Public routes (no authentication required)
	router.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.RefreshToken)
		r.Get("/verify-email", authHandler.VerifyEmail)
		r.Post("/forgot-password", authHandler.ForgotPassword)
		r.Post("/reset-password", authHandler.ResetPassword)
	})

	// Protected routes (authentication required)
	router.Route("/api/v1", func(r chi.Router) {
		// Apply authentication middleware
		r.Use(middleware.RequireAuth(authSystem.JWTService, authSystem.Logger))

		// User endpoints
		r.Get("/auth/me", authHandler.GetCurrentUser)
		r.Put("/auth/me", authHandler.UpdateCurrentUser)
		r.Post("/auth/change-password", authHandler.ChangePassword)
		r.Post("/auth/logout", authHandler.Logout)

		// Example protected endpoints
		r.Get("/workflows", handleGetWorkflows)
		r.Post("/workflows", handleCreateWorkflow)

		// Admin-only endpoints
		r.Route("/admin", func(r chi.Router) {
			r.Use(middleware.RequireRole("admin", authSystem.JWTService, authSystem.Logger))
			r.Get("/users", handleListUsers)
		})
	})

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Println("✅ HTTP routes ready!")
	return router
}

// Example protected handlers
func handleGetWorkflows(w http.ResponseWriter, r *http.Request) {
	// Get user from context (added by auth middleware)
	user := middleware.GetUserFromContext(r.Context())

	workflows := []map[string]interface{}{
		{"id": "1", "name": "My First Workflow", "owner_id": user.ID},
		{"id": "2", "name": "Data Sync Workflow", "owner_id": user.ID},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":    workflows,
		"user_id": user.ID,
		"message": fmt.Sprintf("Hello %s! Here are your workflows.", user.Email),
	})
}

func handleCreateWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())

	var req map[string]interface{}
	json.NewDecoder(r.Body).Decode(&req)

	workflow := map[string]interface{}{
		"id":       "new-workflow-123",
		"name":     req["name"],
		"owner_id": user.ID,
		"created":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":    workflow,
		"message": "Workflow created successfully!",
	})
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	// This is an admin-only endpoint
	users := []map[string]interface{}{
		{"id": "1", "email": "admin@example.com", "role": "admin"},
		{"id": "2", "email": "user@example.com", "role": "user"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":    users,
		"message": "Admin access granted - all users listed",
	})
}

// runAuthExamples demonstrates how to use the authentication system
func runAuthExamples() {
	fmt.Println("\n🎯 Running Authentication Examples")
	fmt.Println("===================================")

	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := "http://localhost:8080/api/v1"

	// Example 1: Register a new user
	fmt.Println("\n1️⃣ Registering a new user...")
	registerUser(client, baseURL, "john@example.com", "SecurePass123!", "John", "Doe")

	// Example 2: Login user and get tokens
	fmt.Println("\n2️⃣ Logging in user...")
	tokens := loginUser(client, baseURL, "john@example.com", "SecurePass123!")
	if tokens == nil {
		fmt.Println("❌ Login failed, stopping examples")
		return
	}

	// Example 3: Make authenticated requests
	fmt.Println("\n3️⃣ Making authenticated API calls...")
	makeAuthenticatedRequest(client, baseURL+"/workflows", "GET", tokens.AccessToken, nil)

	// Example 4: Create a workflow
	fmt.Println("\n4️⃣ Creating a workflow...")
	workflowData := map[string]interface{}{
		"name":        "My Example Workflow",
		"description": "Created via API",
	}
	makeAuthenticatedRequest(client, baseURL+"/workflows", "POST", tokens.AccessToken, workflowData)

	// Example 5: Get current user info
	fmt.Println("\n5️⃣ Getting current user info...")
	makeAuthenticatedRequest(client, baseURL+"/auth/me", "GET", tokens.AccessToken, nil)

	// Example 6: Try admin endpoint (should fail)
	fmt.Println("\n6️⃣ Trying admin endpoint (should fail)...")
	makeAuthenticatedRequest(client, baseURL+"/admin/users", "GET", tokens.AccessToken, nil)

	// Example 7: Refresh token
	fmt.Println("\n7️⃣ Refreshing access token...")
	refreshToken(client, baseURL, tokens.RefreshToken)

	// Example 8: Logout
	fmt.Println("\n8️⃣ Logging out...")
	logout(client, baseURL, tokens.AccessToken)

	fmt.Println("\n🎉 All examples completed!")
}

// TokenResponse represents login/refresh response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// registerUser demonstrates user registration
func registerUser(client *http.Client, baseURL, email, password, firstName, lastName string) {
	registerData := map[string]interface{}{
		"email":             email,
		"password":          password,
		"confirm_password":  password,
		"first_name":        firstName,
		"last_name":         lastName,
		"organization_name": "Example Corp",
	}

	resp, err := makeRequest(client, baseURL+"/auth/register", "POST", "", registerData)
	if err != nil {
		fmt.Printf("❌ Registration failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 {
		fmt.Printf("✅ User registered successfully: %s\n", email)
	} else {
		fmt.Printf("❌ Registration failed with status: %d\n", resp.StatusCode)
		var errorResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errorResp)
		fmt.Printf("Error: %v\n", errorResp)
	}
}

// loginUser demonstrates user login and returns tokens
func loginUser(client *http.Client, baseURL, email, password string) *TokenResponse {
	loginData := map[string]interface{}{
		"email":    email,
		"password": password,
	}

	resp, err := makeRequest(client, baseURL+"/auth/login", "POST", "", loginData)
	if err != nil {
		fmt.Printf("❌ Login failed: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var response struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			TokenType    string `json:"token_type"`
			User         struct {
				Email string `json:"email"`
				ID    string `json:"id"`
			} `json:"user"`
		}

		json.NewDecoder(resp.Body).Decode(&response)
		fmt.Printf("✅ Login successful for: %s\n", response.User.Email)
		fmt.Printf("   Access Token: %s...\n", response.AccessToken[:20])
		fmt.Printf("   Expires in: %d seconds\n", response.ExpiresIn)

		return &TokenResponse{
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			ExpiresIn:    response.ExpiresIn,
			TokenType:    response.TokenType,
		}
	}

	fmt.Printf("❌ Login failed with status: %d\n", resp.StatusCode)
	var errorResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&errorResp)
	fmt.Printf("Error: %v\n", errorResp)
	return nil
}

// makeAuthenticatedRequest demonstrates making API calls with authentication
func makeAuthenticatedRequest(client *http.Client, url, method, token string, data interface{}) {
	resp, err := makeRequest(client, url, method, token, data)
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("📡 %s %s -> Status: %d\n", method, url, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Success: %v\n", response["message"])
		if data, ok := response["data"]; ok {
			fmt.Printf("   Data: %v\n", data)
		}
	} else {
		fmt.Printf("❌ Error: %v\n", response)
	}
}

// refreshToken demonstrates token refresh
func refreshToken(client *http.Client, baseURL, refreshToken string) {
	refreshData := map[string]interface{}{
		"refresh_token": refreshToken,
	}

	resp, err := makeRequest(client, baseURL+"/auth/refresh", "POST", "", refreshData)
	if err != nil {
		fmt.Printf("❌ Token refresh failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var response TokenResponse
		json.NewDecoder(resp.Body).Decode(&response)
		fmt.Printf("✅ Token refreshed successfully\n")
		fmt.Printf("   New Access Token: %s...\n", response.AccessToken[:20])
	} else {
		fmt.Printf("❌ Token refresh failed with status: %d\n", resp.StatusCode)
	}
}

// logout demonstrates user logout
func logout(client *http.Client, baseURL, token string) {
	resp, err := makeRequest(client, baseURL+"/auth/logout", "POST", token, nil)
	if err != nil {
		fmt.Printf("❌ Logout failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("✅ Logout successful\n")
	} else {
		fmt.Printf("❌ Logout failed with status: %d\n", resp.StatusCode)
	}
}

// makeRequest is a helper function for making HTTP requests
func makeRequest(client *http.Client, url, method, token string, data interface{}) (*http.Response, error) {
	var body *bytes.Buffer
	if data != nil {
		jsonData, _ := json.Marshal(data)
		body = bytes.NewBuffer(jsonData)
	} else {
		body = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return client.Do(req)
}

// Example of how to integrate authentication in your own handlers
func ExampleCustomHandler() {
	// This shows how you would write your own authenticated handlers

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Get user from context (added by auth middleware)
		user := middleware.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Now you have access to user information
		fmt.Printf("User ID: %s\n", user.ID)
		fmt.Printf("Email: %s\n", user.Email)
		fmt.Printf("Role: %s\n", user.Role)
		fmt.Printf("Team ID: %s\n", user.TeamID)
		fmt.Printf("Scopes: %v\n", user.Scopes)

		// Check user permissions
		if user.Role != "admin" && user.Role != "user" {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		// Your business logic here
		response := map[string]interface{}{
			"message": fmt.Sprintf("Hello %s!", user.Email),
			"data":    "Your protected data here",
			"user_id": user.ID,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

	// Use this handler with auth middleware
	_ = handler
}

// Example of how to validate JWT tokens manually
func ExampleManualTokenValidation() {
	// Initialize JWT service
	jwtService := jwt.New(&jwt.Config{
		Secret: "your-secret-key",
	})

	// Example token (you would get this from HTTP header)
	tokenString := "your.jwt.token.here"

	// Validate token
	claims, err := jwtService.ValidateAccessToken(tokenString)
	if err != nil {
		fmt.Printf("❌ Token validation failed: %v\n", err)
		return
	}

	// Use claims
	fmt.Printf("✅ Token valid for user: %s\n", claims.Email)
	fmt.Printf("   User ID: %s\n", claims.UserID)
	fmt.Printf("   Role: %s\n", claims.Role)
	fmt.Printf("   Expires: %v\n", claims.ExpiresAt)

	// Check if token is about to expire (refresh if needed)
	if time.Until(claims.ExpiresAt) < 5*time.Minute {
		fmt.Println("⚠️  Token expires soon, should refresh")
	}
}
