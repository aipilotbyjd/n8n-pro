x# Complete Authentication System Guide for n8n Pro

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Components Breakdown](#components-breakdown)
4. [Authentication Flow](#authentication-flow)
5. [Code Examples](#code-examples)
6. [Security Features](#security-features)
7. [API Endpoints](#api-endpoints)
8. [Configuration](#configuration)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

## Overview

The n8n Pro authentication system is a comprehensive, enterprise-grade security solution built in Go. It uses **JSON Web Tokens (JWT)** for stateless authentication and includes advanced features like multi-factor authentication (MFA), session management, rate limiting, and audit logging.

### Key Features
- ✅ JWT-based authentication (stateless)
- ✅ User registration and login
- ✅ Email verification
- ✅ Password reset functionality
- ✅ Session management with device tracking
- ✅ Rate limiting and security monitoring
- ✅ Role-based access control (RBAC)
- ✅ Multi-factor authentication (MFA)
- ✅ API key authentication
- ✅ Audit logging and security events

---

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │   Database      │
│   (React/Vue)   │    │   (Chi Router)  │    │   (PostgreSQL)  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │ HTTP Requests        │ Auth Middleware      │ User Data
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Layer                         │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   Auth Handlers │   JWT Service   │      Auth Service           │
│   (HTTP Layer)  │   (Token Mgmt)  │   (Business Logic)         │
└─────────┬───────┴─────────┬───────┴─────────┬───────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Repository    │ │   Session Mgr   │ │   Rate Limiter  │
│   (Database)    │ │   (Redis)       │ │   (In-Memory)   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## Components Breakdown

### 1. **Auth Handlers** (`internal/api/handlers/auth_handlers.go`)
- **Purpose**: Handle HTTP requests for authentication endpoints
- **Responsibilities**:
  - Parse incoming HTTP requests
  - Validate request data
  - Call appropriate auth service methods
  - Return HTTP responses
- **Endpoints**: `/register`, `/login`, `/logout`, `/refresh-token`, etc.

### 2. **Auth Service** (`internal/auth/auth_service.go`)
- **Purpose**: Core business logic for authentication
- **Responsibilities**:
  - User registration and validation
  - Password hashing and verification
  - Email verification management
  - Password reset functionality
  - Security event logging
  - Rate limiting integration

### 3. **JWT Service** (`internal/auth/jwt/jwt.go`)
- **Purpose**: JSON Web Token management
- **Responsibilities**:
  - Generate access and refresh tokens
  - Validate and parse tokens
  - Handle token expiration
  - Token blacklisting (revocation)
  - Extract user information from tokens

### 4. **Auth Middleware** (`internal/api/middleware/auth.go`)
- **Purpose**: Protect API endpoints
- **Responsibilities**:
  - Extract tokens from HTTP headers
  - Validate tokens on each request
  - Add user context to requests
  - Handle authorization (roles/scopes)
  - Skip authentication for public endpoints

### 5. **Repository Layer** (`internal/auth/service.go`)
- **Purpose**: Database operations
- **Responsibilities**:
  - CRUD operations for users
  - Token storage and retrieval
  - Session management
  - Audit logging

### 6. **Models** (`internal/models/auth_models.go`)
- **Purpose**: Data structures
- **Key Models**:
  - `User`: User account information
  - `AuthSession`: Active user sessions
  - `EmailToken`: Email verification/reset tokens
  - `LoginAttempt`: Security monitoring
  - `SecurityEvent`: Audit logs

---

## Authentication Flow

### 1. **User Registration Flow**

```
User Frontend    →    Auth Handler    →    Auth Service    →    Database
     │                      │                    │                  │
     │ POST /register       │                    │                  │
     ├─────────────────────▶│                    │                  │
     │                      │ RegisterRequest    │                  │
     │                      ├───────────────────▶│                  │
     │                      │                    │ ValidateUser     │
     │                      │                    │ HashPassword     │
     │                      │                    │ CreateUser       │
     │                      │                    ├─────────────────▶│
     │                      │                    │                  │
     │                      │                    │ SendVerifyEmail  │
     │                      │                    │◀─────────────────┤
     │                      │ AuthResponse       │                  │
     │                      │◀───────────────────┤                  │
     │ 201 Created          │                    │                  │
     │◀─────────────────────┤                    │                  │
```

### 2. **Login Flow**

```
User Frontend    →    Auth Handler    →    Auth Service    →    JWT Service    →    Database
     │                      │                    │                      │                │
     │ POST /login          │                    │                      │                │
     ├─────────────────────▶│                    │                      │                │
     │                      │ LoginRequest       │                      │                │
     │                      ├───────────────────▶│                      │                │
     │                      │                    │ ValidateCredentials  │                │
     │                      │                    ├─────────────────────────────────────▶│
     │                      │                    │                      │                │
     │                      │                    │ GenerateTokenPair    │                │
     │                      │                    ├─────────────────────▶│                │
     │                      │                    │                      │ Create JWT     │
     │                      │                    │                      │ Access Token   │
     │                      │                    │                      │ Refresh Token  │
     │                      │                    │ TokenPair            │                │
     │                      │                    │◀─────────────────────┤                │
     │                      │                    │ CreateSession        │                │
     │                      │                    ├─────────────────────────────────────▶│
     │                      │ AuthResponse       │                      │                │
     │                      │◀───────────────────┤                      │                │
     │ 200 OK + Tokens      │                    │                      │                │
     │◀─────────────────────┤                    │                      │                │
```

### 3. **Protected Request Flow**

```
User Frontend    →    Auth Middleware    →    JWT Service    →    Protected Handler
     │                        │                     │                     │
     │ GET /api/workflows      │                     │                     │
     │ Authorization: Bearer   │                     │                     │
     ├────────────────────────▶│                     │                     │
     │                        │ ExtractToken        │                     │
     │                        │ ValidateToken       │                     │
     │                        ├────────────────────▶│                     │
     │                        │                     │ Parse JWT           │
     │                        │                     │ Check Expiration    │
     │                        │                     │ Validate Signature  │
     │                        │ Claims              │                     │
     │                        │◀────────────────────┤                     │
     │                        │ AddUserToContext    │                     │
     │                        │ ContinueRequest     │                     │
     │                        ├────────────────────────────────────────────▶│
     │                        │                     │                     │ ProcessRequest
     │ 200 OK + Data          │                     │                     │◀──────────────
     │◀────────────────────────┤                     │                     │
```

---

## Code Examples

### 1. **How to Register a New User**

```go
// Example: Register a new user
func ExampleRegisterUser() {
    // This is what happens when POST /api/v1/auth/register is called

    // 1. Create registration request
    registerReq := &auth.RegisterRequest{
        Email:           "user@example.com",
        Password:        "securePassword123!",
        ConfirmPassword: "securePassword123!",
        FirstName:       "John",
        LastName:        "Doe",
        OrganizationName: "My Company",
    }

    // 2. Auth service processes the registration
    authService := auth.NewAuthService(repo)
    response, err := authService.Register(ctx, registerReq)
    if err != nil {
        // Handle registration error
        log.Error("Registration failed", "error", err)
        return
    }

    // 3. Response contains user info and tokens
    fmt.Printf("User registered: %s\n", response.User.Email)
    fmt.Printf("Access token: %s\n", response.AccessToken)
    fmt.Printf("Refresh token: %s\n", response.RefreshToken)
}
```

### 2. **How to Login**

```go
// Example: User login
func ExampleLoginUser() {
    // This is what happens when POST /api/v1/auth/login is called

    loginReq := &auth.LoginRequest{
        Email:    "user@example.com",
        Password: "securePassword123!",
        DeviceInfo: &auth.SessionCreateRequest{
            IPAddress: "192.168.1.100",
            UserAgent: "Mozilla/5.0 (Chrome)",
            DeviceID:  "device-12345",
        },
    }

    response, err := authService.Login(ctx, loginReq)
    if err != nil {
        log.Error("Login failed", "error", err)
        return
    }

    // Store tokens for subsequent API calls
    accessToken := response.AccessToken
    refreshToken := response.RefreshToken

    fmt.Printf("Login successful for: %s\n", response.User.Email)
}
```

### 3. **How to Make Authenticated API Calls**

```go
// Example: Making authenticated requests
func ExampleAuthenticatedRequest() {
    // Create HTTP client
    client := &http.Client{}

    // Create request
    req, _ := http.NewRequest("GET", "http://localhost:8080/api/v1/workflows", nil)

    // Add authorization header
    req.Header.Set("Authorization", "Bearer "+accessToken)

    // Make request
    resp, err := client.Do(req)
    if err != nil {
        log.Error("Request failed", "error", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode == 401 {
        // Token expired, need to refresh
        newTokens := refreshAccessToken(refreshToken)
        // Retry request with new token
    }
}
```

### 4. **How JWT Tokens Work**

```go
// Example: Understanding JWT structure
func ExampleJWTStructure() {
    // A JWT token looks like this:
    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature

    // It contains three parts separated by dots:
    // 1. Header (algorithm and token type)
    // 2. Payload (claims - user data)
    // 3. Signature (verifies token hasn't been tampered with)

    // When you make a request, the middleware:
    token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

    // 1. Extracts token from Authorization header
    bearerToken := strings.TrimPrefix(token, "Bearer ")

    // 2. Validates and parses the token
    claims, err := jwtService.ValidateToken(bearerToken)
    if err != nil {
        // Token is invalid or expired
        return
    }

    // 3. Extracts user information
    userID := claims.UserID
    email := claims.Email
    role := claims.Role
    scopes := claims.Scopes

    fmt.Printf("Authenticated user: %s (%s)\n", email, userID)
}
```

---

## Security Features

### 1. **Password Security**
- **Bcrypt hashing** with configurable cost
- **Password complexity** requirements
- **Password history** tracking (prevents reuse)
- **Account lockout** after failed attempts

### 2. **Session Management**
- **Device tracking** and fingerprinting
- **Session expiration** and renewal
- **Concurrent session** limits
- **Session revocation** (logout all devices)

### 3. **Rate Limiting**
- **Login attempt** limiting by IP/user
- **API request** rate limiting
- **Token bucket** algorithm implementation
- **Automatic blocking** of suspicious IPs

### 4. **Security Monitoring**
- **Login attempt** logging
- **Security event** tracking
- **Audit trail** for all actions
- **Anomaly detection** (unusual locations/devices)

### 5. **Token Security**
- **Short-lived access tokens** (15 minutes)
- **Long-lived refresh tokens** (7 days)
- **Token rotation** on refresh
- **Token blacklisting** for revocation

---

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Authentication Required |
|--------|----------|-------------|------------------------|
| `POST` | `/api/v1/auth/register` | Register new user | No |
| `POST` | `/api/v1/auth/login` | User login | No |
| `POST` | `/api/v1/auth/logout` | User logout | Yes |
| `POST` | `/api/v1/auth/refresh` | Refresh access token | No (refresh token) |
| `GET` | `/api/v1/auth/verify-email?token=xxx` | Verify email address | No |
| `POST` | `/api/v1/auth/forgot-password` | Request password reset | No |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token | No |
| `GET` | `/api/v1/auth/me` | Get current user info | Yes |
| `PUT` | `/api/v1/auth/me` | Update user profile | Yes |
| `POST` | `/api/v1/auth/change-password` | Change password | Yes |

### Example API Requests

#### 1. Register User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123!",
    "confirm_password": "securePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "organization_name": "My Company"
  }'
```

#### 2. Login User
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123!"
  }'
```

#### 3. Make Authenticated Request
```bash
curl -X GET http://localhost:8080/api/v1/workflows \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

#### 4. Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

---

## Configuration

### Environment Variables

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=password

# JWT Configuration
JWT_SECRET=your-secret-key-here
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=168h  # 7 days
JWT_ISSUER=n8n-pro
JWT_AUDIENCE=n8n-pro-api

# Redis Configuration (for sessions and caching)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@yourcompany.com

# Security Configuration
BCRYPT_COST=12
PASSWORD_MIN_LENGTH=8
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=30m
REQUIRE_EMAIL_VERIFICATION=true
REQUIRE_MFA=false

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1h

# Session Configuration
SESSION_TIMEOUT=24h
MAX_CONCURRENT_SESSIONS=5
```

### Auth Service Configuration

```go
// Example: Configure auth service in your application
func SetupAuthService() *auth.AuthService {
    config := &auth.AuthConfig{
        BcryptCost:                12,
        PasswordMinLength:         8,
        RequireEmailVerification:  true,
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

    // Initialize services
    db := setupDatabase()
    repo := auth.NewPostgresRepository(db)
    jwtService := jwt.New(jwt.DefaultConfig())

    return auth.NewAuthService(repo, jwtService, config)
}
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. **Token Validation Fails**

**Problem**: Getting "Invalid or expired token" errors

**Solutions**:
```go
// Check if token is properly formatted
token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

// Debug token claims without validation
claims, err := jwtService.ExtractClaims(token)
if err != nil {
    log.Error("Cannot parse token", "error", err)
    return
}

// Check expiration
if claims.IsExpired() {
    log.Info("Token expired", "exp", claims.ExpiresAt)
    // Use refresh token to get new access token
}

// Verify JWT secret matches
// Make sure JWT_SECRET environment variable is the same
// across all services and deployments
```

#### 2. **Database Connection Issues**

**Problem**: Authentication fails due to database errors

**Solutions**:
```go
// Test database connection
func TestDatabaseConnection() {
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database", "error", err)
    }

    // Test with a simple query
    var count int64
    err = db.Model(&models.User{}).Count(&count).Error
    if err != nil {
        log.Error("Database query failed", "error", err)
    }

    log.Info("Database connection OK", "user_count", count)
}
```

#### 3. **Password Hashing Issues**

**Problem**: Login fails even with correct password

**Solutions**:
```go
// Debug password verification
func DebugPasswordVerification(plainPassword, hashedPassword string) {
    err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
    if err != nil {
        log.Error("Password verification failed", "error", err)

        // Check if hash is valid
        cost, err := bcrypt.Cost([]byte(hashedPassword))
        if err != nil {
            log.Error("Invalid bcrypt hash", "error", err)
        } else {
            log.Info("Hash cost", "cost", cost)
        }
    } else {
        log.Info("Password verification successful")
    }
}
```

#### 4. **CORS Issues**

**Problem**: Frontend can't make requests due to CORS errors

**Solutions**:
```go
// Configure CORS middleware properly
func SetupCORS() func(http.Handler) http.Handler {
    return middleware.CORSMiddleware(
        []string{"http://localhost:3000", "https://yourdomain.com"}, // allowed origins
        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},         // allowed methods
        []string{"Authorization", "Content-Type", "X-Requested-With"}, // allowed headers
    )
}
```

#### 5. **Rate Limiting Issues**

**Problem**: Getting blocked by rate limiter

**Solutions**:
```bash
# Check rate limit status
curl -X GET http://localhost:8080/api/v1/auth/login \
  -H "X-Forwarded-For: 192.168.1.100" \
  -v  # See rate limit headers

# Headers returned:
# X-RateLimit-Limit: 5
# X-RateLimit-Remaining: 2
# X-RateLimit-Reset: 1640995200
```

### Debugging Tools

#### 1. **JWT Token Inspector**
```go
// Debug JWT tokens
func InspectJWTToken(tokenString string) {
    // Parse without validation to see contents
    token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &jwt.Claims{})
    if err != nil {
        log.Error("Failed to parse token", "error", err)
        return
    }

    // Print token header
    header, _ := json.MarshalIndent(token.Header, "", "  ")
    fmt.Printf("Header: %s\n", header)

    // Print token claims
    claims, _ := json.MarshalIndent(token.Claims, "", "  ")
    fmt.Printf("Claims: %s\n", claims)
}
```

#### 2. **Database Query Logger**
```go
// Enable GORM query logging for debugging
func SetupDatabaseWithLogging() *gorm.DB {
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
        Logger: gormLogger.Default.LogMode(gormLogger.Info),
    })
    if err != nil {
        log.Fatal("Failed to connect to database", "error", err)
    }
    return db
}
```

---

## Best Practices

### 1. **Security Best Practices**

#### Token Management
```go
// ✅ Good: Short-lived access tokens
config.AccessTokenDuration = 15 * time.Minute

// ✅ Good: Longer refresh tokens with rotation
config.RefreshTokenDuration = 7 * 24 * time.Hour
config.EnableRefreshRotation = true

// ❌ Bad: Long-lived access tokens
config.AccessTokenDuration = 24 * time.Hour // Too long!
```

#### Password Security
```go
// ✅ Good: Strong password requirements
func ValidatePassword(password string) error {
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters")
    }

    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
    hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
    hasSpecial := regexp.MustCompile(`[!@#$%^&*]`).MatchString(password)

    if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
        return errors.New("password must contain upper, lower, number, and special character")
    }

    return nil
}
```

### 2. **Error Handling Best Practices**

```go
// ✅ Good: Don't reveal sensitive information
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    // ... login logic ...

    if err != nil {
        // Log detailed error for debugging
        h.logger.Error("Login failed", "error", err, "email", req.Email, "ip", getClientIP(r))

        // Return generic error to user (prevents enumeration)
        writeError(w, errors.New(errors.ErrorTypeAuthentication,
            errors.CodeInvalidCredentials, "Invalid email or password"))
        return
    }
}

// ❌ Bad: Revealing too much information
if err != nil {
    writeError(w, fmt.Errorf("User with email %s not found in database", req.Email))
}
```

### 3. **Frontend Integration Best Practices**

#### Token Storage
```javascript
// ✅ Good: Store tokens securely
class AuthService {
    constructor() {
        this.accessToken = null;
        this.refreshToken = localStorage.getItem('refresh_token'); // HttpOnly cookie is better
    }

    async login(email, password) {
        const response = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            this.accessToken = data.access_token;
            this.refreshToken = data.refresh_token;
            localStorage.setItem('refresh_token', data.refresh_token);
        }

        return data;
    }

    async makeAuthenticatedRequest(url, options = {}) {
        // Add authorization header
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${this.accessToken}`
        };

        let response = await fetch(url, { ...options, headers });

        // Handle token expiration
        if (response.status === 401) {
            await this.refreshAccessToken();
            headers['Authorization'] = `Bearer ${this.accessToken}`;
            response = await fetch(url, { ...options, headers });
        }

        return response;
    }

    async refreshAccessToken() {
        const response = await fetch('/api/v1/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: this.refreshToken })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            this.refreshToken = data.refresh_token;
            localStorage.setItem('refresh_token', data.refresh_token);
        } else {
            // Refresh failed, redirect to login
            this.logout();
            window.location.href = '/login';
        }
    }

    logout() {
        this.accessToken = null;
        this.refreshToken = null;
        localStorage.removeItem('refresh_token');
    }
}
```

### 4. **Production Deployment Best Practices**

#### Environment Configuration
```bash
# ✅ Good: Use strong, random secrets
JWT_SECRET=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 32)

# ✅ Good: Enable security features
REQUIRE_EMAIL_VERIFICATION=true
REQUIRE_HTTPS=true
LOG_SECURITY_EVENTS=true

# ✅ Good: Set appropriate timeouts
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=7d
SESSION_TIMEOUT=24h
```

#### Monitoring and Logging
```go
// ✅ Good: Comprehensive security logging
func (s *AuthService) logSecurityEvent(ctx context.Context, eventType, description string, userID *string) {
    event := &models.SecurityEvent{
        UserID:        userID,
        EventType:     eventType,
        EventCategory: "auth",
        Severity:      "info",
        Description:   description,
        IPAddress:     getIPFromContext(ctx),
        UserAgent:     getUserAgentFromContext(ctx),
        CreatedAt:     time.Now(),
    }

    if err := s.repo.CreateSecurityEvent(ctx, event); err != nil {
        s.logger.Error("Failed to log security event", "error", err)
    }

    // Also log to structured logger for real-time monitoring
    s.logger.Info("Security event",
        "type", eventType,
        "user_id", userID,
        "description", description,
    )
}
```

### 5. **Testing Best Practices**

#### Unit Testing Authentication
```go
func TestAuthService_Login(t *testing.T) {
    // Setup test database and dependencies
    db := setupTestDB(t)
    repo := auth.NewPostgresRepository(db)
    jwtService := jwt.New(jwt.DefaultConfig())
    authService := auth.NewAuthService(repo, jwtService, auth.DefaultAuthConfig())

    // Create test user
    user := &models.User{
        Email:        "test@example.com",
        PasswordHash: hashPassword("password123"),
        EmailVerified: true,
        IsActive:     true,
    }
    err := repo.CreateUser(context.Background(), user)
    require.NoError(t, err)

    // Test successful login
    loginReq := &auth.LoginRequest{
        Email:    "test@example.com",
        Password: "password123",
    }

    resp, err := authService.Login(context.Background(), loginReq)
    require.NoError(t, err)
    assert.NotEmpty(t, resp.AccessToken)
    assert.NotEmpty(t, resp.RefreshToken)
    assert.Equal(t, user.Email, resp.User.Email)

    // Test invalid password
    loginReq.Password = "wrongpassword"
    _, err = authService.Login(context.Background(), loginReq)
    assert.Error(t, err)
}
```

---

## Summary

The n8n Pro authentication system provides:

1. **Secure Authentication**: JWT-based tokens with proper validation
2. **User Management**: Registration, login, password reset, email verification
3. **Session Management**: Device tracking, session limits, logout functionality
4. **Security Features**: Rate limiting, audit logging, password policies
5. **Enterprise Features**: RBAC, MFA support, API keys, LDAP integration

### Key Takeaways for Beginners:

1. **Stateless Authentication**: JWT tokens contain user information, no server-side sessions
2. **Two Token System**: Short-lived access tokens + long-lived refresh tokens
3. **Middleware Protection**: Authentication middleware validates tokens on each request
4. **Security First**: Rate limiting, password policies, and comprehensive logging
5. **Scalable Design**: Horizontal scaling, database-backed, production-ready

### Next Steps:

1. Set up your development environment
2. Test the API endpoints using curl or Postman
3. Integrate with your frontend application
4. Configure security settings for production
5. Set up monitoring and alerting

For additional help, check the `/docs` directory for specific integration guides and examples!
