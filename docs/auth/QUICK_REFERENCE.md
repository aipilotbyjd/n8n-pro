# Authentication System - Quick Reference

## 🚀 Quick Setup

### 1. Environment Variables
```bash
# Required
JWT_SECRET=your-32-char-secret-key
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_NAME=n8n_pro

# Optional (with defaults)
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=168h
BCRYPT_COST=12
MAX_LOGIN_ATTEMPTS=5
```

### 2. Initialize Services
```go
// main.go
func main() {
    db := setupDatabase()
    repo := auth.NewPostgresRepository(db)
    jwtService := jwt.New(jwt.DefaultConfig())
    authService := auth.NewAuthService(repo, jwtService, auth.DefaultAuthConfig())
    
    // Setup routes
    router := chi.NewRouter()
    authHandler := handlers.NewAuthHandler(authService, jwtService, logger)
    
    router.Route("/api/v1/auth", func(r chi.Router) {
        r.Post("/register", authHandler.Register)
        r.Post("/login", authHandler.Login)
        r.Post("/logout", authHandler.Logout)
        r.Post("/refresh", authHandler.RefreshToken)
    })
}
```

## 📡 API Endpoints

### Authentication Endpoints
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `POST` | `/auth/register` | ❌ | Register new user |
| `POST` | `/auth/login` | ❌ | User login |
| `POST` | `/auth/logout` | ✅ | User logout |
| `POST` | `/auth/refresh` | ❌ | Refresh access token |
| `GET` | `/auth/verify-email?token=xxx` | ❌ | Verify email |
| `POST` | `/auth/forgot-password` | ❌ | Request password reset |
| `POST` | `/auth/reset-password` | ❌ | Reset password |
| `GET` | `/auth/me` | ✅ | Get current user |

## 💻 Code Examples

### Register User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Make Authenticated Request
```bash
curl -X GET http://localhost:8080/api/v1/workflows \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

## 🔧 Go Code Snippets

### Protect Routes with Middleware
```go
// Protect all routes in a group
router.Group(func(r chi.Router) {
    r.Use(middleware.RequireAuth(jwtService, logger))
    r.Get("/workflows", workflowHandler.List)
    r.Post("/workflows", workflowHandler.Create)
})

// Require specific role
router.Group(func(r chi.Router) {
    r.Use(middleware.RequireRole("admin", jwtService, logger))
    r.Get("/admin/users", adminHandler.ListUsers)
})

// Require specific scopes
router.Group(func(r chi.Router) {
    r.Use(middleware.RequireAuth(jwtService, logger))
    r.Use(middleware.RequireScopes("workflows:read", "workflows:write"))
    r.Post("/workflows", workflowHandler.Create)
})
```

### Get User from Request Context
```go
func MyHandler(w http.ResponseWriter, r *http.Request) {
    user := middleware.GetUserFromContext(r.Context())
    if user == nil {
        http.Error(w, "Unauthorized", 401)
        return
    }
    
    fmt.Printf("User ID: %s, Email: %s, Role: %s\n", 
        user.ID, user.Email, user.Role)
}
```

### Manual Token Validation
```go
func ValidateTokenManually(tokenString string, jwtService *jwt.Service) {
    claims, err := jwtService.ValidateAccessToken(tokenString)
    if err != nil {
        log.Error("Invalid token", "error", err)
        return
    }
    
    fmt.Printf("User: %s (%s)\n", claims.Email, claims.UserID)
    fmt.Printf("Role: %s, Team: %s\n", claims.Role, claims.TeamID)
    fmt.Printf("Expires: %v\n", claims.ExpiresAt)
}
```

## 🌐 Frontend Integration

### JavaScript/React Example
```javascript
class AuthService {
    constructor() {
        this.baseURL = 'http://localhost:8080/api/v1';
        this.accessToken = null;
        this.refreshToken = localStorage.getItem('refresh_token');
    }

    // Login
    async login(email, password) {
        const response = await fetch(`${this.baseURL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            this.refreshToken = data.refresh_token;
            localStorage.setItem('refresh_token', data.refresh_token);
            return data.user;
        }
        throw new Error('Login failed');
    }

    // Make authenticated request
    async apiCall(endpoint, options = {}) {
        const headers = {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
            ...options.headers
        };

        let response = await fetch(`${this.baseURL}${endpoint}`, {
            ...options,
            headers
        });

        // Handle token expiration
        if (response.status === 401) {
            await this.refreshAccessToken();
            headers['Authorization'] = `Bearer ${this.accessToken}`;
            response = await fetch(`${this.baseURL}${endpoint}`, {
                ...options,
                headers
            });
        }

        return response;
    }

    // Refresh token
    async refreshAccessToken() {
        const response = await fetch(`${this.baseURL}/auth/refresh`, {
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
            this.logout();
        }
    }

    // Logout
    logout() {
        this.accessToken = null;
        this.refreshToken = null;
        localStorage.removeItem('refresh_token');
    }
}

// Usage
const auth = new AuthService();

// Login
try {
    const user = await auth.login('user@example.com', 'password123');
    console.log('Logged in:', user);
} catch (error) {
    console.error('Login failed:', error);
}

// Make API call
const response = await auth.apiCall('/workflows');
const workflows = await response.json();
```

## ⚠️ Error Codes

| HTTP Status | Error Code | Description | Action |
|-------------|------------|-------------|--------|
| `400` | `validation_error` | Invalid input data | Check request format |
| `401` | `invalid_credentials` | Wrong email/password | Verify credentials |
| `401` | `token_expired` | Access token expired | Use refresh token |
| `401` | `invalid_token` | Malformed/invalid token | Re-authenticate |
| `403` | `insufficient_permissions` | Missing role/scope | Check user permissions |
| `429` | `rate_limit_exceeded` | Too many requests | Wait and retry |
| `500` | `internal_error` | Server error | Check logs |

## 🔍 Debugging

### Check Token Contents (without validation)
```bash
# Decode JWT token (header and payload only)
echo "YOUR_TOKEN_HERE" | cut -d'.' -f2 | base64 -d | jq .
```

### Test Database Connection
```go
func TestDBConnection() {
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal("DB connection failed", "error", err)
    }
    
    var count int64
    db.Model(&models.User{}).Count(&count)
    log.Info("Database OK", "users", count)
}
```

### Enable Debug Logging
```go
// Enable GORM query logging
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
    Logger: logger.Default.LogMode(logger.Info),
})

// Enable JWT debug
jwtService := jwt.New(&jwt.Config{
    Secret: "your-secret",
    Debug:  true, // If available
})
```

## 🛡️ Security Checklist

### Development
- [ ] Use strong JWT secret (32+ characters)
- [ ] Set short access token expiry (15 minutes)
- [ ] Enable HTTPS in production
- [ ] Validate all inputs
- [ ] Hash passwords with bcrypt (cost 12+)

### Production
- [ ] Use environment variables for secrets
- [ ] Enable rate limiting
- [ ] Set up monitoring/alerting
- [ ] Regular security updates
- [ ] Audit logs enabled
- [ ] CORS configured properly

## 📋 Common Configuration

### JWT Configuration
```go
&jwt.Config{
    Secret:                "your-32-char-secret",
    AccessTokenDuration:   15 * time.Minute,
    RefreshTokenDuration:  7 * 24 * time.Hour,
    Issuer:                "n8n-pro",
    Audience:              "n8n-pro-api",
    EnableRefreshRotation: true,
}
```

### Auth Service Configuration
```go
&auth.AuthConfig{
    BcryptCost:              12,
    PasswordMinLength:       8,
    RequireEmailVerification: true,
    EmailTokenExpiry:        24 * time.Hour,
    PasswordResetExpiry:     30 * time.Minute,
    MaxLoginAttempts:        5,
    LockoutDuration:         30 * time.Minute,
    SessionTimeout:          24 * time.Hour,
    LogSecurityEvents:       true,
}
```

## 🔗 Useful Links

- **Complete Guide**: `/docs/auth/COMPLETE_AUTH_GUIDE.md`
- **API Documentation**: `/docs/api/`
- **Security Guide**: `/docs/guides/auth-security.md`
- **Deployment Guide**: `/docs/deployment/`

## 📞 Support

For issues or questions:
1. Check the logs: `tail -f app.log`
2. Review the complete documentation
3. Test with curl commands above
4. Check database connectivity
5. Verify environment variables