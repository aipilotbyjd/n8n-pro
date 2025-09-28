# Security Documentation - n8n Pro Authentication System

## Table of Contents
1. [Overview](#overview)
2. [Authentication Architecture](#authentication-architecture)
3. [Security Features](#security-features)
4. [Password Security](#password-security)
5. [Session Management](#session-management)
6. [Rate Limiting](#rate-limiting)
7. [Multi-Factor Authentication](#multi-factor-authentication)
8. [Security Headers](#security-headers)
9. [Audit Logging](#audit-logging)
10. [Threat Mitigation](#threat-mitigation)
11. [Configuration](#configuration)
12. [Best Practices](#best-practices)

## Overview

The n8n Pro authentication system implements defense-in-depth security with multiple layers of protection following OWASP guidelines and industry best practices.

### Key Security Principles
- **Zero Trust**: Never trust, always verify
- **Defense in Depth**: Multiple security layers
- **Least Privilege**: Minimal access by default
- **Secure by Default**: Security enabled out of the box
- **Audit Everything**: Comprehensive logging

## Authentication Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client    │────▶│  Rate Limiter │────▶│   CAPTCHA    │
└─────────────┘     └──────────────┘     └──────────────┘
                             │
                             ▼
                    ┌──────────────┐
                    │  Validation  │
                    └──────────────┘
                             │
                             ▼
                    ┌──────────────┐     ┌──────────────┐
                    │Auth Service  │────▶│     MFA      │
                    └──────────────┘     └──────────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
            ┌──────────────┐  ┌──────────────┐
            │   Session    │  │     JWT      │
            └──────────────┘  └──────────────┘
                    │                 │
                    └────────┬────────┘
                             ▼
                    ┌──────────────┐
                    │   Database   │
                    └──────────────┘
```

## Security Features

### Core Security Components
| Component | Description | Implementation |
|-----------|-------------|----------------|
| Password Hashing | Bcrypt with configurable cost | Cost factor: 12 (default) |
| Token Generation | Cryptographically secure random | 32 bytes from crypto/rand |
| Session Management | Server-side sessions with tokens | SHA256 hashed tokens |
| Rate Limiting | Token bucket algorithm | Per IP and per user |
| CAPTCHA | Google reCAPTCHA v3 | Score threshold: 0.5 |
| MFA | TOTP (RFC 6238) | 6-digit codes, 30-second window |

## Password Security

### Password Requirements
```yaml
minimum_length: 12
maximum_length: 128
require_uppercase: true
require_lowercase: true
require_numbers: true
require_special: true
minimum_strength: 3  # Scale of 0-4
```

### Password History
- **History Limit**: Last 5 passwords stored
- **Storage**: Bcrypt hashed
- **Validation**: Prevents reuse of recent passwords

### Password Lifecycle
1. **Creation**: Validated against requirements
2. **Storage**: Bcrypt hash (never plain text)
3. **Reset**: Token-based with 1-hour expiry
4. **Change**: Requires current password verification
5. **Age**: 90-day maximum age (configurable)

### Common Password Protection
Blocked passwords include:
- Common passwords (password, 123456, qwerty)
- Username variations
- Company name variations
- Dictionary words

## Session Management

### Session Security Features
| Feature | Default | Description |
|---------|---------|-------------|
| Duration | 24 hours | Maximum session lifetime |
| Inactivity Timeout | 2 hours | Auto-logout after inactivity |
| Concurrent Sessions | 5 | Maximum per user |
| Device Tracking | Enabled | Fingerprint and location |
| Token Rotation | Enabled | Refresh token rotation |

### Session Storage
```go
type Session struct {
    ID               string    // UUID v4
    RefreshTokenHash string    // SHA256 hash
    DeviceFingerprint string   // Device identifier
    IPAddress        string    // Client IP
    UserAgent        string    // Browser info
    ExpiresAt        time.Time // Absolute expiry
    MFAVerified      bool      // MFA status
}
```

### Session Lifecycle
1. **Creation**: After successful authentication
2. **Validation**: On each request
3. **Refresh**: Token rotation on refresh
4. **Revocation**: Manual or automatic expiry
5. **Cleanup**: Automated expired session removal

## Rate Limiting

### Limits by Action
| Action | Limit | Window | Block Duration |
|--------|-------|--------|----------------|
| Login | 5 attempts | 15 minutes | 30 minutes |
| Registration | 3 attempts | 1 hour | 1 hour |
| Password Reset | 5 attempts | 1 hour | 1 hour |
| API Requests | 60/minute | 1 minute | Progressive |
| Email Verification | 3 attempts | 24 hours | 24 hours |

### Progressive Delays
Failed attempts trigger progressive delays:
- 1st failure: No delay
- 2nd failure: 1 second
- 3rd failure: 2 seconds
- 4th failure: 3 seconds
- 5th failure: 5 seconds + block

### Rate Limit Storage
- **In-Memory**: Fast access with sync.Map
- **Database**: Persistent across restarts
- **Cleanup**: Automatic bucket expiry

## Multi-Factor Authentication

### TOTP Configuration
```yaml
algorithm: SHA256
digits: 6
period: 30 seconds
skew: 1  # ±30 seconds tolerance
issuer: "n8n Pro"
```

### Backup Codes
- **Count**: 10 codes generated
- **Format**: XXXX-XXXX (8 characters)
- **Storage**: Bcrypt hashed
- **Usage**: Single-use only
- **Regeneration**: Requires password

### MFA Flow
1. **Setup**: Generate secret + QR code
2. **Verification**: Validate initial code
3. **Enable**: Activate after verification
4. **Login**: Required after password
5. **Recovery**: Backup codes or admin reset

## Security Headers

### HTTP Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### CORS Configuration
```yaml
allowed_origins: ["https://app.example.com"]
allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allowed_headers: ["Authorization", "Content-Type"]
expose_headers: ["X-Total-Count"]
max_age: 3600
credentials: true
```

## Audit Logging

### Logged Events
All security-relevant events are logged:

| Event Type | Severity | Retention |
|------------|----------|-----------|
| Successful Login | Info | 90 days |
| Failed Login | Warning | 90 days |
| Password Change | Info | 1 year |
| MFA Enable/Disable | Warning | 1 year |
| Account Lockout | Critical | 1 year |
| Privilege Escalation | Critical | 3 years |
| Data Export | Info | 1 year |

### Log Format
```json
{
  "id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "event_type": "login_success",
  "user_id": "user123",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "severity": "info",
  "details": {
    "mfa_used": true,
    "session_id": "sess123"
  }
}
```

## Threat Mitigation

### OWASP Top 10 Protection

| Threat | Mitigation |
|--------|------------|
| A01: Broken Access Control | Role-based access, session validation |
| A02: Cryptographic Failures | Strong encryption, secure protocols |
| A03: Injection | Prepared statements, input validation |
| A04: Insecure Design | Security by design, threat modeling |
| A05: Security Misconfiguration | Secure defaults, hardening guides |
| A06: Vulnerable Components | Dependency scanning, updates |
| A07: Authentication Failures | MFA, rate limiting, account lockout |
| A08: Data Integrity Failures | HMAC validation, secure sessions |
| A09: Security Logging Failures | Comprehensive audit logs |
| A10: SSRF | URL validation, network segmentation |

### Specific Attack Prevention

#### Brute Force Protection
- Rate limiting per IP and account
- Progressive delays
- Account lockout after 5 failures
- CAPTCHA after 3 failures

#### Session Attacks
- Secure, httpOnly, sameSite cookies
- Token rotation on refresh
- Device fingerprinting
- IP validation

#### Password Attacks
- Strong hashing (Bcrypt)
- Salt per password
- Password complexity requirements
- History checking

#### XSS Protection
- Content Security Policy
- Input sanitization
- Output encoding
- Template auto-escaping

#### CSRF Protection
- Double submit cookies
- Custom headers
- SameSite cookies
- Origin validation

## Configuration

### Environment Variables

```bash
# Security Settings
BCRYPT_COST=12
SESSION_TIMEOUT=24h
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=30m
PASSWORD_MIN_LENGTH=12
PASSWORD_HISTORY_COUNT=5

# MFA Settings
MFA_ENABLED=true
MFA_ISSUER="n8n Pro"
MFA_ALGORITHM=SHA256
MFA_BACKUP_CODES=10

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOGIN=5
RATE_LIMIT_REGISTER=3
RATE_LIMIT_WINDOW=15m

# CAPTCHA
RECAPTCHA_ENABLED=true
RECAPTCHA_SITE_KEY=your-site-key
RECAPTCHA_SECRET_KEY=your-secret-key
RECAPTCHA_SCORE_THRESHOLD=0.5

# Session Security
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=strict
SESSION_MAX_AGE=86400

# Headers
HSTS_ENABLED=true
HSTS_MAX_AGE=31536000
CSP_ENABLED=true
CSP_REPORT_URI=/api/csp-report
```

### Database Schema Security

```sql
-- Sensitive data encryption
ALTER TABLE users 
  ALTER COLUMN password_hash SET ENCRYPTED;

-- Row-level security
ALTER TABLE sessions 
  ENABLE ROW LEVEL SECURITY;

-- Audit triggers
CREATE TRIGGER audit_user_changes 
  AFTER INSERT OR UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION audit_changes();
```

## Best Practices

### For Developers

1. **Never Store Plaintext Passwords**
   - Always use bcrypt or argon2
   - Never log passwords
   - Clear from memory after use

2. **Validate All Input**
   ```go
   if err := validator.ValidateEmail(email); err != nil {
       return errors.NewValidationError(err)
   }
   ```

3. **Use Prepared Statements**
   ```go
   db.Where("email = ?", email).First(&user)
   ```

4. **Implement Proper Error Handling**
   - Don't leak sensitive information
   - Log security events
   - Return generic errors to users

5. **Keep Dependencies Updated**
   ```bash
   go get -u ./...
   go mod tidy
   ```

### For System Administrators

1. **Environment Security**
   - Use secret management (Vault, K8s secrets)
   - Rotate credentials regularly
   - Implement network segmentation

2. **Monitoring**
   - Set up alerts for failed logins
   - Monitor rate limit violations
   - Track privilege escalations

3. **Backup and Recovery**
   - Regular database backups
   - Test restore procedures
   - Document recovery processes

4. **Compliance**
   - GDPR: Data protection and privacy
   - SOC 2: Security controls
   - ISO 27001: Information security
   - HIPAA: Healthcare data (if applicable)

### For End Users

1. **Password Guidelines**
   - Use unique passwords
   - Enable password manager
   - Change compromised passwords immediately

2. **MFA Best Practices**
   - Enable MFA on all accounts
   - Store backup codes securely
   - Use authenticator apps over SMS

3. **Session Security**
   - Log out when finished
   - Don't share session links
   - Review active sessions regularly

## Security Incident Response

### Incident Types and Responses

| Incident | Immediate Response | Follow-up |
|----------|-------------------|-----------|
| Brute Force Attack | Auto-block IP, notify user | Review logs, adjust limits |
| Account Compromise | Lock account, force password reset | Audit activity, notify user |
| Data Breach | Disable affected accounts | Full audit, notification |
| MFA Bypass Attempt | Lock account, alert admins | Review MFA implementation |

### Contact Information

- Security Team: security@n8n-pro.com
- Bug Bounty: https://n8n-pro.com/security/bug-bounty
- Status Page: https://status.n8n-pro.com

## Compliance and Certifications

### Standards Compliance
- ✅ OWASP Top 10 (2021)
- ✅ NIST Cybersecurity Framework
- ✅ CIS Controls v8
- ✅ PCI DSS (if processing payments)

### Data Protection
- GDPR compliant (EU)
- CCPA compliant (California)
- PIPEDA compliant (Canada)
- Data residency options available

## Regular Security Tasks

### Daily
- Review security alerts
- Check failed login patterns
- Monitor rate limit violations

### Weekly
- Review audit logs
- Check for unusual patterns
- Update security dashboards

### Monthly
- Security patches
- Dependency updates
- Access reviews
- Password age checks

### Quarterly
- Security assessments
- Penetration testing
- Compliance audits
- Training updates

## Conclusion

The n8n Pro authentication system provides enterprise-grade security through:
- Multiple layers of protection
- Comprehensive audit logging
- Industry-standard encryption
- Proactive threat detection
- Continuous monitoring

Regular updates and security reviews ensure the system remains resilient against evolving threats.