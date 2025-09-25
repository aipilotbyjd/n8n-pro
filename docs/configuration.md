# Configuration Guide

This guide covers all configuration options for n8n Pro. The application uses environment variables for configuration, allowing for flexible deployment across different environments.

## Environment Variables

### Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Application environment (`development`, `staging`, `production`) |
| `DEBUG` | `false` | Enable debug logging |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | API server bind address |
| `API_PORT` | `8080` | API server port |
| `API_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `API_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `API_IDLE_TIMEOUT` | `60s` | HTTP idle timeout |
| `API_ENABLE_CORS` | `false` | Enable CORS |
| `API_CORS_ALLOWED_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `API_CORS_ALLOWED_METHODS` | `GET,POST,PUT,DELETE,OPTIONS` | Allowed CORS methods |
| `API_CORS_ALLOWED_HEADERS` | `*` | Allowed CORS headers |
| `API_ENABLE_GZIP` | `true` | Enable gzip compression |
| `API_ENABLE_RATE_LIMIT` | `true` | Enable API rate limiting |
| `API_RATE_LIMIT_REQUESTS` | `1000` | Rate limit requests per hour |
| `API_RATE_LIMIT_BURST` | `100` | Rate limit burst capacity |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `n8n_pro` | Database name |
| `DB_USER` | `postgres` | Database username |
| `DB_PASSWORD` | - | Database password |
| `DB_SSL_MODE` | `disable` | SSL mode (`disable`, `require`, `verify-ca`, `verify-full`) |
| `DB_MAX_OPEN_CONNECTIONS` | `25` | Maximum open connections |
| `DB_MAX_IDLE_CONNECTIONS` | `5` | Maximum idle connections |
| `DB_CONNECTION_MAX_LIFETIME` | `1h` | Connection maximum lifetime |
| `DB_ENABLE_LOGGING` | `false` | Enable query logging |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | - | Redis password |
| `REDIS_DATABASE` | `0` | Redis database number |
| `REDIS_MAX_RETRIES` | `3` | Maximum retry attempts |
| `REDIS_RETRY_DELAY` | `1s` | Retry delay |
| `REDIS_POOL_SIZE` | `10` | Connection pool size |
| `REDIS_MIN_IDLE_CONNECTIONS` | `2` | Minimum idle connections |
| `REDIS_DIAL_TIMEOUT` | `5s` | Connection timeout |
| `REDIS_READ_TIMEOUT` | `3s` | Read timeout |
| `REDIS_WRITE_TIMEOUT` | `3s` | Write timeout |

### Kafka Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka brokers (comma-separated) |
| `KAFKA_TOPIC` | `n8n-workflows` | Default Kafka topic |
| `KAFKA_GROUP_ID` | `n8n-workers` | Consumer group ID |
| `KAFKA_CLIENT_ID` | `n8n-pro` | Kafka client ID |
| `KAFKA_ENABLE_SASL` | `false` | Enable SASL authentication |
| `KAFKA_SASL_MECHANISM` | `PLAIN` | SASL mechanism |
| `KAFKA_SASL_USERNAME` | - | SASL username |
| `KAFKA_SASL_PASSWORD` | - | SASL password |
| `KAFKA_ENABLE_TLS` | `false` | Enable TLS |
| `KAFKA_TLS_SKIP_VERIFY` | `false` | Skip TLS certificate verification |
| `KAFKA_CONSUMER_TIMEOUT` | `30s` | Consumer timeout |
| `KAFKA_PRODUCER_TIMEOUT` | `30s` | Producer timeout |
| `KAFKA_PRODUCER_RETRY_MAX` | `3` | Producer max retries |

### Authentication Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | - | JWT signing secret (required) |
| `JWT_EXPIRATION` | `24h` | JWT access token expiration |
| `REFRESH_TOKEN_EXPIRATION` | `168h` | Refresh token expiration (7 days) |
| `PASSWORD_MIN_LENGTH` | `8` | Minimum password length |
| `PASSWORD_REQUIRE_SYMBOLS` | `true` | Require symbols in password |
| `PASSWORD_REQUIRE_NUMBERS` | `true` | Require numbers in password |
| `PASSWORD_REQUIRE_UPPER` | `true` | Require uppercase letters |
| `PASSWORD_REQUIRE_LOWER` | `true` | Require lowercase letters |
| `MAX_LOGIN_ATTEMPTS` | `5` | Maximum login attempts |
| `LOGIN_ATTEMPT_WINDOW` | `15m` | Login attempt window |
| `ENABLE_MFA` | `false` | Enable multi-factor authentication |
| `MFA_ISSUER` | `n8n-pro` | MFA issuer name |

#### OAuth Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_OAUTH` | `false` | Enable OAuth authentication |
| `OAUTH_PROVIDERS` | - | Enabled OAuth providers (comma-separated) |
| `GOOGLE_OAUTH_CLIENT_ID` | - | Google OAuth client ID |
| `GOOGLE_OAUTH_CLIENT_SECRET` | - | Google OAuth client secret |
| `GOOGLE_OAUTH_REDIRECT_URL` | - | Google OAuth redirect URL |
| `GITHUB_OAUTH_CLIENT_ID` | - | GitHub OAuth client ID |
| `GITHUB_OAUTH_CLIENT_SECRET` | - | GitHub OAuth client secret |
| `GITHUB_OAUTH_REDIRECT_URL` | - | GitHub OAuth redirect URL |

#### Session Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_COOKIE_NAME` | `n8n_session` | Session cookie name |
| `SESSION_COOKIE_DOMAIN` | - | Session cookie domain |
| `SESSION_COOKIE_SECURE` | `false` | Secure session cookies |
| `SESSION_COOKIE_HTTP_ONLY` | `true` | HTTP-only session cookies |

### Webhook Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_HOST` | `0.0.0.0` | Webhook server bind address |
| `WEBHOOK_PORT` | `8081` | Webhook server port |
| `WEBHOOK_PATH` | `/webhook` | Webhook base path |
| `WEBHOOK_MAX_PAYLOAD_SIZE` | `10485760` | Maximum payload size (10MB) |
| `WEBHOOK_TIMEOUT` | `30s` | Webhook timeout |
| `WEBHOOK_ENABLE_SIGNATURE_VERIFY` | `true` | Enable signature verification |
| `WEBHOOK_SIGNATURE_HEADER` | `X-Signature` | Signature header name |
| `WEBHOOK_SIGNATURE_ALGORITHM` | `sha256` | Signature algorithm |
| `WEBHOOK_SIGNATURE_SECRET` | - | Signature secret |
| `WEBHOOK_RETRY_ATTEMPTS` | `3` | Retry attempts for failed webhooks |
| `WEBHOOK_RETRY_DELAY` | `1s` | Retry delay |
| `WEBHOOK_ENABLE_LOGGING` | `true` | Enable webhook logging |
| `WEBHOOK_ALLOWED_HOSTS` | - | Allowed webhook hosts (comma-separated) |
| `WEBHOOK_BLOCKED_HOSTS` | `localhost,127.0.0.1,0.0.0.0` | Blocked webhook hosts |
| `WEBHOOK_ENABLE_RATE_LIMIT` | `true` | Enable webhook rate limiting |
| `WEBHOOK_RATE_LIMIT_REQUESTS` | `100` | Rate limit requests per minute |
| `WEBHOOK_RATE_LIMIT_WINDOW` | `1m` | Rate limit window |

### Scheduler Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_ENABLED` | `true` | Enable scheduler service |
| `SCHEDULER_CHECK_INTERVAL` | `30s` | Job check interval |
| `SCHEDULER_MAX_CONCURRENT_JOBS` | `10` | Maximum concurrent jobs |
| `SCHEDULER_JOB_TIMEOUT` | `5m` | Individual job timeout |
| `SCHEDULER_ENABLE_DISTRIBUTED_MODE` | `false` | Enable distributed scheduling |
| `SCHEDULER_LOCK_TIMEOUT` | `10m` | Distributed lock timeout |
| `SCHEDULER_LOCK_REFRESH_INTERVAL` | `30s` | Lock refresh interval |
| `SCHEDULER_CLEANUP_INTERVAL` | `1h` | Cleanup job interval |
| `SCHEDULER_RETAIN_COMPLETED_JOBS` | `24h` | Retain completed jobs duration |
| `SCHEDULER_RETAIN_FAILED_JOBS` | `168h` | Retain failed jobs duration (7 days) |

### Worker Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_ENABLED` | `true` | Enable worker service |
| `WORKER_CONCURRENCY` | `10` | Worker concurrency level |
| `WORKER_QUEUE_NAME` | `workflow-jobs` | Worker queue name |
| `WORKER_POLL_INTERVAL` | `5s` | Job polling interval |
| `WORKER_JOB_TIMEOUT` | `10m` | Job execution timeout |
| `WORKER_RETRY_ATTEMPTS` | `3` | Job retry attempts |
| `WORKER_RETRY_DELAY` | `30s` | Retry delay |
| `WORKER_ENABLE_HEALTH_CHECK` | `true` | Enable health check endpoint |
| `WORKER_HEALTH_CHECK_PORT` | `8082` | Health check port |
| `WORKER_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown timeout |

### Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_KEY` | - | Data encryption key (32 characters) |
| `HASH_COST` | `12` | BCrypt hash cost |
| `SECURITY_ALLOWED_ORIGINS` | - | Allowed origins for CORS |
| `SECURITY_TRUSTED_PROXIES` | - | Trusted proxy addresses |
| `SECURITY_ENABLE_CSRF` | `true` | Enable CSRF protection |
| `SECURITY_CSRF_TOKEN_LENGTH` | `32` | CSRF token length |
| `SECURITY_ENABLE_CONTENT_SECURITY` | `true` | Enable content security policy |
| `SECURITY_CONTENT_SECURITY_POLICY` | `default-src 'self'` | Content security policy |
| `SECURITY_ENABLE_HSTS` | `false` | Enable HSTS headers |
| `SECURITY_HSTS_MAX_AGE` | `31536000` | HSTS max age (1 year) |
| `SECURITY_ENABLE_X_FRAME_OPTIONS` | `true` | Enable X-Frame-Options |
| `SECURITY_X_FRAME_OPTIONS` | `DENY` | X-Frame-Options value |
| `SECURITY_ENABLE_X_CONTENT_TYPE` | `true` | Enable X-Content-Type-Options |
| `SECURITY_ENABLE_XSS_PROTECTION` | `true` | Enable XSS protection |
| `SECURITY_ENABLE_CLICKJACKING` | `true` | Enable clickjacking protection |

### Metrics Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLED` | `true` | Enable metrics collection |
| `METRICS_HOST` | `0.0.0.0` | Metrics server bind address |
| `METRICS_PORT` | `9090` | Metrics server port |
| `METRICS_PATH` | `/metrics` | Metrics endpoint path |
| `METRICS_NAMESPACE` | `n8n_pro` | Metrics namespace |
| `METRICS_SUBSYSTEM` | - | Metrics subsystem |
| `METRICS_SERVICE_NAME` | `api` | Service name for metrics |

### Storage Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_PROVIDER` | `local` | Storage provider (`local`, `s3`) |
| `STORAGE_LOCAL_PATH` | `./storage` | Local storage path |
| `STORAGE_MAX_FILE_SIZE` | `104857600` | Maximum file size (100MB) |
| `STORAGE_ALLOWED_MIME_TYPES` | `application/json,text/plain,image/*` | Allowed MIME types |
| `STORAGE_ENABLE_ENCRYPTION` | `false` | Enable file encryption |
| `STORAGE_ENCRYPTION_KEY` | - | File encryption key |
| `STORAGE_CDN_ENABLED` | `false` | Enable CDN integration |
| `STORAGE_CDN_BASE_URL` | - | CDN base URL |

#### S3 Storage Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_ENDPOINT` | - | S3 endpoint URL |
| `S3_REGION` | `us-east-1` | S3 region |
| `S3_BUCKET` | - | S3 bucket name |
| `S3_ACCESS_KEY_ID` | - | S3 access key ID |
| `S3_SECRET_ACCESS_KEY` | - | S3 secret access key |
| `S3_USE_SSL` | `true` | Use SSL for S3 connections |
| `S3_PATH_STYLE` | `false` | Use path-style S3 URLs |

### Email Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `EMAIL_PROVIDER` | `smtp` | Email provider (`smtp`, `sendgrid`) |
| `EMAIL_FROM_EMAIL` | `noreply@example.com` | Default from email |
| `EMAIL_FROM_NAME` | `n8n Pro` | Default from name |
| `EMAIL_REPLY_TO_EMAIL` | - | Reply-to email address |
| `EMAIL_TEMPLATES_PATH` | `./templates/email` | Email templates path |
| `EMAIL_ENABLE_RETRIES` | `true` | Enable email retries |
| `EMAIL_MAX_RETRIES` | `3` | Maximum email retries |
| `EMAIL_RETRY_DELAY` | `5s` | Email retry delay |

#### SMTP Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `localhost` | SMTP server host |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | - | SMTP username |
| `SMTP_PASSWORD` | - | SMTP password |
| `SMTP_USE_TLS` | `true` | Use TLS for SMTP |
| `SMTP_USE_SSL` | `false` | Use SSL for SMTP |

#### SendGrid Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDGRID_API_KEY` | - | SendGrid API key |

### Sandbox Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDBOX_ENABLED` | `true` | Enable code sandbox |
| `SANDBOX_DEFAULT_CONTEXT` | `javascript` | Default execution context |
| `SANDBOX_MAX_CONCURRENT_JOBS` | `5` | Maximum concurrent sandbox jobs |
| `SANDBOX_JOB_TIMEOUT` | `5m` | Sandbox job timeout |
| `SANDBOX_MAX_MEMORY_MB` | `128` | Maximum memory per job (MB) |
| `SANDBOX_MAX_CPU_PERCENT` | `50` | Maximum CPU usage percent |
| `SANDBOX_MAX_DISK_MB` | `10` | Maximum disk usage (MB) |
| `SANDBOX_ENABLE_NODEJS` | `true` | Enable Node.js execution |
| `SANDBOX_ENABLE_PYTHON` | `true` | Enable Python execution |
| `SANDBOX_ENABLE_DOCKER` | `false` | Enable Docker sandbox |
| `SANDBOX_WORKING_DIRECTORY` | `/tmp/n8n-sandbox` | Sandbox working directory |
| `SANDBOX_ALLOWED_PACKAGES` | `lodash,axios,moment` | Allowed npm packages |
| `SANDBOX_BLOCKED_PACKAGES` | `fs,child_process` | Blocked packages |
| `SANDBOX_NETWORK_POLICY` | `restricted` | Network access policy |
| `SANDBOX_ALLOWED_DOMAINS` | - | Allowed domains for network access |
| `SANDBOX_BLOCKED_DOMAINS` | `localhost,127.0.0.1` | Blocked domains |

### Limits Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LIMITS_MAX_WORKFLOWS_PER_TEAM` | `100` | Maximum workflows per team |
| `LIMITS_MAX_NODES_PER_WORKFLOW` | `50` | Maximum nodes per workflow |
| `LIMITS_MAX_EXECUTIONS_PER_MINUTE` | `60` | Maximum executions per minute |
| `LIMITS_MAX_EXECUTION_TIME` | `10m` | Maximum workflow execution time |
| `LIMITS_MAX_PAYLOAD_SIZE` | `52428800` | Maximum payload size (50MB) |
| `LIMITS_MAX_CONCURRENT_EXECUTIONS` | `10` | Maximum concurrent executions |
| `LIMITS_MAX_WEBHOOKS_PER_WORKFLOW` | `5` | Maximum webhooks per workflow |
| `LIMITS_MAX_TRIGGERS_PER_WORKFLOW` | `5` | Maximum triggers per workflow |
| `LIMITS_MAX_FILE_UPLOAD_SIZE` | `104857600` | Maximum file upload size (100MB) |
| `LIMITS_MAX_STORAGE_PER_TEAM` | `10737418240` | Maximum storage per team (10GB) |
| `LIMITS_MAX_USERS_PER_TEAM` | `25` | Maximum users per team |
| `LIMITS_MAX_TEAMS_PER_USER` | `5` | Maximum teams per user |

## Configuration Files

### Environment File (.env)

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env

# Edit with your settings
vim .env
```

Example `.env` file:

```bash
# Application
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=info

# API
API_HOST=0.0.0.0
API_PORT=8080
API_ENABLE_CORS=true

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=n8n_user
DB_PASSWORD=secure_db_password
DB_SSL_MODE=require

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=secure_redis_password

# Kafka
KAFKA_BROKERS=localhost:9092
KAFKA_TOPIC=n8n-workflows
KAFKA_GROUP_ID=n8n-workers

# Security
JWT_SECRET=your-super-secret-jwt-signing-key-change-in-production
ENCRYPTION_KEY=your-32-character-encryption-key

# Features
SCHEDULER_ENABLED=true
WORKER_ENABLED=true
METRICS_ENABLED=true
```

### Docker Environment

For Docker deployments, create a `.env.docker` file:

```bash
# Database (Docker)
DB_HOST=postgres
DB_PORT=5432
DB_NAME=n8n_clone
DB_USER=user
DB_PASSWORD=password
DB_SSL_MODE=disable

# Redis (Docker)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_password

# Kafka (Docker)
KAFKA_BROKERS=kafka:9092
```

### Kubernetes Configuration

For Kubernetes deployments, use ConfigMaps and Secrets:

```yaml
# config-map.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: n8n-pro-config
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "info"
  DB_HOST: "postgres-service"
  DB_PORT: "5432"
  DB_NAME: "n8n_pro"
  REDIS_HOST: "redis-service"
  REDIS_PORT: "6379"
  KAFKA_BROKERS: "kafka-service:9092"
---
apiVersion: v1
kind: Secret
metadata:
  name: n8n-pro-secrets
type: Opaque
stringData:
  DB_PASSWORD: "your-db-password"
  JWT_SECRET: "your-jwt-secret"
  ENCRYPTION_KEY: "your-encryption-key"
  REDIS_PASSWORD: "your-redis-password"
```

## Environment-Specific Configuration

### Development

```bash
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=debug
API_ENABLE_CORS=true
METRICS_ENABLED=true
SCHEDULER_CHECK_INTERVAL=10s
```

### Staging

```bash
ENVIRONMENT=staging
DEBUG=false
LOG_LEVEL=info
API_ENABLE_CORS=true
SECURITY_ENABLE_HSTS=false
DB_SSL_MODE=prefer
```

### Production

```bash
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=warn
API_ENABLE_CORS=false
SECURITY_ENABLE_HSTS=true
SECURITY_ENABLE_CSRF=true
DB_SSL_MODE=require
SESSION_COOKIE_SECURE=true
```

## Configuration Validation

The application validates configuration on startup. Required variables:

- `JWT_SECRET` - Must be set and non-empty
- `ENCRYPTION_KEY` - Must be 32 characters long
- Database connection parameters
- Redis connection parameters (if enabled)
- Kafka connection parameters (if enabled)

## Configuration Best Practices

### Security
1. **Never commit secrets** to version control
2. **Use strong passwords** and keys (32+ characters)
3. **Enable TLS/SSL** in production
4. **Restrict CORS origins** in production
5. **Use environment-specific configurations**

### Performance
1. **Tune connection pools** based on load
2. **Set appropriate timeouts** for your use case
3. **Configure resource limits** to prevent abuse
4. **Enable compression** for API responses
5. **Use Redis clustering** for high availability

### Monitoring
1. **Enable metrics collection**
2. **Configure proper log levels**
3. **Set up health checks**
4. **Monitor resource usage**
5. **Set up alerts** for critical metrics

### Scaling
1. **Use distributed scheduling** for multiple instances
2. **Configure Kafka partitioning** for parallel processing
3. **Scale workers** based on queue depth
4. **Use database read replicas** for read-heavy workloads
5. **Implement proper load balancing**

## Troubleshooting Configuration

### Common Issues

1. **Database Connection Failed**
   - Check `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`
   - Verify network connectivity
   - Check SSL mode requirements

2. **JWT Token Issues**
   - Ensure `JWT_SECRET` is set and consistent across instances
   - Check token expiration settings
   - Verify token format and claims

3. **Redis Connection Issues**
   - Check `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
   - Verify Redis is running and accessible
   - Check authentication requirements

4. **Kafka Connection Issues**
   - Verify `KAFKA_BROKERS` are reachable
   - Check topic existence and permissions
   - Verify consumer group configuration

5. **Performance Issues**
   - Review connection pool settings
   - Check timeout configurations
   - Monitor resource usage and limits

### Validation Tools

```bash
# Check configuration
make config-check

# Validate database connection
make db-ping

# Test Redis connection
make redis-ping

# Verify Kafka connectivity
make kafka-ping
```