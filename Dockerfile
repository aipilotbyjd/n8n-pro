# Multi-stage Docker build for n8n-pro
# Stage 1: Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata make curl

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o n8n-pro \
    ./cmd/api

# Stage 2: Security scan stage (optional)
FROM aquasec/trivy:latest AS security

# Copy the binary for security scanning
COPY --from=builder /app/n8n-pro /tmp/n8n-pro

# Run security scan
RUN trivy fs --exit-code 1 --no-progress --severity HIGH,CRITICAL /tmp/

# Stage 3: Final production stage
FROM scratch

# Import ca-certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/n8n-pro /n8n-pro

# Copy configuration files
COPY --from=builder /app/configs /configs

# Create non-root user (numeric for security)
USER 65534:65534

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/n8n-pro", "health"]

# Expose ports
EXPOSE 8080 9090

# Labels for better maintainability
LABEL org.opencontainers.image.title="n8n-pro"
LABEL org.opencontainers.image.description="Production-ready n8n workflow automation platform"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
LABEL org.opencontainers.image.source="https://github.com/n8n-io/n8n-pro"
LABEL org.opencontainers.image.licenses="PROPRIETARY"

# Default command
ENTRYPOINT ["/n8n-pro"]
CMD ["serve"]