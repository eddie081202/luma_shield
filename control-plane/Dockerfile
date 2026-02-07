# LumaShield Control Plane Dockerfile
# Multi-stage build for optimal image size

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -o /app/control-plane \
    ./cmd/server

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 lumashield && \
    adduser -u 1000 -G lumashield -s /bin/sh -D lumashield

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/control-plane /usr/local/bin/control-plane

# Copy any additional files (configs, etc.)
# COPY --from=builder /app/config /app/config

# Set ownership
RUN chown -R lumashield:lumashield /app

# Switch to non-root user
USER lumashield

# Expose ports
EXPOSE 8080 50051

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# Default command
CMD ["control-plane"]
