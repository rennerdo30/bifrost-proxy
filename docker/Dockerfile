# Bifrost Server Dockerfile

# Web UI build stage
FROM node:20-alpine AS web-builder

WORKDIR /app

# Copy package files and install dependencies
COPY web/server/package*.json ./web/server/
RUN cd web/server && npm ci

# Copy web source
COPY web/server/ ./web/server/

# Create output directory and build (Vite outputs to ../../internal/api/server/static)
RUN mkdir -p internal/api/server/static
RUN cd web/server && npm run build

# Go build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Copy built web UI from web-builder stage
COPY --from=web-builder /app/internal/api/server/static/ /app/internal/api/server/static/

# Build args for version info (defaults used when not passed)
ARG VERSION=docker
ARG COMMIT=docker

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X github.com/rennerdo30/bifrost-proxy/internal/version.Version=${VERSION} -X github.com/rennerdo30/bifrost-proxy/internal/version.GitCommit=${COMMIT} -X github.com/rennerdo30/bifrost-proxy/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/bifrost-server ./cmd/server

# Runtime stage
FROM alpine:3.21

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary
COPY --from=builder /app/bin/bifrost-server /app/bifrost-server

# Create non-root user and data directory
RUN adduser -D -H -s /sbin/nologin -u 1000 bifrost && \
    mkdir -p /app/data /var/log/bifrost && \
    chown -R bifrost:bifrost /app/data /var/log/bifrost

# Copy default config to data directory (owned by bifrost)
COPY --chown=bifrost:bifrost configs/server-config.example.yaml /app/data/config.yaml

USER bifrost

# Expose ports
EXPOSE 7080 7180 7090 7081

# Health check (use 127.0.0.1 to avoid IPv6 resolution issues)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:7090/api/v1/health || exit 1

# Default command - use config from data directory
ENTRYPOINT ["/app/bifrost-server"]
CMD ["-c", "/app/data/config.yaml"]
