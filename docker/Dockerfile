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

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X github.com/rennerdo30/bifrost-proxy/internal/version.Version=docker -X github.com/rennerdo30/bifrost-proxy/internal/version.GitCommit=docker -X github.com/rennerdo30/bifrost-proxy/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/bifrost-server ./cmd/server

# Runtime stage
FROM alpine:3.21

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary
COPY --from=builder /app/bin/bifrost-server /app/bifrost-server

# Copy default config
COPY configs/server-config.example.yaml /app/config.yaml

# Create non-root user
RUN adduser -D -H -s /sbin/nologin bifrost
USER bifrost

# Expose ports
EXPOSE 8080 1080 9090 8081

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/metrics || exit 1

# Default command
ENTRYPOINT ["/app/bifrost-server"]
CMD ["-c", "/app/config.yaml"]
