# Bifrost Server Dockerfile

# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux make build-server

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
