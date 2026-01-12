# Bifrost Makefile

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/rennerdo30/bifrost-proxy/internal/version.Version=$(VERSION) \
           -X github.com/rennerdo30/bifrost-proxy/internal/version.GitCommit=$(COMMIT) \
           -X github.com/rennerdo30/bifrost-proxy/internal/version.BuildTime=$(BUILD_TIME)

# Directories
BIN_DIR := bin
DIST_DIR := dist

# Build targets
.PHONY: all build build-server build-client clean test test-coverage lint fmt install

all: build

build: web-sync build-server build-client

build-server: web-sync-server
	@echo "Building bifrost-server..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bifrost-server ./cmd/server

build-client: web-sync-client
	@echo "Building bifrost-client..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bifrost-client ./cmd/client

clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
	rm -f coverage.out coverage.html

# Testing
test:
	@echo "Running tests..."
	go test -race -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration:
	@echo "Running integration tests..."
	go test -race -tags=integration -v ./...

# Linting
lint:
	@echo "Running linter..."
	golangci-lint run ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Installation
install: build
	@echo "Installing to GOPATH/bin..."
	cp $(BIN_DIR)/bifrost-server $(GOPATH)/bin/
	cp $(BIN_DIR)/bifrost-client $(GOPATH)/bin/

# Cross-platform builds
.PHONY: build-all build-linux build-darwin build-windows

build-all: web-sync build-linux build-darwin build-windows

build-linux: web-sync
	@echo "Building for Linux..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-client-linux-amd64 ./cmd/client
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-client-linux-arm64 ./cmd/client

build-darwin: web-sync
	@echo "Building for macOS..."
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-client-darwin-amd64 ./cmd/client
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-client-darwin-arm64 ./cmd/client

build-windows: web-sync
	@echo "Building for Windows..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/bifrost-client-windows-amd64.exe ./cmd/client

# Docker
.PHONY: docker-build docker-push docker-deploy docker-up docker-down docker-logs docker-status docker-stop

docker-build: web-sync
	@echo "Building Docker image..."
	docker build -t bifrost-server:$(VERSION) -f docker/Dockerfile .
	docker build -t bifrost-client:$(VERSION) -f docker/Dockerfile.client .

docker-push:
	@echo "Pushing Docker image..."
	docker push bifrost-server:$(VERSION)
	docker push bifrost-client:$(VERSION)

docker-deploy: docker-build
	@echo "Deploying with Docker Compose..."
	docker-compose -f docker/docker-compose.yml -p bifrost up -d

docker-up:
	@echo "Starting Docker Compose services..."
	docker-compose -f docker/docker-compose.yml -p bifrost up -d

docker-down:
	@echo "Stopping Docker Compose services..."
	docker-compose -f docker/docker-compose.yml -p bifrost down

docker-stop:
	@echo "Stopping Docker Compose services (keeping volumes)..."
	docker-compose -f docker/docker-compose.yml -p bifrost stop

docker-logs:
	@docker-compose -f docker/docker-compose.yml -p bifrost logs -f

docker-status:
	@docker-compose -f docker/docker-compose.yml -p bifrost ps

# Web UI - sync static files from source to embedded directories
.PHONY: web-sync web-sync-server web-sync-client web-build

web-sync: web-sync-server web-sync-client

web-sync-server:
	@echo "Syncing server Web UI..."
	@mkdir -p internal/api/server/static
	@cp web/server/src/index.html internal/api/server/static/index.html

web-sync-client:
	@echo "Syncing client Web UI..."
	@mkdir -p internal/api/client/static
	@cp web/client/src/index.html internal/api/client/static/index.html

# Optional: Build web UIs with npm if you add build tools later
web-build:
	@echo "Building Web UIs..."
	@if [ -f web/server/package.json ]; then cd web/server && npm install && npm run build; fi
	@if [ -f web/client/package.json ]; then cd web/client && npm install && npm run build; fi

# Help
.PHONY: help

help:
	@echo "Bifrost Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - Build both server and client (syncs web UI)"
	@echo "  make build-server   - Build server only"
	@echo "  make build-client   - Build client only"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make lint           - Run linter"
	@echo "  make fmt            - Format code"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make build-all      - Cross-platform builds"
	@echo "  make install        - Install to GOPATH/bin"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   - Build Docker images"
	@echo "  make docker-push    - Push Docker images to registry"
	@echo "  make docker-deploy  - Build and deploy with docker-compose"
	@echo "  make docker-up      - Start docker-compose services"
	@echo "  make docker-down    - Stop and remove docker-compose services"
	@echo "  make docker-stop    - Stop services (keep volumes)"
	@echo "  make docker-logs    - Follow docker-compose logs"
	@echo "  make docker-status  - Show docker-compose service status"
	@echo ""
	@echo "Other:"
	@echo "  make web-sync       - Sync web UI files to embedded directories"
	@echo "  make help           - Show this help"
