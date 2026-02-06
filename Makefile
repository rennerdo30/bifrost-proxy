# Bifrost Makefile

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/rennerdo30/bifrost-proxy/internal/version.Version=$(VERSION) \
           -X github.com/rennerdo30/bifrost-proxy/internal/version.GitCommit=$(COMMIT) \
           -X github.com/rennerdo30/bifrost-proxy/internal/version.BuildTime=$(BUILD_TIME)
LDFLAGS_STRIP := -s -w $(LDFLAGS)

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
test: web-sync
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

# OpenWrt / Embedded builds (stripped for smaller size)
.PHONY: build-stripped build-openwrt build-openwrt-all build-openwrt-mips build-openwrt-arm

build-stripped: web-sync
	@echo "Building stripped binaries (30-40% smaller)..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS_STRIP)" -o $(BIN_DIR)/bifrost-server ./cmd/server
	go build -ldflags "$(LDFLAGS_STRIP)" -o $(BIN_DIR)/bifrost-client ./cmd/client

build-openwrt: build-openwrt-all

build-openwrt-all: web-sync
	@echo "Building for OpenWrt (all architectures)..."
	@mkdir -p $(DIST_DIR)
	@$(MAKE) build-openwrt-mips
	@$(MAKE) build-openwrt-arm

build-openwrt-mips: web-sync
	@echo "Building for OpenWrt MIPS..."
	@mkdir -p $(DIST_DIR)
	# MIPS big-endian (many older routers)
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-server-linux-mips ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-client-linux-mips ./cmd/client
	# MIPS little-endian
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-server-linux-mipsle ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-client-linux-mipsle ./cmd/client

build-openwrt-arm: web-sync
	@echo "Building for OpenWrt ARM..."
	@mkdir -p $(DIST_DIR)
	# ARM v6 (older Raspberry Pi, some routers)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-server-linux-arm6 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-client-linux-arm6 ./cmd/client
	# ARM v7 (Raspberry Pi 2+, many modern routers)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-server-linux-arm7 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-client-linux-arm7 ./cmd/client
	# ARM64 (modern high-end routers, Raspberry Pi 3+)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-server-linux-arm64-openwrt ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS_STRIP)" -o $(DIST_DIR)/bifrost-client-linux-arm64-openwrt ./cmd/client

# IPK Packaging for OpenWrt
.PHONY: build-openwrt-ipk

build-openwrt-ipk: build-openwrt-all
	@echo "Creating .ipk packages for all architectures..."
	@mkdir -p $(CURDIR)/$(DIST_DIR)/ipk
	@for arch in mips mipsle arm6 arm7 arm64-openwrt; do \
		echo "Packaging for $$arch..."; \
		TEMP_DIR=$$(mktemp -d); \
		mkdir -p $$TEMP_DIR/control $$TEMP_DIR/data/usr/bin $$TEMP_DIR/data/etc/init.d $$TEMP_DIR/data/etc/bifrost || exit 1; \
		echo "2.0" > $$TEMP_DIR/debian-binary; \
		echo "Package: bifrost-server" > $$TEMP_DIR/control/control; \
		echo "Version: $(VERSION)" >> $$TEMP_DIR/control/control; \
		echo "Architecture: all" >> $$TEMP_DIR/control/control; \
		echo "Maintainer: Bifrost Team" >> $$TEMP_DIR/control/control; \
		echo "Description: Lightweight proxy server with WireGuard and OpenVPN support" >> $$TEMP_DIR/control/control; \
		cp $(CURDIR)/$(DIST_DIR)/bifrost-server-linux-$$arch $$TEMP_DIR/data/usr/bin/bifrost-server || exit 1; \
		cp $(CURDIR)/openwrt/etc/init.d/bifrost $$TEMP_DIR/data/etc/init.d/bifrost || exit 1; \
		cp $(CURDIR)/configs/server-config.openwrt.yaml $$TEMP_DIR/data/etc/bifrost/config.yaml || exit 1; \
		(cd $$TEMP_DIR/control && tar -czf ../control.tar.gz .) || exit 1; \
		(cd $$TEMP_DIR/data && tar -czf ../data.tar.gz .) || exit 1; \
		(cd $$TEMP_DIR && tar -czf $(CURDIR)/$(DIST_DIR)/ipk/bifrost-server_$(VERSION)_$$arch.ipk debian-binary control.tar.gz data.tar.gz) || exit 1; \
		rm -rf $$TEMP_DIR; \
	done

# Docker
.PHONY: docker-build docker-push docker-deploy docker-up docker-down docker-logs docker-status docker-stop docker-rebuild docker-rebuild-clean

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
	docker compose -f docker/docker-compose.yml -p bifrost up -d

docker-up:
	@echo "Starting Docker Compose services..."
	docker compose -f docker/docker-compose.yml -p bifrost up -d

docker-down:
	@echo "Stopping Docker Compose services..."
	docker compose -f docker/docker-compose.yml -p bifrost down

docker-stop:
	@echo "Stopping Docker Compose services (keeping volumes)..."
	docker compose -f docker/docker-compose.yml -p bifrost stop

docker-logs:
	@docker compose -f docker/docker-compose.yml -p bifrost logs -f

docker-status:
	@docker compose -f docker/docker-compose.yml -p bifrost ps

docker-rebuild:
	@echo "Rebuilding and starting Docker Compose services..."
	docker compose -f docker/docker-compose.yml -p bifrost up -d --build

docker-rebuild-clean:
	@echo "Rebuilding (no cache) and starting Docker Compose services..."
	docker compose -f docker/docker-compose.yml -p bifrost build --no-cache
	docker compose -f docker/docker-compose.yml -p bifrost up -d

# Web UI - build and sync static files
.PHONY: web-sync web-sync-server web-sync-client web-build web-install web-dev

web-sync: web-sync-server web-sync-client

web-sync-server: web-build-server
	@echo "Server Web UI built and synced"

web-sync-client: web-build-client
	@echo "Client Web UI built and synced"

# Build server web UI with Vite
web-build-server:
	@echo "Building server Web UI..."
	@cd web/server && npm install && npm run build
	@test -d internal/api/server/static/assets || (echo "ERROR: Server Web UI build failed - no output in internal/api/server/static/assets" && exit 1)

# Build client web UI with Vite
web-build-client:
	@echo "Building client Web UI..."
	@cd web/client && npm install && npm run build
	@test -d internal/api/client/static/assets || (echo "ERROR: Client Web UI build failed - no output in internal/api/client/static/assets" && exit 1)

# Build all web UIs
web-build: web-build-server web-build-client

# Install web dependencies
web-install:
	@echo "Installing web dependencies..."
	@cd web/server && npm install
	@cd web/client && npm install

# Development mode for server UI
web-dev:
	@echo "Starting Vite dev server for server UI..."
	@cd web/server && npm run dev

# Development mode for client UI
web-dev-client:
	@echo "Starting Vite dev server for client UI..."
	@cd web/client && npm run dev

# Desktop (Wails)
.PHONY: desktop-dev desktop-build desktop-build-all desktop-install desktop-check-wails

# Wails binary path (use GOPATH/bin or system wails)
WAILS := $(shell command -v wails 2>/dev/null || echo "$(shell go env GOPATH)/bin/wails")

# Check and install Wails if not present
desktop-check-wails:
	@if [ ! -f "$(WAILS)" ]; then \
		echo "Wails not found, installing..."; \
		go install github.com/wailsapp/wails/v2/cmd/wails@latest; \
	fi

desktop-dev: desktop-check-wails desktop-install
	@echo "Starting Wails dev server..."
	@cd desktop && $(WAILS) dev

desktop-build: desktop-check-wails desktop-install
	@echo "Building desktop app for current platform..."
	@cd desktop && $(WAILS) build

desktop-build-all: desktop-check-wails desktop-install
	@echo "Building desktop app for all platforms..."
	@mkdir -p $(DIST_DIR)
	cd desktop && $(WAILS) build -platform darwin/amd64 -o ../$(DIST_DIR)/bifrost-quick-darwin-amd64
	cd desktop && $(WAILS) build -platform darwin/arm64 -o ../$(DIST_DIR)/bifrost-quick-darwin-arm64
	cd desktop && $(WAILS) build -platform windows/amd64 -o ../$(DIST_DIR)/bifrost-quick-windows-amd64.exe
	cd desktop && $(WAILS) build -platform linux/amd64 -o ../$(DIST_DIR)/bifrost-quick-linux-amd64

desktop-install:
	@echo "Installing Wails frontend dependencies..."
	@cd desktop/frontend && npm install

# Mobile (React Native / Expo)
.PHONY: mobile-install mobile-dev mobile-ios mobile-android mobile-build-ios mobile-build-android

mobile-install:
	@echo "Installing mobile dependencies..."
	@cd mobile && npm install

mobile-dev:
	@echo "Starting Expo development server..."
	@cd mobile && npx expo start

mobile-ios:
	@echo "Starting iOS simulator..."
	@cd mobile && npx expo run:ios

mobile-android:
	@echo "Starting Android emulator..."
	@cd mobile && npx expo run:android

mobile-build-ios:
	@echo "Building iOS app..."
	@cd mobile && npx expo prebuild --platform ios
	@echo "Open mobile/ios/BifrostVPN.xcworkspace in Xcode to build"

mobile-build-android:
	@echo "Building Android app..."
	@cd mobile && npx expo prebuild --platform android
	@cd mobile/android && ./gradlew assembleRelease
	@echo "APK available at mobile/android/app/build/outputs/apk/release/"

# Documentation
.PHONY: docs docs-serve docs-build

docs-serve:
	@echo "Starting documentation server..."
	@pip install mkdocs-material mkdocs-minify-plugin -q 2>/dev/null || pip install mkdocs-material mkdocs-minify-plugin
	@mkdocs serve

docs-build:
	@echo "Building documentation..."
	@pip install mkdocs-material mkdocs-minify-plugin -q 2>/dev/null || pip install mkdocs-material mkdocs-minify-plugin
	@mkdocs build --strict

docs: docs-serve

# Help
.PHONY: help

help:
	@echo "Bifrost Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - Build both server and client (syncs web UI)"
	@echo "  make build-server   - Build server only"
	@echo "  make build-client   - Build client only"
	@echo "  make build-stripped - Build stripped binaries (30-40% smaller)"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make lint           - Run linter"
	@echo "  make fmt            - Format code"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make build-all      - Cross-platform builds"
	@echo "  make install        - Install to GOPATH/bin"
	@echo ""
	@echo "OpenWrt/Embedded:"
	@echo "  make build-openwrt       - Build for all OpenWrt architectures"
	@echo "  make build-openwrt-mips  - Build for MIPS (big/little endian)"
	@echo "  make build-openwrt-arm   - Build for ARM (v6, v7, arm64)"
	@echo ""
	@echo "Desktop (Wails):"
	@echo "  make desktop-dev        - Start Wails dev server"
	@echo "  make desktop-build      - Build for current platform"
	@echo "  make desktop-build-all  - Build for all platforms"
	@echo "  make desktop-install    - Install frontend dependencies"
	@echo ""
	@echo "Mobile (React Native):"
	@echo "  make mobile-install     - Install dependencies"
	@echo "  make mobile-dev         - Start Expo dev server"
	@echo "  make mobile-ios         - Run on iOS simulator"
	@echo "  make mobile-android     - Run on Android emulator"
	@echo "  make mobile-build-ios   - Build iOS app"
	@echo "  make mobile-build-android - Build Android APK"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build         - Build Docker images"
	@echo "  make docker-push          - Push Docker images to registry"
	@echo "  make docker-deploy        - Build and deploy with Docker Compose"
	@echo "  make docker-up            - Start Docker Compose services"
	@echo "  make docker-down          - Stop and remove Docker Compose services"
	@echo "  make docker-stop          - Stop services (keep volumes)"
	@echo "  make docker-logs          - Follow Docker Compose logs"
	@echo "  make docker-status        - Show Docker Compose service status"
	@echo "  make docker-rebuild       - Rebuild and start services (--build)"
	@echo "  make docker-rebuild-clean - Rebuild without cache and start"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs           - Start local docs server (alias for docs-serve)"
	@echo "  make docs-serve     - Start MkDocs development server"
	@echo "  make docs-build     - Build static documentation site"
	@echo ""
	@echo "Other:"
	@echo "  make web-sync       - Sync web UI files to embedded directories"
	@echo "  make help           - Show this help"
