.PHONY: all build clean server client test fmt lint

# Build output directory
BUILD_DIR := bin

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS := -s -w \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.Version=$(VERSION)' \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.Commit=$(COMMIT)' \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.BuildDate=$(BUILD_DATE)'

# CGO disabled for static binaries
export CGO_ENABLED=0

all: build

build: server client

server:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server ./cmd/server

client:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client ./cmd/client

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test -v -race ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fmt:
	go fmt ./...
	gofmt -s -w .

lint:
	golangci-lint run

vet:
	go vet ./...

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run server
run-server: server
	./$(BUILD_DIR)/holepunch-server

# Run client
run-client: client
	./$(BUILD_DIR)/holepunch-client

# Build for multiple platforms
release:
	@mkdir -p $(BUILD_DIR)/release
	@echo "Building version $(VERSION)..."
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-client-linux-amd64 ./cmd/client
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-client-linux-arm64 ./cmd/client
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-client-darwin-amd64 ./cmd/client
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-client-darwin-arm64 ./cmd/client
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/holepunch-client-windows-amd64.exe ./cmd/client
	@echo "Release binaries in $(BUILD_DIR)/release/"

# Create checksums for release
checksums:
	cd $(BUILD_DIR)/release && sha256sum * > SHA256SUMS
