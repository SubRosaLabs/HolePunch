.PHONY: all build clean server client test fmt lint release checksums check-release-tools dry-run-release publish-release

# Build output directory
BUILD_DIR := bin
RELEASE_DIR := $(BUILD_DIR)/release
GO ?= go
GARBLE ?= garble
PYTHON ?= python3
GARBLE_VERSION := v0.14.2
RELEASE_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
RELEASE_DATE := $(shell git show -s --format=%cI HEAD 2>/dev/null || echo "unknown")

# Go build flags; releases use the commit date for repeatable metadata.
LDFLAGS_VERSION := -X 'github.com/abb3rrant/HolePunch/pkg/config.Version=$(VERSION)' \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.Commit=$(COMMIT)'
LDFLAGS := -s -w $(LDFLAGS_VERSION) \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.BuildDate=$(BUILD_DATE)'
RELEASE_LDFLAGS := -s -w $(LDFLAGS_VERSION) \
	-X 'github.com/abb3rrant/HolePunch/pkg/config.BuildDate=$(RELEASE_DATE)'

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

# Release builds are separate from the normal, debuggable "make build" artifacts.
# Pin Garble to the last release supporting Go 1.24; -tiny is intentionally
# omitted so panic diagnostics remain available to OSS users.
check-release-tools:
	@command -v $(GARBLE) >/dev/null || { echo "Install Garble: go install mvdan.cc/garble@$(GARBLE_VERSION)" >&2; exit 1; }
	@case "$$($(GARBLE) version)" in *"mvdan.cc/garble $(GARBLE_VERSION)"*) ;; *) echo "Garble $(GARBLE_VERSION) required" >&2; exit 1;; esac
	@case "$$($(GO) version)" in *"go1.24."*) ;; *) echo "Go 1.24.x required for Garble $(GARBLE_VERSION)" >&2; exit 1;; esac
	@command -v $(PYTHON) >/dev/null || { echo "python3 is required for release verification" >&2; exit 1; }

release: check-release-tools
	@rm -rf -- $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	@set -eu; for target in $(RELEASE_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		for role in server client; do \
			out="$(RELEASE_DIR)/holepunch-$$role-$$os-$$arch$$ext"; \
			printf 'Building %s\n' "$$out"; \
			GOOS=$$os GOARCH=$$arch $(GARBLE) -literals build -trimpath -ldflags "$(RELEASE_LDFLAGS)" -o "$$out" "./cmd/$$role"; \
		done; \
	done
	@$(PYTHON) scripts/verify_release.py $(RELEASE_DIR)

# Revalidate the complete release set and regenerate SHA256SUMS.
checksums:
	@$(PYTHON) scripts/verify_release.py $(RELEASE_DIR)

# Publication is explicit, never part of "make release". Require a tag already
# present on GitHub and matching the local HEAD, plus human-written notes.
dry-run-release: checksums
	@test -n "$(TAG)" && test -n "$(NOTES_FILE)" || { echo "usage: make dry-run-release TAG=vX.Y.Z NOTES_FILE=path" >&2; exit 2; }
	@$(PYTHON) scripts/publish_release.py "$(TAG)" --notes-file "$(NOTES_FILE)" --directory $(RELEASE_DIR)

publish-release: checksums
	@test -n "$(TAG)" && test -n "$(NOTES_FILE)" || { echo "usage: make publish-release TAG=vX.Y.Z NOTES_FILE=path" >&2; exit 2; }
	@$(PYTHON) scripts/publish_release.py "$(TAG)" --notes-file "$(NOTES_FILE)" --directory $(RELEASE_DIR) --publish
