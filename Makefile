# passcheck — Password strength checking library and CLI tool.

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY   := passcheck
CMD      := ./cmd/passcheck
LDFLAGS  := -ldflags "-s -w -X main.version=$(VERSION)"
BIN_DIR  := bin

# Default target.
.PHONY: all
all: build

# ─── Build ────────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the CLI binary for the current platform.
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD)

.PHONY: install
install: ## Install the CLI binary to $GOPATH/bin.
	go install $(LDFLAGS) $(CMD)

# ─── Cross-compile ────────────────────────────────────────────────────────────

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64


.PHONY: wasm
wasm: wasm ## Build WASM and copy to wasm/web/public/ for the modern web app.
	@mkdir -p wasm/web/public
	@cp $(BIN_DIR)/passcheck.wasm wasm/web/public/ 2>/dev/null || true
	@cp $(BIN_DIR)/wasm_exec.js wasm/web/public/ 2>/dev/null || true
	@echo "  copied WASM files to wasm/web/public/"
	@echo "  Run 'cd wasm/web && npm install && npm run dev' to start the development server"

.PHONY: serve-wasm
serve-wasm: wasm ## Build WASM web app and start Vite dev server (requires Node.js and npm).
	@echo "Starting Vite dev server for wasm/web..."
	@cd wasm/web && npm install && npm run dev

.PHONY: cross
cross: ## Cross-compile for all supported platforms.
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)-$${platform%/*}-$${platform#*/}$$([ "$${platform%/*}" = "windows" ] && echo ".exe") $(CMD) && \
		echo "  built $(BIN_DIR)/$(BINARY)-$${platform%/*}-$${platform#*/}"; \
	done

# ─── Quality ──────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests.
	go test ./... -count=1

.PHONY: cover
cover: ## Run tests with coverage report.
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out
	@rm -f coverage.out

.PHONY: bench
bench: ## Run benchmarks.
	go test . -bench=. -benchmem -count=1 -run='^\z'

.PHONY: validate-lists
validate-lists: ## Validate dictionary lists (no duplicates, sorted, lowercase).
	go generate ./internal/dictionary/...

.PHONY: lint
lint: ## Run go vet.
	go vet ./...

.PHONY: lint-ci
lint-ci: ## Run golangci-lint (install: https://golangci-lint.run/welcome/install/).
	golangci-lint run --timeout=5m

# ─── Maintenance ──────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR) coverage.out

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
