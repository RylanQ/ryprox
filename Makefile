.PHONY: build test lint vuln dev clean help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/rylanq/ryprox/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

help: ## Show this help
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build ./bin/ryprox
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ryprox ./cmd/ryprox

test: ## Run all tests with the race detector
	go test -race -count=1 ./...

lint: ## Run go vet and golangci-lint (if installed)
	go vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed; skipped (CI runs it)"

vuln: ## Scan dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

dev: ## Run RyProx locally on 127.0.0.1:8080
	go run ./cmd/ryprox serve

clean: ## Remove build output
	rm -rf bin
