.PHONY: all build clean test test-race lint vuln ci fmt

# Binary output directory and name (overridable)
BINDIR ?= ./bin
BINARY ?= coder-ssh-gateway

# Version link flags (overridable)
VERSION ?= dev
COMMIT ?= dev
DATE ?= dev
LDFLAGS ?= -X github.com/taxilian/coder-ssh-gateway/internal/version.Version=$(VERSION) \
          -X github.com/taxilian/coder-ssh-gateway/internal/version.Commit=$(COMMIT) \
          -X github.com/taxilian/coder-ssh-gateway/internal/version.Date=$(DATE)

.DEFAULT_GOAL := all

all: build

build:
	mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) ./cmd/coder-ssh-gateway

clean:
	rm -rf $(BINDIR)

test:
	go test ./... -count=1

test-race:
	go test ./... -race -count=1

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

ci: test test-race lint vuln

fmt:
	gofmt -l .
	@if command -v goimports >/dev/null 2>&1; then goimports -l .; fi
