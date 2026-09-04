.PHONY: test test-race lint vuln ci fmt

test:
	go test ./... -count=1

test-race:
	go test ./... -race -count=1

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

ci: test test-race lint vuln

fmt:
	gofmt -l .
	@which goimports >/dev/null 2>&1 && goimports -l . || true
