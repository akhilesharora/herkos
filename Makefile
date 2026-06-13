# Herkos - local-first context + egress broker for AI coding agents.
GOLANGCI := $(shell go env GOPATH)/bin/golangci-lint

.PHONY: build test race vet lint fmt check demo verify-clean
build: ; go build ./...
test:  ; go test ./... -count=1
race:  ; go test ./... -race -count=1
vet:   ; go vet ./...
lint:  ; $(GOLANGCI) run ./...
fmt:   ; gofmt -w .
demo:  ; go run ./cmd/herkos-demo
check: build vet race lint

# verify-clean builds + tests the COMMITTED tree (HEAD) from a throwaway worktree, never the
# dirty working tree, so a non-compiling HEAD is caught even when an uncommitted file in the
# working tree would otherwise mask it.
verify-clean:
	@set -e; \
	wt=$$(mktemp -d); \
	git worktree add -q --detach "$$wt" HEAD; \
	echo "verify-clean: HEAD $$(git -C "$$wt" rev-parse --short HEAD) in $$wt"; \
	( cd "$$wt" && go build ./... && go vet ./... && go test ./... -race -count=1 ); \
	status=$$?; \
	git worktree remove --force "$$wt"; \
	exit $$status
