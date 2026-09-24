.PHONY: build test test-integration vet fmt tidy migrate-up migrate-down up down

build:
	go build -o bin/riskforge ./cmd/riskforge
	go build -o bin/riskforge-agent ./cmd/riskforge-agent
	go build -o bin/riskforge-worker ./cmd/riskforge-worker

test:
	go test ./...

# Integration tests (internal/infrastructure/postgres) start a real
# PostgreSQL container via testcontainers-go (AGENTS.md §25A.6) and
# require Docker.
test-integration:
	go test -tags=integration ./... -timeout 300s

vet:
	go vet ./...

fmt:
	gofmt -l .

# -tags=integration is required here so go.mod/go.sum keep the
# testcontainers-go dependencies that only internal/infrastructure/postgres's
# //go:build integration test file imports; `go mod tidy` alone does not
# see build-tag-gated files and would drop them.
tidy:
	GOFLAGS=-tags=integration go mod tidy

migrate-up:
	migrate -database "$${RISKFORGE_DATABASE_URL}" -path migrations up

migrate-down:
	migrate -database "$${RISKFORGE_DATABASE_URL}" -path migrations down

up:
	docker compose up -d

down:
	docker compose down
