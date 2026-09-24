.PHONY: build test vet fmt tidy up down

build:
	go build -o bin/riskforge ./cmd/riskforge
	go build -o bin/riskforge-agent ./cmd/riskforge-agent
	go build -o bin/riskforge-worker ./cmd/riskforge-worker

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

tidy:
	go mod tidy

up:
	docker compose up -d

down:
	docker compose down
