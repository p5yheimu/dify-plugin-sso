# Dify SSO Plugin - Development Makefile

.PHONY: help build run test lint clean docker-build docker-run

# Default target
help:
	@echo "Available targets:"
	@echo "  build       - Build the application"
	@echo "  run         - Run the application in development mode"
	@echo "  test        - Run all tests"
	@echo "  test-cover  - Run tests with coverage report"
	@echo "  lint        - Run linter checks"
	@echo "  clean       - Clean build artifacts"
	@echo "  tidy        - Clean up go.mod and go.sum"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run Docker container"
	@echo "  ci-local    - Run CI checks locally"

# Build the application
build:
	CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/sso-server ./cmd/sso-server

# Run the application
run:
	DATABASE_URL=postgres://postgres:postgres@localhost:5432/dify_sso_dev?sslmode=disable \
	DEBUG=true \
	go run ./cmd/sso-server

# Run tests
test:
	go test -v -race ./...

# Run tests with coverage
test-cover:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter
lint:
	golangci-lint run --config=.golangci.yml

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Tidy dependencies
tidy:
	go mod tidy
	go mod verify

# Build Docker image
docker-build:
	docker build -t dify-sso-plugin .

# Run Docker container
docker-run:
	docker run --rm -d -p 8000:8000 \
		-e DATABASE_URL=sqlite:///dify_sso.db \
		-e DEBUG=true \
		--name dify-sso-dev \
		dify-sso-plugin

# Run CI checks locally (similar to GitHub Actions)
ci-local: tidy lint test
	@echo "✅ All CI checks passed locally!"

# Initialize development environment
dev-setup:
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "✅ Development environment setup complete!" 