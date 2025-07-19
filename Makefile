.PHONY: all build clean test run docker-build docker-run lint

# Variables
BINARY_NAME=certstream-server
DOCKER_IMAGE=certstream/certstream-server-go
VERSION=$(shell git describe --tags --always || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD || echo "unknown")
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Default target
all: build

# Build the binary
build:
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/certstream-server

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@go clean

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -cover ./...

# Run the application
run: build
	@echo "Running ${BINARY_NAME}..."
	@./bin/${BINARY_NAME}

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t ${DOCKER_IMAGE}:${VERSION} -t ${DOCKER_IMAGE}:latest .

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	@docker run -p 4000:4000 ${DOCKER_IMAGE}:latest

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Generate mocks (if needed)
mocks:
	@echo "Generating mocks..."
	@go generate ./...

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  make build       - Build the binary"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test        - Run tests"
	@echo "  make run         - Build and run the application"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run  - Run Docker container"
	@echo "  make lint        - Run linter"
	@echo "  make deps        - Install dependencies"
	@echo "  make bench       - Run benchmarks"
	@echo "  make help        - Show this help message"