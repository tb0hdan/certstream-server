.PHONY: build

# Variables
BINARY_NAME=certstream-server
DOCKER_IMAGE=tb0hdan/certstream-server-go
VERSION=$(shell git describe --tags --always || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD || echo "unknown")
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Default target
all: tools lint test build

build-dir:
	@if [ ! -d "build" ]; then mkdir -p build; fi

# Build the binary
build: build-dir
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o build/${BINARY_NAME} ./cmd/certstream-server

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf build
	@go clean

# Run tests
test: build-dir
	@echo "Running tests..."
	@go test -v -race -cover -coverprofile=build/coverage.out ./...
	@go tool cover -html=build/coverage.out -o build/coverage.html

# Run the application
run: build
	@echo "Running ${BINARY_NAME}..."
	@./build/${BINARY_NAME}

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

tools:
	@echo "Running tools..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v2.2.1
