# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always || echo dev) \
    -X main.commit=$(git rev-parse --short HEAD || echo unknown) \
    -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o certstream-server \
    ./cmd/certstream-server

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 certstream && \
    adduser -u 1000 -G certstream -D certstream

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/certstream-server /app/
COPY --from=builder /app/configs/config.yaml /app/configs/

# Copy frontend files if they exist
COPY --from=builder /app/frontend/dist /app/frontend/dist

# Change ownership
RUN chown -R certstream:certstream /app

# Switch to non-root user
USER certstream

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:4000/stats || exit 1

# Run the application
ENTRYPOINT ["/app/certstream-server"]