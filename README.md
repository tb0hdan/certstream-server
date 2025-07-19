# Certstream Server - Go Implementation

This is a Go port of the [CaliDog Certstream server](https://github.com/CaliDog/certstream-server), which aggregates certificate data from Certificate Transparency logs and provides real-time streaming via WebSocket.

## Features

- Real-time certificate streaming from multiple CT logs
- WebSocket endpoints for different data formats:
  - `/` - Lite stream (certificates without DER encoding)
  - `/full-stream` - Full certificate data including chains
  - `/domains-only` - Just domain names
- REST API endpoints:
  - `/latest.json` - Last 25 certificates
  - `/example.json` - Most recent certificate
  - `/stats` - Server statistics
- Configurable via YAML or environment variables
- Structured logging with zap
- Graceful shutdown
- Docker support
- No UI. You can use the original [CaliDog Certstream UI](https://github.com/CaliDog/certstream-server/tree/master/frontend) if you need.

## Requirements

- Go 1.21 or higher
- Make (optional, for using Makefile commands)

## Quick Start

### Using Make

```bash
# Build the application
make build

# Run tests
make test

# Run the application
make run

# Build Docker image
make docker-build

# Run in Docker
make docker-run
```

### Manual Build

```bash
# Download dependencies
go mod download

# Build the binary
go build -o build/certstream-server ./cmd/certstream-server

# Run the application
./build/certstream-server
```

## Configuration

The server can be configured using:

1. Configuration file (`configs/config.yaml`)
2. Environment variables (prefix: `CERTSTREAM_`)
3. Command line flags

### Configuration Options

```yaml
server:
  port: 4000              # Server port (env: CERTSTREAM_SERVER_PORT or PORT)
  host: "0.0.0.0"         # Server host
  read_timeout: 10        # Read timeout in seconds
  write_timeout: 10       # Write timeout in seconds
  max_message_size: 512000  # Max WebSocket message size
  pong_timeout: 60        # WebSocket pong timeout
  ping_period: 30         # WebSocket ping period
  client_buffer_size: 500 # Client message buffer size

ct_logs:
  log_list_url: "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
  user_agent: "certstream-server-go/1.0"
  polling_interval: 10    # CT log polling interval in seconds
  batch_size: 512         # Certificates per batch
  max_concurrency: 5      # Concurrent fetches per watcher
  request_timeout: 30     # HTTP request timeout

logging:
  level: "info"           # Log level: debug, info, warn, error
  format: "json"          # Log format: json, console
```

### Environment Variables

All configuration options can be overridden using environment variables:

```bash
# Server configuration
export CERTSTREAM_SERVER_PORT=8080
export CERTSTREAM_SERVER_HOST=localhost

# CT logs configuration
export CERTSTREAM_CT_LOGS_POLLING_INTERVAL=5
export CERTSTREAM_CT_LOGS_BATCH_SIZE=1024

# Logging configuration
export CERTSTREAM_LOGGING_LEVEL=debug
export CERTSTREAM_LOGGING_FORMAT=console

# Special: PORT environment variable (for cloud deployments)
export PORT=8080  # Overrides CERTSTREAM_SERVER_PORT
```

### Command Line Flags

```bash
# Specify custom config file
./certstream-server -config /path/to/config.yaml

# Override log level
./certstream-server -log-level debug

# Show version
./certstream-server -version
```

## Docker

### Build Image

```bash
docker build -t certstream-server-go .
```

### Run Container

```bash
# Basic run
docker run -p 4000:4000 certstream-server-go

# With custom configuration
docker run -p 4000:4000 \
  -e CERTSTREAM_LOGGING_LEVEL=debug \
  -e CERTSTREAM_SERVER_PORT=8080 \
  certstream-server-go

# With config file
docker run -p 4000:4000 \
  -v /path/to/config.yaml:/app/configs/config.yaml \
  certstream-server-go
```

## API Usage

### WebSocket Endpoints

Connect to WebSocket endpoints to receive real-time certificate updates:

```javascript
// JavaScript example
const ws = new WebSocket('ws://localhost:4000/');

ws.on('message', (data) => {
  const cert = JSON.parse(data);
  console.log('New certificate:', cert.data.leaf_cert.all_domains);
});
```

### REST Endpoints

```bash
# Get latest 25 certificates
curl http://localhost:4000/latest.json

# Get most recent certificate
curl http://localhost:4000/example.json

# Get server statistics
curl http://localhost:4000/stats
```

## Development

### Project Structure

```
certstream-server/
├── cmd/
│   └── certstream-server/    # Main application entry point
│       └── main.go
├── pkg/
│   ├── buffer/               # Certificate ring buffer
│   ├── certstream/           # Main server logic
│   ├── client/               # WebSocket client management
│   ├── configs/              # Configuration structs
│   ├── log/                  # Logging utilities
│   ├── models/               # Data models
│   ├── parser/               # Certificate parsing
│   ├── utils/                # Utility functions
│   ├── watcher/              # CT log watchers
│   └── web/                  # HTTP/WebSocket server
├── configs/
│   └── config.yaml           # Default configuration
├── build/                    # Build artifacts
├── Dockerfile                # Docker build file
├── Makefile                  # Build automation
├── CLAUDE.md                 # Claude AI instructions
├── LICENSE                   # License file
├── go.mod                    # Go module definition
└── go.sum                    # Go module checksums
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with race detection
go test -race ./...
```

### Benchmarks

```bash
# Run benchmarks
go test -bench=. ./...
```

## Performance Considerations

- The server uses concurrent processing for fetching certificates from CT logs
- Client connections are managed with buffered channels to handle backpressure
- Slow clients are automatically disconnected if their buffers fill up
- The certificate buffer maintains only the most recent certificates in memory

## License

See the LICENSE file in the root directory.
