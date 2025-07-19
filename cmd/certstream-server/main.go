package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tb0hdan/certstream-server/pkg/certstream"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version = "1.0.0"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Parse command line flags
	var (
		configFile  = flag.String("config", "", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information")
		logLevel    = flag.String("log-level", "", "Override log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("certstream-server version %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Load configuration
	config, err := configs.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if specified
	if *logLevel != "" {
		config.Logging.Level = *logLevel
	}

	// Initialize logger
	logger, err := initLogger(config.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Log startup information
	logger.Info("Starting certstream-server",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("built", date),
	)

	// Create and start server
	server, err := certstream.New(config, logger)
	if err != nil {
		logger.Fatal("Failed to create server", zap.Error(err))
	}

	if err := server.Start(); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	logger.Info("Received shutdown signal")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(); err != nil {
		logger.Error("Error during shutdown", zap.Error(err))
	}

	select {
	case <-shutdownCtx.Done():
		logger.Error("Shutdown timeout exceeded")
	default:
		logger.Info("Shutdown complete")
	}
}

// initLogger initializes the zap logger
func initLogger(config configs.LoggingConfig) (*zap.Logger, error) {
	// Parse log level
	level, err := zapcore.ParseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Create encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Create encoder based on format
	var encoder zapcore.Encoder
	switch config.Format {
	case "json":
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case "console":
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Create core
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		level,
	)

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}
