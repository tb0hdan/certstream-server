package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tb0hdan/certstream-server/pkg/certstream"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/log"
	"github.com/tb0hdan/certstream-server/pkg/utils"
	"go.uber.org/zap"
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
	logger, err := log.New(config.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = logger.Sync()
	}()

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
	utils.Run(server, logger)

}
