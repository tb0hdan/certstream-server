package utils

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type ServerInterface interface {
	// Start starts the certstream server
	Start() error
	// Shutdown gracefully shuts down the server
	Shutdown() error
}

func Run(server ServerInterface, logger *zap.Logger) {
	if err := server.Start(); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}

	// Wait for interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds.
	<-ctx.Done()
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
