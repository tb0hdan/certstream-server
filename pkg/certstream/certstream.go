package certstream

import (
	"context"
	"fmt"
	"sync"

	"github.com/tb0hdan/certstream-server/pkg/buffer"
	"github.com/tb0hdan/certstream-server/pkg/client"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/watcher"
	"github.com/tb0hdan/certstream-server/pkg/web"
	"go.uber.org/zap"
)

type ServerInterface interface {
	// Start starts the certstream server
	Start() error
	// Shutdown gracefully shuts down the server
	Shutdown() error
}

// Server represents the main certstream server
type Server struct {
	config         *configs.Config
	logger         *zap.Logger
	clientManager  client.ManagerInterface
	certBuffer     buffer.CertificateBufferInterface
	watcherManager watcher.ManagerInterface
	webServer      web.ServerInterface
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// New creates a new certstream server
func New(config *configs.Config, logger *zap.Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create certificate buffer
	certBuffer := buffer.New(25)

	// Create client manager
	clientManager := client.NewManager(logger, config.Server.ClientBufferSize)

	// Create watcher manager
	watcherManager := watcher.NewManager(config, logger, clientManager, certBuffer)

	// Create web server
	webServer := web.NewServer(config, logger, clientManager, certBuffer)

	return &Server{
		config:         config,
		logger:         logger,
		clientManager:  clientManager,
		certBuffer:     certBuffer,
		watcherManager: watcherManager,
		webServer:      webServer,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// Start starts the certstream server
func (s *Server) Start() error {
	s.logger.Info("Starting certstream server")

	// Start client manager
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.clientManager.Start(s.ctx)
	}()

	// Start CT log watchers
	if err := s.watcherManager.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start watcher manager: %w", err)
	}

	// Start web server
	if err := s.webServer.Start(); err != nil {
		return fmt.Errorf("failed to start web server: %w", err)
	}

	s.logger.Info("Certstream server started",
		zap.Int("port", s.config.Server.Port),
		zap.String("host", s.config.Server.Host),
	)

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down certstream server")

	// Cancel context to signal shutdown
	s.cancel()

	// Shutdown web server
	if err := s.webServer.Shutdown(s.ctx); err != nil {
		s.logger.Error("Error shutting down web server", zap.Error(err))
	}

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("Certstream server shut down")
	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"processed_certs":   s.certBuffer.GetProcessedCount(),
		"connected_clients": s.clientManager.GetClientCount(),
		"worker_stats":      s.watcherManager.GetStats(),
	}
}
