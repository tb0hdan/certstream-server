package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tb0hdan/certstream-server/pkg/buffer"
	"github.com/tb0hdan/certstream-server/pkg/client"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
)

type ServerInterface interface {
	Start() error
	Shutdown(ctx context.Context) error
}

// Server represents the web server
type Server struct {
	config        *configs.Config
	logger        *zap.Logger
	clientManager client.ManagerInterface
	certBuffer    buffer.CertificateBufferInterface
	httpServer    *http.Server
	upgrader      websocket.Upgrader
}

// NewServer creates a new web server
func NewServer(config *configs.Config, logger *zap.Logger, clientManager client.ManagerInterface, certBuffer buffer.CertificateBufferInterface) ServerInterface {
	return &Server{
		config:        config,
		logger:        logger,
		clientManager: clientManager,
		certBuffer:    certBuffer,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
	}
}

// Start starts the web server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// WebSocket endpoints
	mux.HandleFunc("/", s.handleWebSocket)
	mux.HandleFunc("/full-stream", s.handleWebSocket)
	mux.HandleFunc("/domains-only", s.handleWebSocket)

	// REST endpoints
	mux.HandleFunc("/latest.json", s.handleLatest)
	mux.HandleFunc("/example.json", s.handleExample)
	mux.HandleFunc("/stats", s.handleStats)

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  time.Duration(s.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Server.WriteTimeout) * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fatal("Failed to start HTTP server", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the web server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check if this is a WebSocket upgrade request
	if r.Header.Get("Upgrade") != "websocket" {
		s.handleHome(w, r)
		return
	}

	// Upgrade connection
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade connection", zap.Error(err))
		return
	}

	// Determine stream type based on path
	var streamType models.StreamType
	switch r.URL.Path {
	case "/full-stream":
		streamType = models.StreamFull
	case "/domains-only":
		streamType = models.StreamDomainsOnly
	default:
		streamType = models.StreamLite
	}

	// Create client
	client := &models.Client{
		StreamType:  streamType,
		Connection:  conn,
		SendChan:    make(chan []byte, s.config.Server.ClientBufferSize),
		IP:          r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		ConnectedAt: time.Now(),
	}

	// Register client
	s.clientManager.Register(client)

	// Handle client connection
	go s.handleClient(client)
}

// handleClient manages a WebSocket client connection
func (s *Server) handleClient(client *models.Client) {
	conn := client.Connection.(*websocket.Conn)
	ticker := time.NewTicker(time.Duration(s.config.Server.PingPeriod) * time.Second)
	defer func() {
		ticker.Stop()
		_ = conn.Close()
		s.clientManager.Unregister(client)
	}()

	// Configure connection
	conn.SetReadLimit(s.config.Server.MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Server.PongTimeout) * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Server.PongTimeout) * time.Second))
		return nil
	})

	// Start read pump (to handle pongs and client disconnects)
	go func() {
		for {
			if _, _, err := conn.NextReader(); err != nil {
				_ = conn.Close()
				break
			}
		}
	}()

	// Write pump
	for {
		select {
		case message, ok := <-client.SendChan:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Duration(s.config.Server.WriteTimeout) * time.Second))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Duration(s.config.Server.WriteTimeout) * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleHome serves the homepage
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./frontend/dist/index.html")
}

// handleLatest returns the latest certificates
func (s *Server) handleLatest(w http.ResponseWriter, r *http.Request) {
	certs := s.certBuffer.GetLatest(25)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(certs); err != nil {
		s.logger.Error("Failed to encode latest certificates", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleExample returns the most recent certificate
func (s *Server) handleExample(w http.ResponseWriter, r *http.Request) {
	cert := s.certBuffer.GetMostRecent()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if cert == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := json.NewEncoder(w).Encode(cert); err != nil {
		s.logger.Error("Failed to encode example certificate", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleStats returns server statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"processed_certs":   s.certBuffer.GetProcessedCount(),
		"connected_clients": s.clientManager.GetClientCount(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(stats); err != nil {
		s.logger.Error("Failed to encode stats", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
