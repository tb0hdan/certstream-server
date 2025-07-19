package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
)

type ManagerInterface interface {
	Start(ctx context.Context)
	Register(client *models.Client)
	Unregister(client *models.Client)
	Broadcast(cert *models.Certificate)
	GetClientCount() int
	GetClients() map[string]*models.Client
}

// Manager manages WebSocket clients
type Manager struct {
	clients    map[string]*models.Client
	mu         sync.RWMutex
	logger     *zap.Logger
	register   chan *models.Client
	unregister chan *models.Client
	broadcast  chan *models.Certificate
	bufferSize int
}

// NewManager creates a new client manager
func NewManager(logger *zap.Logger, bufferSize int) ManagerInterface {
	return &Manager{
		clients:    make(map[string]*models.Client),
		logger:     logger,
		register:   make(chan *models.Client),
		unregister: make(chan *models.Client),
		broadcast:  make(chan *models.Certificate, 1000),
		bufferSize: bufferSize,
	}
}

// Start starts the client manager
func (m *Manager) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			m.closeAllClients()
			return

		case client := <-m.register:
			m.registerClient(client)

		case client := <-m.unregister:
			m.unregisterClient(client)

		case cert := <-m.broadcast:
			m.broadcastCertificate(cert)
		}
	}
}

// Register registers a new client
func (m *Manager) Register(client *models.Client) {
	client.ID = uuid.New().String()
	m.register <- client
}

// Unregister unregisters a client
func (m *Manager) Unregister(client *models.Client) {
	m.unregister <- client
}

// Broadcast broadcasts a certificate to all clients
func (m *Manager) Broadcast(cert *models.Certificate) {
	select {
	case m.broadcast <- cert:
	default:
		m.logger.Warn("Broadcast channel full, dropping certificate")
	}
}

// GetClientCount returns the number of connected clients
func (m *Manager) GetClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// GetClients returns a copy of all connected clients
func (m *Manager) GetClients() map[string]*models.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clients := make(map[string]*models.Client)
	for id, client := range m.clients {
		clients[id] = client
	}
	return clients
}

// registerClient handles client registration
func (m *Manager) registerClient(client *models.Client) {
	m.mu.Lock()
	m.clients[client.ID] = client
	m.mu.Unlock()

	m.logger.Info("Client connected",
		zap.String("id", client.ID),
		zap.String("ip", client.IP),
		zap.String("stream_type", streamTypeToString(client.StreamType)),
	)
}

// unregisterClient handles client unregistration
func (m *Manager) unregisterClient(client *models.Client) {
	m.mu.Lock()
	if _, ok := m.clients[client.ID]; ok {
		close(client.SendChan)
		delete(m.clients, client.ID)
	}
	m.mu.Unlock()

	m.logger.Info("Client disconnected",
		zap.String("id", client.ID),
		zap.Duration("duration", time.Since(client.ConnectedAt)),
	)
}

// broadcastCertificate broadcasts a certificate to all clients
func (m *Manager) broadcastCertificate(cert *models.Certificate) {
	m.mu.RLock()
	clients := make([]*models.Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	m.mu.RUnlock()

	for _, client := range clients {
		message, err := m.formatMessage(cert, client.StreamType)
		if err != nil {
			m.logger.Error("Failed to format message", zap.Error(err))
			continue
		}

		select {
		case client.SendChan <- message:
		default:
			// Client buffer is full, close the client
			m.logger.Warn("Client buffer full, closing connection",
				zap.String("id", client.ID),
			)
			m.Unregister(client)
		}
	}
}

// formatMessage formats a certificate message based on stream type
func (m *Manager) formatMessage(cert *models.Certificate, streamType models.StreamType) ([]byte, error) {
	switch streamType {
	case models.StreamFull:
		return json.Marshal(cert)

	case models.StreamLite:
		// Remove DER data from lite stream
		liteCert := *cert
		liteCert.Data.LeafCert.AsDER = ""
		if liteCert.Data.Chain != nil {
			chain := make([]models.ChainCertificate, len(liteCert.Data.Chain))
			for i, c := range liteCert.Data.Chain {
				chain[i] = c
				chain[i].AsDER = ""
			}
			liteCert.Data.Chain = chain
		}
		return json.Marshal(liteCert)

	case models.StreamDomainsOnly:
		domainsOnly := models.DomainsOnly{
			MessageType: cert.MessageType,
			Data: models.DomainsOnlyData{
				UpdateType: cert.Data.UpdateType,
				Domains:    cert.Data.LeafCert.AllDomains,
				CertIndex:  cert.Data.CertIndex,
				CertLink:   cert.Data.CertLink,
				Source:     cert.Data.Source,
				Seen:       cert.Data.Seen,
			},
		}
		return json.Marshal(domainsOnly)

	default:
		return json.Marshal(cert)
	}
}

// closeAllClients closes all client connections
func (m *Manager) closeAllClients() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, client := range m.clients {
		close(client.SendChan)
	}
	m.clients = make(map[string]*models.Client)
}

// streamTypeToString converts stream type to string
func streamTypeToString(st models.StreamType) string {
	switch st {
	case models.StreamFull:
		return "full"
	case models.StreamLite:
		return "lite"
	case models.StreamDomainsOnly:
		return "domains-only"
	default:
		return "unknown"
	}
}
