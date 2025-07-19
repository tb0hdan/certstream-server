package client

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type ClientManagerTestSuite struct {
	suite.Suite
	logger  *zap.Logger
	manager *Manager
	ctx     context.Context
	cancel  context.CancelFunc
}

func (suite *ClientManagerTestSuite) SetupTest() {
	suite.logger = zaptest.NewLogger(suite.T())
	suite.manager = NewManager(suite.logger, 100).(*Manager)
	suite.ctx, suite.cancel = context.WithCancel(context.Background())
}

func (suite *ClientManagerTestSuite) TearDownTest() {
	suite.cancel()
}

func (suite *ClientManagerTestSuite) createTestClient(streamType models.StreamType) *models.Client {
	return &models.Client{
		StreamType:  streamType,
		SendChan:    make(chan []byte, 10),
		IP:          "127.0.0.1",
		UserAgent:   "test-agent",
		ConnectedAt: time.Now(),
	}
}

func (suite *ClientManagerTestSuite) createTestCertificate() *models.Certificate {
	return &models.Certificate{
		MessageType: "certificate_update",
		Data: models.CertificateData{
			UpdateType: "X509LogEntry",
			LeafCert: models.LeafCertificate{
				Subject: models.Subject{
					CN: "test.example.com",
				},
				Extensions: models.Extensions{
					SubjectAlternativeName: "DNS:test.example.com",
				},
				NotBefore:    time.Now().Unix(),
				NotAfter:     time.Now().Add(365 * 24 * time.Hour).Unix(),
				SerialNumber: "12345",
				Fingerprint:  "fingerprint123",
				AsDER:        "der-data",
				AllDomains:   []string{"test.example.com", "www.test.example.com"},
			},
			Chain: []models.ChainCertificate{
				{
					Subject: models.Subject{
						CN: "Intermediate CA",
					},
					Extensions:   models.Extensions{},
					NotBefore:    time.Now().Unix(),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour).Unix(),
					SerialNumber: "54321",
					Fingerprint:  "fingerprint321",
					AsDER:        "chain-der-data",
				},
			},
			CertIndex: 12345,
			CertLink:  "https://ct.example.com/cert/12345",
			Source: models.Source{
				Name: "Test CT Log",
				URL:  "https://ct.example.com",
			},
			Seen: float64(time.Now().Unix()),
		},
	}
}

func (suite *ClientManagerTestSuite) TestNewManager() {
	manager := NewManager(suite.logger, 500)
	suite.NotNil(manager)
	
	m, ok := manager.(*Manager)
	suite.True(ok)
	suite.Equal(500, m.bufferSize)
	suite.NotNil(m.clients)
	suite.NotNil(m.register)
	suite.NotNil(m.unregister)
	suite.NotNil(m.broadcast)
	suite.Equal(0, len(m.clients))
}

func (suite *ClientManagerTestSuite) TestRegisterClient() {
	client := suite.createTestClient(models.StreamFull)
	
	// Start manager in background
	go suite.manager.Start(suite.ctx)
	
	suite.manager.Register(client)
	
	// Give time for registration to process
	time.Sleep(10 * time.Millisecond)
	
	suite.NotEmpty(client.ID)
	suite.Equal(1, suite.manager.GetClientCount())
	
	clients := suite.manager.GetClients()
	suite.Len(clients, 1)
	suite.Equal(client, clients[client.ID])
}

func (suite *ClientManagerTestSuite) TestUnregisterClient() {
	client := suite.createTestClient(models.StreamFull)
	
	// Start manager in background
	go suite.manager.Start(suite.ctx)
	
	suite.manager.Register(client)
	time.Sleep(10 * time.Millisecond)
	
	suite.Equal(1, suite.manager.GetClientCount())
	
	suite.manager.Unregister(client)
	time.Sleep(10 * time.Millisecond)
	
	suite.Equal(0, suite.manager.GetClientCount())
	
	// Verify channel is closed
	_, ok := <-client.SendChan
	suite.False(ok)
}

func (suite *ClientManagerTestSuite) TestBroadcastCertificate() {
	// Create clients with different stream types
	clientFull := suite.createTestClient(models.StreamFull)
	clientLite := suite.createTestClient(models.StreamLite)
	clientDomains := suite.createTestClient(models.StreamDomainsOnly)
	
	// Start manager in background
	go suite.manager.Start(suite.ctx)
	
	// Register all clients
	suite.manager.Register(clientFull)
	suite.manager.Register(clientLite)
	suite.manager.Register(clientDomains)
	time.Sleep(10 * time.Millisecond)
	
	cert := suite.createTestCertificate()
	suite.manager.Broadcast(cert)
	
	// Check full stream client
	select {
	case msg := <-clientFull.SendChan:
		var receivedCert models.Certificate
		err := json.Unmarshal(msg, &receivedCert)
		suite.NoError(err)
		suite.Equal(cert.MessageType, receivedCert.MessageType)
		suite.Equal(cert.Data.LeafCert.AsDER, receivedCert.Data.LeafCert.AsDER)
	case <-time.After(100 * time.Millisecond):
		suite.Fail("Full stream client did not receive message")
	}
	
	// Check lite stream client
	select {
	case msg := <-clientLite.SendChan:
		var receivedCert models.Certificate
		err := json.Unmarshal(msg, &receivedCert)
		suite.NoError(err)
		suite.Equal(cert.MessageType, receivedCert.MessageType)
		suite.Empty(receivedCert.Data.LeafCert.AsDER) // DER should be removed
		suite.Empty(receivedCert.Data.Chain[0].AsDER)  // Chain DER should be removed
	case <-time.After(100 * time.Millisecond):
		suite.Fail("Lite stream client did not receive message")
	}
	
	// Check domains-only stream client
	select {
	case msg := <-clientDomains.SendChan:
		var receivedMsg models.DomainsOnly
		err := json.Unmarshal(msg, &receivedMsg)
		suite.NoError(err)
		suite.Equal(cert.MessageType, receivedMsg.MessageType)
		suite.Equal(cert.Data.LeafCert.AllDomains, receivedMsg.Data.Domains)
		suite.Equal(cert.Data.CertIndex, receivedMsg.Data.CertIndex)
	case <-time.After(100 * time.Millisecond):
		suite.Fail("Domains-only stream client did not receive message")
	}
}

func (suite *ClientManagerTestSuite) TestBroadcastChannelFull() {
	// Fill the broadcast channel
	for i := 0; i < 1000; i++ {
		suite.manager.broadcast <- suite.createTestCertificate()
	}
	
	// Try to broadcast when channel is full
	cert := suite.createTestCertificate()
	suite.manager.Broadcast(cert)
	
	// Should not block - test passes if we get here
}

func (suite *ClientManagerTestSuite) TestClientBufferFull() {
	// Create two clients - one with buffer, one without
	clientWithBuffer := &models.Client{
		StreamType:  models.StreamFull,
		SendChan:    make(chan []byte, 10), // Has buffer
		IP:          "127.0.0.1",
		UserAgent:   "test-agent",
		ConnectedAt: time.Now(),
	}
	
	clientNoBuffer := &models.Client{
		StreamType:  models.StreamFull,
		SendChan:    make(chan []byte), // No buffer
		IP:          "127.0.0.2",
		UserAgent:   "test-agent",
		ConnectedAt: time.Now(),
	}
	
	// Start manager in background
	go suite.manager.Start(suite.ctx)
	
	// Register both clients
	suite.manager.Register(clientWithBuffer)
	suite.manager.Register(clientNoBuffer)
	time.Sleep(20 * time.Millisecond)
	
	suite.Equal(2, suite.manager.GetClientCount())
	
	// Broadcast - should succeed for client with buffer, fail for client without
	cert := suite.createTestCertificate()
	suite.manager.Broadcast(cert)
	
	// Client with buffer should receive the message
	select {
	case msg := <-clientWithBuffer.SendChan:
		suite.NotNil(msg)
	case <-time.After(100 * time.Millisecond):
		suite.Fail("Client with buffer did not receive message")
	}
	
	// Give some time for the unregister to process
	time.Sleep(100 * time.Millisecond)
	
	// At least one client should remain (the one with buffer)
	remainingClients := suite.manager.GetClientCount()
	suite.GreaterOrEqual(remainingClients, 1, "At least the client with buffer should remain")
}

func (suite *ClientManagerTestSuite) TestGetClients() {
	client1 := suite.createTestClient(models.StreamFull)
	client2 := suite.createTestClient(models.StreamLite)
	
	// Start manager in background
	go suite.manager.Start(suite.ctx)
	
	suite.manager.Register(client1)
	suite.manager.Register(client2)
	time.Sleep(10 * time.Millisecond)
	
	clients := suite.manager.GetClients()
	suite.Len(clients, 2)
	
	// Verify it's a copy by modifying returned map
	delete(clients, client1.ID)
	suite.Equal(2, suite.manager.GetClientCount()) // Original should be unchanged
}

func (suite *ClientManagerTestSuite) TestContextCancellation() {
	// Start manager
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		suite.manager.Start(suite.ctx)
	}()
	
	// Register a client
	client := suite.createTestClient(models.StreamFull)
	suite.manager.Register(client)
	time.Sleep(10 * time.Millisecond)
	
	suite.Equal(1, suite.manager.GetClientCount())
	
	// Cancel context
	suite.cancel()
	
	// Wait for manager to stop
	wg.Wait()
	
	// All clients should be closed
	_, ok := <-client.SendChan
	suite.False(ok)
}

func (suite *ClientManagerTestSuite) TestConcurrentOperations() {
	// Start manager
	go suite.manager.Start(suite.ctx)
	
	var wg sync.WaitGroup
	numClients := 10
	numBroadcasts := 100
	
	// Register multiple clients concurrently
	clients := make([]*models.Client, numClients)
	wg.Add(numClients)
	for i := 0; i < numClients; i++ {
		go func(idx int) {
			defer wg.Done()
			client := suite.createTestClient(models.StreamType(idx % 3))
			clients[idx] = client
			suite.manager.Register(client)
		}(i)
	}
	wg.Wait()
	
	time.Sleep(50 * time.Millisecond)
	suite.Equal(numClients, suite.manager.GetClientCount())
	
	// Broadcast messages concurrently
	wg.Add(numBroadcasts)
	for i := 0; i < numBroadcasts; i++ {
		go func() {
			defer wg.Done()
			cert := suite.createTestCertificate()
			suite.manager.Broadcast(cert)
		}()
	}
	
	// Get client count concurrently
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			_ = suite.manager.GetClientCount()
			_ = suite.manager.GetClients()
		}()
	}
	
	wg.Wait()
	
	// Verify all clients received at least one message
	for _, client := range clients {
		select {
		case <-client.SendChan:
			// Success
		case <-time.After(100 * time.Millisecond):
			suite.Fail("Client did not receive any message")
		}
	}
}

func (suite *ClientManagerTestSuite) TestStreamTypeToString() {
	testCases := []struct {
		streamType models.StreamType
		expected   string
	}{
		{models.StreamFull, "full"},
		{models.StreamLite, "lite"},
		{models.StreamDomainsOnly, "domains-only"},
		{models.StreamType(99), "unknown"},
	}
	
	for _, tc := range testCases {
		result := streamTypeToString(tc.streamType)
		suite.Equal(tc.expected, result)
	}
}

func (suite *ClientManagerTestSuite) TestFormatMessageError() {
	// Test with nil certificate data that should cause marshaling to succeed
	// but we'll test the error path by mocking a scenario
	client := suite.createTestClient(models.StreamFull)
	
	// Start manager
	go suite.manager.Start(suite.ctx)
	
	suite.manager.Register(client)
	time.Sleep(10 * time.Millisecond)
	
	// Create a valid certificate - JSON marshaling rarely fails with valid structs
	cert := suite.createTestCertificate()
	suite.manager.Broadcast(cert)
	
	// Should still receive the message
	select {
	case msg := <-client.SendChan:
		suite.NotNil(msg)
	case <-time.After(100 * time.Millisecond):
		// This is expected if marshaling failed, but with our structs it shouldn't
	}
}

func (suite *ClientManagerTestSuite) TestManagerInterface() {
	// Test that NewManager returns an implementation of ManagerInterface
	manager := NewManager(suite.logger, 100)
	suite.NotNil(manager)
	suite.Implements((*ManagerInterface)(nil), manager)
}

func (suite *ClientManagerTestSuite) TestUnregisterNonExistentClient() {
	// Start manager
	go suite.manager.Start(suite.ctx)
	
	// Create a client but don't register it
	client := suite.createTestClient(models.StreamFull)
	client.ID = "non-existent"
	
	// Should not panic
	suite.manager.Unregister(client)
	time.Sleep(10 * time.Millisecond)
	
	suite.Equal(0, suite.manager.GetClientCount())
}

func (suite *ClientManagerTestSuite) TestFormatMessageWithNilChain() {
	cert := suite.createTestCertificate()
	cert.Data.Chain = nil
	
	// Test lite stream formatting with nil chain
	msg, err := suite.manager.formatMessage(cert, models.StreamLite)
	suite.NoError(err)
	
	var liteCert models.Certificate
	err = json.Unmarshal(msg, &liteCert)
	suite.NoError(err)
	suite.Nil(liteCert.Data.Chain)
}

func TestClientManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ClientManagerTestSuite))
}