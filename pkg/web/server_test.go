package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type WebServerTestSuite struct {
	suite.Suite
	logger            *zap.Logger
	config            *configs.Config
	mockClientManager *MockClientManager
	mockCertBuffer    *MockCertificateBuffer
	server            *Server
}

func (suite *WebServerTestSuite) SetupTest() {
	suite.logger = zaptest.NewLogger(suite.T())
	suite.config = &configs.Config{
		Server: configs.ServerConfig{
			Host:             "localhost",
			Port:             8080,
			ReadTimeout:      10,
			WriteTimeout:     10,
			MaxMessageSize:   512000,
			PongTimeout:      60,
			PingPeriod:       30,
			ClientBufferSize: 500,
		},
	}

	suite.mockClientManager = new(MockClientManager)
	suite.mockCertBuffer = new(MockCertificateBuffer)
	
	suite.server = NewServer(suite.config, suite.logger, suite.mockClientManager, suite.mockCertBuffer).(*Server)
}

func (suite *WebServerTestSuite) TearDownTest() {
	suite.mockClientManager.AssertExpectations(suite.T())
	suite.mockCertBuffer.AssertExpectations(suite.T())
}

func (suite *WebServerTestSuite) createTestCertificate() *models.Certificate {
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
				AllDomains:   []string{"test.example.com"},
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

func (suite *WebServerTestSuite) TestNewServer() {
	server := NewServer(suite.config, suite.logger, suite.mockClientManager, suite.mockCertBuffer)
	suite.NotNil(server)
	
	s, ok := server.(*Server)
	suite.True(ok)
	suite.Equal(suite.config, s.config)
	suite.Equal(suite.logger, s.logger)
	suite.Equal(suite.mockClientManager, s.clientManager)
	suite.Equal(suite.mockCertBuffer, s.certBuffer)
	suite.NotNil(s.upgrader)
}

func (suite *WebServerTestSuite) TestServerInterface() {
	server := NewServer(suite.config, suite.logger, suite.mockClientManager, suite.mockCertBuffer)
	suite.NotNil(server)
	suite.Implements((*ServerInterface)(nil), server)
}

func (suite *WebServerTestSuite) TestHandleLatest() {
	// Create test certificates
	cert1 := suite.createTestCertificate()
	cert2 := suite.createTestCertificate()
	cert2.Data.LeafCert.Subject.CN = "test2.example.com"
	
	certs := []*models.Certificate{cert1, cert2}
	
	suite.mockCertBuffer.On("GetLatest", 25).Return(certs)

	req, err := http.NewRequest("GET", "/latest.json", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleLatest(rr, req)

	suite.Equal(http.StatusOK, rr.Code)
	suite.Equal("application/json", rr.Header().Get("Content-Type"))
	suite.Equal("*", rr.Header().Get("Access-Control-Allow-Origin"))

	var response []*models.Certificate
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Len(response, 2)
	suite.Equal("test.example.com", response[0].Data.LeafCert.Subject.CN)
	suite.Equal("test2.example.com", response[1].Data.LeafCert.Subject.CN)
}

func (suite *WebServerTestSuite) TestHandleLatestEmpty() {
	suite.mockCertBuffer.On("GetLatest", 25).Return([]*models.Certificate{})

	req, err := http.NewRequest("GET", "/latest.json", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleLatest(rr, req)

	suite.Equal(http.StatusOK, rr.Code)
	suite.Equal("application/json", rr.Header().Get("Content-Type"))

	var response []*models.Certificate
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Len(response, 0)
}

func (suite *WebServerTestSuite) TestHandleExample() {
	cert := suite.createTestCertificate()
	suite.mockCertBuffer.On("GetMostRecent").Return(cert)

	req, err := http.NewRequest("GET", "/example.json", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleExample(rr, req)

	suite.Equal(http.StatusOK, rr.Code)
	suite.Equal("application/json", rr.Header().Get("Content-Type"))
	suite.Equal("*", rr.Header().Get("Access-Control-Allow-Origin"))

	var response models.Certificate
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("test.example.com", response.Data.LeafCert.Subject.CN)
}

func (suite *WebServerTestSuite) TestHandleExampleNoCert() {
	suite.mockCertBuffer.On("GetMostRecent").Return((*models.Certificate)(nil))

	req, err := http.NewRequest("GET", "/example.json", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleExample(rr, req)

	suite.Equal(http.StatusNoContent, rr.Code)
	suite.Equal("application/json", rr.Header().Get("Content-Type"))
	suite.Equal("*", rr.Header().Get("Access-Control-Allow-Origin"))
}

func (suite *WebServerTestSuite) TestHandleStats() {
	suite.mockCertBuffer.On("GetProcessedCount").Return(int64(12345))
	suite.mockClientManager.On("GetClientCount").Return(42)

	req, err := http.NewRequest("GET", "/stats", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleStats(rr, req)

	suite.Equal(http.StatusOK, rr.Code)
	suite.Equal("application/json", rr.Header().Get("Content-Type"))
	suite.Equal("*", rr.Header().Get("Access-Control-Allow-Origin"))

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(float64(12345), response["processed_certs"])
	suite.Equal(float64(42), response["connected_clients"])
}

func (suite *WebServerTestSuite) TestHandleHome() {
	req, err := http.NewRequest("GET", "/", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleHome(rr, req)

	// Since we don't have the actual frontend file, this will return 404
	// but we can verify the function doesn't panic
	suite.NotPanics(func() {
		suite.server.handleHome(rr, req)
	})
}

func (suite *WebServerTestSuite) TestWebSocketUpgradeHeaders() {
	// Test that non-WebSocket requests are handled by home handler
	req, err := http.NewRequest("GET", "/", nil)
	suite.NoError(err)

	rr := httptest.NewRecorder()
	suite.server.handleWebSocket(rr, req)

	// Should call handleHome since no Upgrade header
	suite.NotPanics(func() {
		suite.server.handleWebSocket(rr, req)
	})
}

func (suite *WebServerTestSuite) TestStreamTypeDetection() {
	testCases := []struct {
		path       string
		streamType models.StreamType
	}{
		{"/", models.StreamLite},
		{"/full-stream", models.StreamFull},
		{"/domains-only", models.StreamDomainsOnly},
		{"/unknown-path", models.StreamLite},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Path_%s", strings.ReplaceAll(tc.path, "/", "_")), func() {
			// Channel to capture the stream type from the goroutine
			actualStreamType := make(chan models.StreamType, 1)
			
			// Create a test server for WebSocket
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Mock client manager register call
				suite.mockClientManager.On("Register", mock.AnythingOfType("*models.Client")).Run(func(args mock.Arguments) {
					client := args.Get(0).(*models.Client)
					// Send the stream type to the channel instead of using suite.Equal in goroutine
					select {
					case actualStreamType <- client.StreamType:
					default:
					}
				}).Return().Once()

				suite.server.handleWebSocket(w, r)
			}))
			defer server.Close()

			// Convert HTTP URL to WebSocket URL
			u, err := url.Parse(server.URL)
			suite.NoError(err)
			u.Scheme = "ws"
			u.Path = tc.path

			// Attempt WebSocket connection
			_, _, _ = websocket.DefaultDialer.Dial(u.String(), nil)
			// We expect this to fail since we're not properly handling the WebSocket,
			// but the Register call should have been made with correct stream type
			
			// Wait for the stream type and assert it in the main test goroutine
			select {
			case streamType := <-actualStreamType:
				suite.Equal(tc.streamType, streamType)
			case <-time.After(100 * time.Millisecond):
				suite.Fail("Timeout waiting for Register call")
			}
		})
	}
}

func (suite *WebServerTestSuite) TestServerStartAndShutdown() {
	// Create a server with a different port to avoid conflicts
	config := &configs.Config{
		Server: configs.ServerConfig{
			Host:             "localhost",
			Port:             0, // Use any available port
			ReadTimeout:      1,
			WriteTimeout:     1,
			MaxMessageSize:   512000,
			PongTimeout:      60,
			PingPeriod:       30,
			ClientBufferSize: 500,
		},
	}

	mockClientManager := new(MockClientManager)
	mockCertBuffer := new(MockCertificateBuffer)
	server := NewServer(config, suite.logger, mockClientManager, mockCertBuffer).(*Server)

	// Start the server
	err := server.Start()
	suite.NoError(err)
	suite.NotNil(server.httpServer)

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = server.Shutdown(ctx)
	suite.NoError(err)

	mockClientManager.AssertExpectations(suite.T())
	mockCertBuffer.AssertExpectations(suite.T())
}

func (suite *WebServerTestSuite) TestHTTPEndpointsIntegration() {
	// Create a test server
	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", suite.server.handleLatest)
	mux.HandleFunc("/example.json", suite.server.handleExample)
	mux.HandleFunc("/stats", suite.server.handleStats)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test /latest.json
	suite.mockCertBuffer.On("GetLatest", 25).Return([]*models.Certificate{suite.createTestCertificate()})
	
	resp, err := http.Get(server.URL + "/latest.json")
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Test /example.json
	suite.mockCertBuffer.On("GetMostRecent").Return(suite.createTestCertificate())
	
	resp, err = http.Get(server.URL + "/example.json")
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Test /stats
	suite.mockCertBuffer.On("GetProcessedCount").Return(int64(100))
	suite.mockClientManager.On("GetClientCount").Return(5)
	
	resp, err = http.Get(server.URL + "/stats")
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

func (suite *WebServerTestSuite) TestWebSocketClientFields() {
	// Channel to capture client from the goroutine
	clientChan := make(chan *models.Client, 1)
	
	// Create a test server for WebSocket
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.mockClientManager.On("Register", mock.AnythingOfType("*models.Client")).Run(func(args mock.Arguments) {
			client := args.Get(0).(*models.Client)
			
			// Send client to channel instead of asserting in goroutine
			select {
			case clientChan <- client:
			default:
			}
		}).Return().Once()

		suite.server.handleWebSocket(w, r)
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	u, err := url.Parse(server.URL)
	suite.NoError(err)
	u.Scheme = "ws"

	// Attempt WebSocket connection with custom headers
	headers := http.Header{}
	headers.Set("User-Agent", "Test-Agent/1.0")
	
	_, _, _ = websocket.DefaultDialer.Dial(u.String(), headers)
	// We expect this to fail since we're not properly handling the WebSocket,
	// but the Register call should have been made
	
	// Verify client fields in the main test goroutine
	select {
	case client := <-clientChan:
		suite.NotNil(client.Connection)
		suite.NotNil(client.SendChan)
		suite.Equal(suite.config.Server.ClientBufferSize, cap(client.SendChan))
		suite.NotEmpty(client.IP)
		suite.False(client.ConnectedAt.IsZero())
		// UserAgent might be empty in test
	case <-time.After(100 * time.Millisecond):
		suite.Fail("Timeout waiting for Register call")
	}
}

func (suite *WebServerTestSuite) TestCORSHeaders() {
	endpoints := []string{"/latest.json", "/example.json", "/stats"}
	
	for _, endpoint := range endpoints {
		suite.Run(fmt.Sprintf("CORS_%s", strings.ReplaceAll(endpoint, "/", "_")), func() {
			req, err := http.NewRequest("GET", endpoint, nil)
			suite.NoError(err)

			rr := httptest.NewRecorder()

			// Set up mocks based on endpoint
			switch endpoint {
			case "/latest.json":
				suite.mockCertBuffer.On("GetLatest", 25).Return([]*models.Certificate{}).Once()
				suite.server.handleLatest(rr, req)
			case "/example.json":
				suite.mockCertBuffer.On("GetMostRecent").Return((*models.Certificate)(nil)).Once()
				suite.server.handleExample(rr, req)
			case "/stats":
				suite.mockCertBuffer.On("GetProcessedCount").Return(int64(0)).Once()
				suite.mockClientManager.On("GetClientCount").Return(0).Once()
				suite.server.handleStats(rr, req)
			}

			suite.Equal("*", rr.Header().Get("Access-Control-Allow-Origin"))
			suite.Equal("application/json", rr.Header().Get("Content-Type"))
		})
	}
}

func (suite *WebServerTestSuite) TestWebSocketUpgraderConfiguration() {
	server := NewServer(suite.config, suite.logger, suite.mockClientManager, suite.mockCertBuffer).(*Server)
	
	suite.Equal(1024, server.upgrader.ReadBufferSize)
	suite.Equal(1024, server.upgrader.WriteBufferSize)
	suite.NotNil(server.upgrader.CheckOrigin)
	
	// Test CheckOrigin function
	req := &http.Request{}
	suite.True(server.upgrader.CheckOrigin(req)) // Should allow all origins
}

func (suite *WebServerTestSuite) TestHTTPServerConfiguration() {
	config := &configs.Config{
		Server: configs.ServerConfig{
			Host:         "0.0.0.0",
			Port:         9999,
			ReadTimeout:  30,
			WriteTimeout: 45,
		},
	}

	server := NewServer(config, suite.logger, suite.mockClientManager, suite.mockCertBuffer).(*Server)
	
	err := server.Start()
	suite.NoError(err)
	
	suite.Equal("0.0.0.0:9999", server.httpServer.Addr)
	suite.Equal(30*time.Second, server.httpServer.ReadTimeout)
	suite.Equal(45*time.Second, server.httpServer.WriteTimeout)
	
	// Clean shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func TestWebServerTestSuite(t *testing.T) {
	suite.Run(t, new(WebServerTestSuite))
}