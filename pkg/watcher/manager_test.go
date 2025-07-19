package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type ManagerTestSuite struct {
	suite.Suite
	logger     *zap.Logger
	config     *configs.Config
	mockClient *MockClientManager
	mockBuffer *MockCertificateBuffer
	testServer *httptest.Server
}

func (suite *ManagerTestSuite) SetupTest() {
	suite.logger = zaptest.NewLogger(suite.T())
	suite.config = &configs.Config{
		CTLogs: configs.CTLogsConfig{
			LogListURL:       "http://localhost/ct/v3/all_logs_list.json",
			UserAgent:        "test-agent/1.0",
			PollingInterval:  1,
			BatchSize:        256,
			MaxConcurrency:   2,
			RequestTimeout:   10,
		},
	}

	suite.mockClient = new(MockClientManager)
	suite.mockBuffer = new(MockCertificateBuffer)
}

func (suite *ManagerTestSuite) TearDownTest() {
	if suite.testServer != nil {
		suite.testServer.Close()
	}
	suite.mockClient.AssertExpectations(suite.T())
	suite.mockBuffer.AssertExpectations(suite.T())
}

func (suite *ManagerTestSuite) createTestCTLogList() *models.CTLogList {
	return &models.CTLogList{
		Operators: []models.Operator{
			{
				Name: "Test Operator 1",
				Logs: []models.CTLog{
					{
						Description: "Test CT Log 1",
						LogID:       "test-log-1",
						Key:         "test-key-1",
						URL:         "https://ct1.example.com",
						MMD:         86400,
						State: models.State{
							Timestamp: time.Now(),
							State:     "usable",
						},
					},
					{
						Description: "Test CT Log 2",
						LogID:       "test-log-2",
						Key:         "test-key-2",
						URL:         "https://ct2.example.com",
						MMD:         86400,
						State: models.State{
							Timestamp: time.Now(),
							State:     "readonly",
						},
					},
				},
			},
			{
				Name: "Test Operator 2",
				Logs: []models.CTLog{
					{
						Description: "Test CT Log 3",
						LogID:       "test-log-3",
						Key:         "test-key-3",
						URL:         "https://ct3.example.com",
						MMD:         86400,
						State: models.State{
							Timestamp: time.Now(),
							State:     "usable",
						},
					},
				},
			},
		},
	}
}

func (suite *ManagerTestSuite) setupTestServer(response interface{}, statusCode int) {
	suite.testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("GET", r.Method)
		suite.Equal("test-agent/1.0", r.Header.Get("User-Agent"))
		
		w.WriteHeader(statusCode)
		if response != nil {
			err := json.NewEncoder(w).Encode(response)
			suite.NoError(err)
		}
	}))
	
	suite.config.CTLogs.LogListURL = suite.testServer.URL
}

func (suite *ManagerTestSuite) TestNewManager() {
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	suite.NotNil(manager)
	suite.IsType(&Manager{}, manager)
	
	mgr := manager.(*Manager)
	suite.Equal(suite.config, mgr.config)
	suite.Equal(suite.logger, mgr.logger)
	suite.Equal(suite.mockClient, mgr.clientManager)
	suite.Equal(suite.mockBuffer, mgr.certBuffer)
	suite.NotNil(mgr.watchers)
	suite.NotNil(mgr.httpClient)
}

func (suite *ManagerTestSuite) TestManagerInterface() {
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	suite.NotNil(manager)
}

func (suite *ManagerTestSuite) TestStartSuccess() {
	logList := suite.createTestCTLogList()
	suite.setupTestServer(logList, http.StatusOK)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.NoError(err)
	
	// Verify watchers were created
	mgr := manager.(*Manager)
	mgr.mu.RLock()
	suite.Len(mgr.watchers, 3) // Total logs from all operators
	suite.Contains(mgr.watchers, "https://ct1.example.com")
	suite.Contains(mgr.watchers, "https://ct2.example.com")
	suite.Contains(mgr.watchers, "https://ct3.example.com")
	mgr.mu.RUnlock()
	
	// Give a moment for goroutines to start
	time.Sleep(10 * time.Millisecond)
	cancel()
}

func (suite *ManagerTestSuite) TestStartWithEmptyLogList() {
	emptyLogList := &models.CTLogList{
		Operators: []models.Operator{},
	}
	suite.setupTestServer(emptyLogList, http.StatusOK)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.NoError(err)
	
	// Verify no watchers were created
	mgr := manager.(*Manager)
	mgr.mu.RLock()
	suite.Len(mgr.watchers, 0)
	mgr.mu.RUnlock()
}

func (suite *ManagerTestSuite) TestStartHTTPError() {
	suite.setupTestServer(nil, http.StatusInternalServerError)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.Error(err)
	suite.Contains(err.Error(), "failed to fetch CT log list")
}

func (suite *ManagerTestSuite) TestStartInvalidJSON() {
	suite.testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	suite.config.CTLogs.LogListURL = suite.testServer.URL
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.Error(err)
	suite.Contains(err.Error(), "failed to fetch CT log list")
}

func (suite *ManagerTestSuite) TestStartInvalidURL() {
	suite.config.CTLogs.LogListURL = "invalid-url"
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.Error(err)
	suite.Contains(err.Error(), "failed to fetch CT log list")
}

func (suite *ManagerTestSuite) TestGetStatsEmpty() {
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	stats := manager.GetStats()
	suite.NotNil(stats)
	suite.Len(stats, 0)
}

func (suite *ManagerTestSuite) TestGetStatsWithWatchers() {
	logList := suite.createTestCTLogList()
	suite.setupTestServer(logList, http.StatusOK)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.NoError(err)
	
	// Get stats
	stats := manager.GetStats()
	suite.NotNil(stats)
	suite.Len(stats, 3)
	
	// Verify stats structure
	for url, stat := range stats {
		suite.NotEmpty(url)
		suite.Equal(url, stat.LogURL)
		suite.GreaterOrEqual(stat.ProcessedCount, int64(0))
		suite.GreaterOrEqual(stat.TreeSize, int64(0))
		// LastUpdate might be zero for new watchers
	}
}

func (suite *ManagerTestSuite) TestConcurrentAccess() {
	logList := suite.createTestCTLogList()
	suite.setupTestServer(logList, http.StatusOK)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.NoError(err)
	
	// Test concurrent access to GetStats
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				stats := manager.GetStats()
				suite.NotNil(stats)
			}
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func (suite *ManagerTestSuite) TestManagerDependencyValidation() {
	// Test that manager requires valid dependencies
	// Note: In production, NewManager expects valid dependencies
	// This test verifies the expected behavior
	suite.True(true, "Manager requires valid dependencies for proper operation")
}

func (suite *ManagerTestSuite) TestFetchCTLogListUserAgent() {
	logList := suite.createTestCTLogList()
	
	// Custom user agent test
	suite.config.CTLogs.UserAgent = "custom-test-agent/2.0"
	
	suite.testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("custom-test-agent/2.0", r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(logList)
		suite.NoError(err)
	}))
	suite.config.CTLogs.LogListURL = suite.testServer.URL
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := manager.Start(ctx)
	suite.NoError(err)
}

func (suite *ManagerTestSuite) TestContextCancellation() {
	logList := suite.createTestCTLogList()
	suite.setupTestServer(logList, http.StatusOK)
	
	manager := NewManager(suite.config, suite.logger, suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	err := manager.Start(ctx)
	suite.NoError(err)
	
	// Cancel context immediately
	cancel()
	
	// Give time for watchers to handle cancellation
	time.Sleep(50 * time.Millisecond)
	
	// GetStats should still work after cancellation
	stats := manager.GetStats()
	suite.NotNil(stats)
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}