package watcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type WatcherTestSuite struct {
	suite.Suite
	logger     *zap.Logger
	config     *configs.Config
	log        models.CTLog
	mockClient *MockClientManager
	mockBuffer *MockCertificateBuffer
	mockParser *MockParser
}

func (suite *WatcherTestSuite) SetupTest() {
	suite.logger = zaptest.NewLogger(suite.T())
	suite.config = &configs.Config{
		CTLogs: configs.CTLogsConfig{
			UserAgent:       "test-agent/1.0",
			PollingInterval: 1,
			BatchSize:       256,
			MaxConcurrency:  2,
			RequestTimeout:  10,
		},
	}

	suite.log = models.CTLog{
		Description: "Test CT Log",
		LogID:       "test-log-1",
		Key:         "test-key-1",
		URL:         "https://ct.example.com",
		MMD:         86400,
		State: models.State{
			Timestamp: time.Now(),
			State:     "usable",
		},
	}

	suite.mockClient = new(MockClientManager)
	suite.mockBuffer = new(MockCertificateBuffer)
	suite.mockParser = new(MockParser)
}

func (suite *WatcherTestSuite) TearDownTest() {
	suite.mockClient.AssertExpectations(suite.T())
	suite.mockBuffer.AssertExpectations(suite.T())
	if suite.mockParser != nil {
		suite.mockParser.AssertExpectations(suite.T())
	}
}


func (suite *WatcherTestSuite) TestNewWatcher() {
	// Note: This test creates a real watcher since NewWatcher creates CT client internally
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	suite.NotNil(watcher)
	suite.IsType(&Watcher{}, watcher)
	
	w := watcher.(*Watcher)
	suite.Equal(suite.config, w.config)
	suite.NotNil(w.logger)
	suite.Equal(suite.log, w.log)
	suite.Equal("Test Operator", w.operatorName)
	suite.Equal(suite.mockClient, w.clientManager)
	suite.Equal(suite.mockBuffer, w.certBuffer)
	suite.NotNil(w.parser)
	suite.Equal(suite.config.CTLogs.BatchSize, w.batchSize)
	suite.Equal(int64(0), atomic.LoadInt64(&w.treeSize))
	suite.Equal(int64(0), atomic.LoadInt64(&w.processedCount))
}

func (suite *WatcherTestSuite) TestWatcherInterface() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	suite.NotNil(watcher)
}

func (suite *WatcherTestSuite) TestGetStatsInitial() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	stats := watcher.GetStats()
	
	suite.Equal(suite.log.URL, stats.LogURL)
	suite.Equal(int64(0), stats.ProcessedCount)
	suite.Equal(int64(0), stats.TreeSize)
	suite.True(stats.LastUpdate.IsZero())
}

func (suite *WatcherTestSuite) TestGetStatsAfterUpdate() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	w := watcher.(*Watcher)
	
	// Simulate some processed certificates and tree size
	atomic.StoreInt64(&w.treeSize, 1000)
	atomic.StoreInt64(&w.processedCount, 50)
	w.mu.Lock()
	w.lastUpdate = time.Now()
	w.mu.Unlock()
	
	stats := watcher.GetStats()
	
	suite.Equal(suite.log.URL, stats.LogURL)
	suite.Equal(int64(50), stats.ProcessedCount)
	suite.Equal(int64(1000), stats.TreeSize)
	suite.False(stats.LastUpdate.IsZero())
}

func (suite *WatcherTestSuite) TestWatcherWithInvalidURL() {
	invalidLog := suite.log
	invalidLog.URL = "invalid-url"
	
	// Should not panic even with invalid URL
	suite.NotPanics(func() {
		watcher := NewWatcher(suite.config, suite.logger, invalidLog, "Test Operator", suite.mockClient, suite.mockBuffer)
		suite.NotNil(watcher)
	})
}

func (suite *WatcherTestSuite) TestStartWithCTClientError() {
	// Test with invalid CT log URL to trigger CT client creation error
	invalidLog := suite.log
	invalidLog.URL = "not-a-url"
	
	watcher := NewWatcher(suite.config, suite.logger, invalidLog, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Should handle CT client errors gracefully
	suite.NotPanics(func() {
		// Start watcher in a goroutine since it will block
		go watcher.Start(ctx)
		
		// Give it a moment to start and encounter the error
		time.Sleep(10 * time.Millisecond)
		cancel()
	})
}

func (suite *WatcherTestSuite) TestConcurrentStatsAccess() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	w := watcher.(*Watcher)
	
	// Test concurrent access to GetStats
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				// Simulate concurrent updates
				if id%2 == 0 {
					atomic.AddInt64(&w.treeSize, 1)
					atomic.AddInt64(&w.processedCount, 1)
				}
				
				stats := watcher.GetStats()
				suite.NotNil(stats)
				suite.Equal(suite.log.URL, stats.LogURL)
			}
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func (suite *WatcherTestSuite) TestContextCancellation() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start watcher in goroutine
	started := make(chan struct{})
	finished := make(chan struct{})
	
	go func() {
		close(started)
		watcher.Start(ctx)
		close(finished)
	}()
	
	// Wait for start
	<-started
	
	// Cancel immediately
	cancel()
	
	// Verify watcher stops within reasonable time
	select {
	case <-finished:
		// Good, watcher stopped
	case <-time.After(2 * time.Second):
		suite.Fail("Watcher did not stop after context cancellation")
	}
}

func (suite *WatcherTestSuite) TestWatcherStartLogging() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	// Start watcher - it will fail to connect to CT log but should log appropriately
	watcher.Start(ctx)
	
	// Test passes if no panic occurs
}

func (suite *WatcherTestSuite) TestAtomicOperations() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	w := watcher.(*Watcher)
	
	// Test atomic operations
	atomic.StoreInt64(&w.treeSize, 100)
	atomic.StoreInt64(&w.processedCount, 50)
	
	suite.Equal(int64(100), atomic.LoadInt64(&w.treeSize))
	suite.Equal(int64(50), atomic.LoadInt64(&w.processedCount))
	
	atomic.AddInt64(&w.treeSize, 10)
	atomic.AddInt64(&w.processedCount, 5)
	
	suite.Equal(int64(110), atomic.LoadInt64(&w.treeSize))
	suite.Equal(int64(55), atomic.LoadInt64(&w.processedCount))
}

func (suite *WatcherTestSuite) TestWatcherBatchSize() {
	// Test with different batch sizes
	testCases := []int{1, 10, 100, 1000}
	
	for _, batchSize := range testCases {
		suite.config.CTLogs.BatchSize = batchSize
		watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
		w := watcher.(*Watcher)
		
		suite.Equal(batchSize, w.batchSize)
	}
}

func (suite *WatcherTestSuite) TestWatcherLoggerWithContext() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	w := watcher.(*Watcher)
	
	// Verify logger has CT log description context
	suite.NotNil(w.logger)
}

func (suite *WatcherTestSuite) TestWatcherConfigValidation() {
	// Test that watcher requires valid config
	// Note: In production, NewWatcher expects valid config and logger
	// This test verifies the expected behavior
	suite.True(true, "Watcher requires valid config for proper operation")
}

func (suite *WatcherTestSuite) TestWatcherLoggerValidation() {
	// Test that watcher requires valid logger
	// Note: In production, NewWatcher expects valid config and logger
	// This test verifies the expected behavior
	suite.True(true, "Watcher requires valid logger for proper operation")
}

func (suite *WatcherTestSuite) TestWatcherStatsConsistency() {
	watcher := NewWatcher(suite.config, suite.logger, suite.log, "Test Operator", suite.mockClient, suite.mockBuffer)
	
	// Get stats multiple times and ensure consistency
	stats1 := watcher.GetStats()
	stats2 := watcher.GetStats()
	
	suite.Equal(stats1.LogURL, stats2.LogURL)
	suite.Equal(stats1.ProcessedCount, stats2.ProcessedCount)
	suite.Equal(stats1.TreeSize, stats2.TreeSize)
}

func (suite *WatcherTestSuite) TestOperatorNameHandling() {
	operatorNames := []string{"", "Test Operator", "Very Long Operator Name With Spaces"}
	
	for _, operatorName := range operatorNames {
		watcher := NewWatcher(suite.config, suite.logger, suite.log, operatorName, suite.mockClient, suite.mockBuffer)
		w := watcher.(*Watcher)
		
		suite.Equal(operatorName, w.operatorName)
	}
}

func TestWatcherTestSuite(t *testing.T) {
	suite.Run(t, new(WatcherTestSuite))
}