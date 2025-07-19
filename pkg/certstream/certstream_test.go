package certstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type CertstreamTestSuite struct {
	suite.Suite
	logger            *zap.Logger
	config            *configs.Config
	mockClientManager *MockClientManager
	mockCertBuffer    *MockCertificateBuffer
	mockWatcherManager *MockWatcherManager
	mockWebServer     *MockWebServer
}

func (suite *CertstreamTestSuite) SetupTest() {
	suite.logger = zaptest.NewLogger(suite.T())
	suite.config = &configs.Config{
		Server: configs.ServerConfig{
			Host:             "localhost",
			Port:             4000,
			ClientBufferSize: 1000,
		},
		CTLogs: configs.CTLogsConfig{
			LogListURL: "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json",
		},
	}

	suite.mockClientManager = new(MockClientManager)
	suite.mockCertBuffer = new(MockCertificateBuffer)
	suite.mockWatcherManager = new(MockWatcherManager)
	suite.mockWebServer = new(MockWebServer)
}

func (suite *CertstreamTestSuite) TearDownTest() {
	suite.mockClientManager.AssertExpectations(suite.T())
	suite.mockCertBuffer.AssertExpectations(suite.T())
	suite.mockWatcherManager.AssertExpectations(suite.T())
	suite.mockWebServer.AssertExpectations(suite.T())
}

func (suite *CertstreamTestSuite) TestNew() {
	server, err := New(suite.config, suite.logger)
	
	suite.NoError(err)
	suite.NotNil(server)
	suite.Equal(suite.config, server.config)
	suite.Equal(suite.logger, server.logger)
	suite.NotNil(server.clientManager)
	suite.NotNil(server.certBuffer)
	suite.NotNil(server.watcherManager)
	suite.NotNil(server.webServer)
	suite.NotNil(server.ctx)
	suite.NotNil(server.cancel)
}

func (suite *CertstreamTestSuite) TestServerInterface() {
	var server ServerInterface
	server, err := New(suite.config, suite.logger)
	
	suite.NoError(err)
	suite.NotNil(server)
}

func (suite *CertstreamTestSuite) TestStartSuccess() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())
	defer server.cancel()

	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWatcherManager.On("Start", mock.Anything).Return(nil)
	suite.mockWebServer.On("Start").Return(nil)

	err := server.Start()
	
	suite.NoError(err)
	
	// Give time for goroutine to start
	time.Sleep(10 * time.Millisecond)
}

func (suite *CertstreamTestSuite) TestStartWatcherError() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())
	defer server.cancel()

	watcherError := errors.New("watcher start failed")
	
	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWatcherManager.On("Start", mock.Anything).Return(watcherError)

	err := server.Start()
	
	suite.Error(err)
	suite.Contains(err.Error(), "failed to start watcher manager")
	suite.Contains(err.Error(), watcherError.Error())
	
	// Give time for goroutine to start
	time.Sleep(10 * time.Millisecond)
}

func (suite *CertstreamTestSuite) TestStartWebServerError() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())
	defer server.cancel()

	webServerError := errors.New("web server start failed")
	
	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWatcherManager.On("Start", mock.Anything).Return(nil)
	suite.mockWebServer.On("Start").Return(webServerError)

	err := server.Start()
	
	suite.Error(err)
	suite.Contains(err.Error(), "failed to start web server")
	suite.Contains(err.Error(), webServerError.Error())
	
	// Give time for goroutine to start
	time.Sleep(10 * time.Millisecond)
}

func (suite *CertstreamTestSuite) TestShutdownSuccess() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())

	// Start the client manager goroutine
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		suite.mockClientManager.Start(server.ctx)
	}()

	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWebServer.On("Shutdown", mock.Anything).Return(nil)

	err := server.Shutdown()
	
	suite.NoError(err)
}

func (suite *CertstreamTestSuite) TestShutdownWebServerError() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())

	// Start the client manager goroutine
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		suite.mockClientManager.Start(server.ctx)
	}()

	webServerError := errors.New("web server shutdown failed")
	
	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWebServer.On("Shutdown", mock.Anything).Return(webServerError)

	err := server.Shutdown()
	
	suite.NoError(err) // Shutdown doesn't return error even if web server shutdown fails
}

func (suite *CertstreamTestSuite) TestGetStats() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}

	processedCount := int64(12345)
	clientCount := 42
	workerStats := map[string]models.WorkerStats{
		"worker1": {
			LogURL:         "https://ct1.example.com",
			ProcessedCount: 100,
			TreeSize:       1000,
			LastUpdate:     time.Now(),
		},
		"worker2": {
			LogURL:         "https://ct2.example.com",
			ProcessedCount: 200,
			TreeSize:       2000,
			LastUpdate:     time.Now(),
		},
	}

	// Set up expectations
	suite.mockCertBuffer.On("GetProcessedCount").Return(processedCount)
	suite.mockClientManager.On("GetClientCount").Return(clientCount)
	suite.mockWatcherManager.On("GetStats").Return(workerStats)

	stats := server.GetStats()
	
	suite.Equal(processedCount, stats["processed_certs"])
	suite.Equal(clientCount, stats["connected_clients"])
	suite.Equal(workerStats, stats["worker_stats"])
}

func (suite *CertstreamTestSuite) TestStartAndShutdownIntegration() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())

	// Set up expectations
	suite.mockClientManager.On("Start", mock.Anything).Return()
	suite.mockWatcherManager.On("Start", mock.Anything).Return(nil)
	suite.mockWebServer.On("Start").Return(nil)
	suite.mockWebServer.On("Shutdown", mock.Anything).Return(nil)

	// Start the server
	err := server.Start()
	suite.NoError(err)

	// Give some time for everything to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown the server
	err = server.Shutdown()
	suite.NoError(err)
}

func (suite *CertstreamTestSuite) TestContextCancellation() {
	server := &Server{
		config:         suite.config,
		logger:         suite.logger,
		clientManager:  suite.mockClientManager,
		certBuffer:     suite.mockCertBuffer,
		watcherManager: suite.mockWatcherManager,
		webServer:      suite.mockWebServer,
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())

	// Set up a channel to signal when Start is called
	startCalled := make(chan struct{})
	
	suite.mockClientManager.On("Start", mock.Anything).Run(func(args mock.Arguments) {
		close(startCalled)
		ctx := args.Get(0).(context.Context)
		<-ctx.Done() // Wait for context cancellation
	}).Return()

	// Start the client manager goroutine
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		server.clientManager.Start(server.ctx)
	}()

	// Wait for Start to be called
	<-startCalled

	// Cancel the context
	server.cancel()

	// Wait for goroutine to finish
	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - goroutine finished
	case <-time.After(1 * time.Second):
		suite.Fail("Goroutine did not finish after context cancellation")
	}
}

func TestCertstreamTestSuite(t *testing.T) {
	suite.Run(t, new(CertstreamTestSuite))
}