package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/tb0hdan/certstream-server/pkg/buffer"
	"github.com/tb0hdan/certstream-server/pkg/client"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"github.com/tb0hdan/certstream-server/pkg/utils"
	"go.uber.org/zap"
)

type ManagerInterface interface {
	Start(ctx context.Context) error
	GetStats() map[string]models.WorkerStats
}

// Manager manages CT log watchers
type Manager struct {
	config        *configs.Config
	logger        *zap.Logger
	clientManager client.ManagerInterface
	certBuffer    buffer.CertificateBufferInterface
	watchers      map[string]*Watcher
	mu            sync.RWMutex
	httpClient    *http.Client
}

// NewManager creates a new watcher manager
func NewManager(config *configs.Config, logger *zap.Logger, clientManager client.ManagerInterface, certBuffer buffer.CertificateBufferInterface) ManagerInterface {
	standardClient := utils.GetRetryableClient(config, logger)

	return &Manager{
		config:        config,
		logger:        logger,
		clientManager: clientManager,
		certBuffer:    certBuffer,
		watchers:      make(map[string]*Watcher),
		httpClient:    standardClient,
	}
}

// Start starts all CT log watchers
func (m *Manager) Start(ctx context.Context) error {
	// Fetch CT log list
	logList, err := m.fetchCTLogList()
	if err != nil {
		return fmt.Errorf("failed to fetch CT log list: %w", err)
	}

	// Start watchers for each log
	for _, operator := range logList.Operators {
		// m.logger.Info(fmt.Sprintf("starting watcher for operator %s", operator))
		for _, log := range operator.Logs {
			// Only watch usable logs
			/*
				if log.State.State != "usable" {
					m.logger.Warn("Skipping CT log that is not usable", zap.String("log", log.URL), zap.String("state", log.State.State))
					continue
				} */

			watcher := NewWatcher(m.config, m.logger, log, operator.Name, m.clientManager, m.certBuffer)
			m.mu.Lock()
			m.watchers[log.URL] = watcher
			m.mu.Unlock()

			go watcher.Start(ctx)
		}
	}

	m.logger.Info("Started CT log watchers", zap.Int("count", len(m.watchers)))
	return nil
}

// fetchCTLogList fetches the list of CT logs
func (m *Manager) fetchCTLogList() (*models.CTLogList, error) {
	req, err := http.NewRequest("GET", m.config.CTLogs.LogListURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", m.config.CTLogs.UserAgent)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var logList models.CTLogList
	if err := json.NewDecoder(resp.Body).Decode(&logList); err != nil {
		return nil, err
	}

	return &logList, nil
}

// GetStats returns statistics for all watchers
func (m *Manager) GetStats() map[string]models.WorkerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]models.WorkerStats)
	for url, watcher := range m.watchers {
		stats[url] = watcher.GetStats()
	}
	return stats
}
