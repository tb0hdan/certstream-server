package watcher

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/tb0hdan/certstream-server/pkg/buffer"
	"github.com/tb0hdan/certstream-server/pkg/client"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/models"
	"github.com/tb0hdan/certstream-server/pkg/parser"
	"go.uber.org/zap"
)

// Watcher watches a single CT log for new certificates
type Watcher struct {
	config        *configs.Config
	logger        *zap.Logger
	log           models.CTLog
	operatorName  string
	clientManager *client.Manager
	certBuffer    *buffer.CertificateBuffer
	parser        *parser.Parser
	ctClient      *ctclient.LogClient

	// State
	treeSize       int64
	processedCount int64
	batchSize      int
	lastUpdate     time.Time
	mu             sync.RWMutex
}

// NewWatcher creates a new CT log watcher
func NewWatcher(config *configs.Config, logger *zap.Logger, log models.CTLog, operatorName string,
	clientManager *client.Manager, certBuffer *buffer.CertificateBuffer) *Watcher {

	// Create CT client
	httpClient := &http.Client{
		Timeout: time.Duration(config.CTLogs.RequestTimeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}

	ctClient, err := ctclient.New(log.URL, httpClient, jsonclient.Options{
		UserAgent: config.CTLogs.UserAgent,
	})
	if err != nil {
		logger.Error("Failed to create CT client", zap.Error(err), zap.String("log", log.URL))
	}

	return &Watcher{
		config:        config,
		logger:        logger.With(zap.String("log", log.Description)),
		log:           log,
		operatorName:  operatorName,
		clientManager: clientManager,
		certBuffer:    certBuffer,
		parser:        parser.New(),
		ctClient:      ctClient,
		batchSize:     config.CTLogs.BatchSize,
	}
}

// Start starts watching the CT log
func (w *Watcher) Start(ctx context.Context) {
	w.logger.Info("Starting CT log watcher")

	// Initialize by getting current tree size
	if err := w.updateTreeSize(ctx); err != nil {
		w.logger.Error("Failed to get initial tree size", zap.Error(err))
		return
	}

	// Main polling loop
	ticker := time.NewTicker(time.Duration(w.config.CTLogs.PollingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Stopping CT log watcher")
			return

		case <-ticker.C:
			w.poll(ctx)
		}
	}
}

// poll checks for new certificates
func (w *Watcher) poll(ctx context.Context) {
	// Get current tree size
	oldSize := atomic.LoadInt64(&w.treeSize)
	if err := w.updateTreeSize(ctx); err != nil {
		w.logger.Error("Failed to update tree size", zap.Error(err))
		return
	}

	newSize := atomic.LoadInt64(&w.treeSize)
	if newSize <= oldSize {
		return // No new certificates
	}

	// Calculate number of new entries
	newEntries := newSize - oldSize
	w.logger.Debug("Found new certificates",
		zap.Int64("count", newEntries),
		zap.Int64("old_size", oldSize),
		zap.Int64("new_size", newSize),
	)

	// Fetch new certificates in batches
	w.fetchNewCertificates(ctx, oldSize, newSize)
}

// updateTreeSize updates the current tree size
func (w *Watcher) updateTreeSize(ctx context.Context) error {
	sth, err := w.ctClient.GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get STH: %w", err)
	}

	atomic.StoreInt64(&w.treeSize, int64(sth.TreeSize))
	w.mu.Lock()
	w.lastUpdate = time.Now()
	w.mu.Unlock()

	return nil
}

// fetchNewCertificates fetches certificates between start and end indices
func (w *Watcher) fetchNewCertificates(ctx context.Context, start, end int64) {
	// Create work items for batch processing
	type workItem struct {
		start int64
		end   int64
	}

	var workItems []workItem
	for i := start; i < end; i += int64(w.batchSize) {
		batchEnd := i + int64(w.batchSize)
		if batchEnd > end {
			batchEnd = end
		}
		workItems = append(workItems, workItem{start: i, end: batchEnd - 1})
	}

	// Process batches concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, w.config.CTLogs.MaxConcurrency)

	for _, item := range workItems {
		wg.Add(1)
		go func(wi workItem) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			w.processBatch(ctx, wi.start, wi.end)
		}(item)
	}

	wg.Wait()
}

// processBatch processes a batch of certificates
func (w *Watcher) processBatch(ctx context.Context, start, end int64) {
	entries, err := w.ctClient.GetEntries(ctx, start, end)
	if err != nil {
		w.logger.Error("Failed to fetch entries",
			zap.Error(err),
			zap.Int64("start", start),
			zap.Int64("end", end),
		)
		return
	}

	for idx, entry := range entries {
		// Parse the certificate
		logEntry := &ct.LogEntry{
			Leaf:  entry.Leaf,
			Chain: entry.Chain,
			Index: int64(uint64(start + int64(idx))),
		}

		cert, err := w.parser.ParseLogEntry(logEntry, w.log.URL, w.operatorName)
		if err != nil {
			w.logger.Debug("Failed to parse certificate",
				zap.Error(err),
				zap.Int64("index", start+int64(idx)),
			)
			continue
		}

		// Add to buffer
		w.certBuffer.Add(cert)

		// Broadcast to clients
		w.clientManager.Broadcast(cert)

		// Update processed count
		atomic.AddInt64(&w.processedCount, 1)
	}
}

// GetStats returns watcher statistics
func (w *Watcher) GetStats() models.WorkerStats {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return models.WorkerStats{
		LogURL:         w.log.URL,
		ProcessedCount: atomic.LoadInt64(&w.processedCount),
		TreeSize:       atomic.LoadInt64(&w.treeSize),
		LastUpdate:     w.lastUpdate,
	}
}
