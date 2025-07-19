package buffer

import (
	"sync"
	"sync/atomic"

	"github.com/tb0hdan/certstream-server/pkg/models"
)

type CertificateBufferInterface interface {
	Add(cert *models.Certificate)
	GetLatest(limit int) []*models.Certificate
	GetMostRecent() *models.Certificate
	GetProcessedCount() int64
}

// CertificateBuffer maintains a ring buffer of recent certificates
type CertificateBuffer struct {
	mu             sync.RWMutex
	buffer         []*models.Certificate
	capacity       int
	head           int
	size           int
	processedCount int64
}

// New creates a new certificate buffer with the specified capacity
func New(capacity int) CertificateBufferInterface {
	return &CertificateBuffer{
		buffer:   make([]*models.Certificate, capacity),
		capacity: capacity,
		head:     0,
		size:     0,
	}
}

// Add adds a certificate to the buffer
func (cb *CertificateBuffer) Add(cert *models.Certificate) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.buffer[cb.head] = cert
	cb.head = (cb.head + 1) % cb.capacity

	if cb.size < cb.capacity {
		cb.size++
	}

	atomic.AddInt64(&cb.processedCount, 1)
}

// GetLatest returns the most recent certificates (up to limit)
func (cb *CertificateBuffer) GetLatest(limit int) []*models.Certificate {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if limit > cb.size {
		limit = cb.size
	}

	result := make([]*models.Certificate, limit)

	// Start from the most recent entry
	start := cb.head - 1
	if start < 0 {
		start = cb.capacity - 1
	}

	for i := 0; i < limit; i++ {
		idx := (start - i) % cb.capacity
		if idx < 0 {
			idx += cb.capacity
		}
		result[i] = cb.buffer[idx]
	}

	return result
}

// GetMostRecent returns the single most recent certificate
func (cb *CertificateBuffer) GetMostRecent() *models.Certificate {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.size == 0 {
		return nil
	}

	idx := cb.head - 1
	if idx < 0 {
		idx = cb.capacity - 1
	}

	return cb.buffer[idx]
}

// GetProcessedCount returns the total number of certificates processed
func (cb *CertificateBuffer) GetProcessedCount() int64 {
	return atomic.LoadInt64(&cb.processedCount)
}
