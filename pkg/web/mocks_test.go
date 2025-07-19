package web

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/tb0hdan/certstream-server/pkg/models"
)

// MockClientManager is a mock implementation of client.ManagerInterface
type MockClientManager struct {
	mock.Mock
}

func (m *MockClientManager) Start(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockClientManager) Register(client *models.Client) {
	m.Called(client)
}

func (m *MockClientManager) Unregister(client *models.Client) {
	m.Called(client)
}

func (m *MockClientManager) Broadcast(cert *models.Certificate) {
	m.Called(cert)
}

func (m *MockClientManager) GetClientCount() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockClientManager) GetClients() map[string]*models.Client {
	args := m.Called()
	return args.Get(0).(map[string]*models.Client)
}

// MockCertificateBuffer is a mock implementation of buffer.CertificateBufferInterface
type MockCertificateBuffer struct {
	mock.Mock
}

func (m *MockCertificateBuffer) Add(cert *models.Certificate) {
	m.Called(cert)
}

func (m *MockCertificateBuffer) GetLatest(limit int) []*models.Certificate {
	args := m.Called(limit)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]*models.Certificate)
}

func (m *MockCertificateBuffer) GetMostRecent() *models.Certificate {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*models.Certificate)
}

func (m *MockCertificateBuffer) GetProcessedCount() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}