package buffer

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/tb0hdan/certstream-server/pkg/models"
)

type BufferTestSuite struct {
	suite.Suite
}

func (suite *BufferTestSuite) createTestCertificate(index int) *models.Certificate {
	return &models.Certificate{
		MessageType: "certificate_update",
		Data: models.CertificateData{
			UpdateType: "X509LogEntry",
			LeafCert: models.LeafCertificate{
				Subject: models.Subject{
					CN: fmt.Sprintf("test%d.example.com", index),
				},
				Extensions: models.Extensions{
					SubjectAlternativeName: fmt.Sprintf("DNS:test%d.example.com", index),
				},
				NotBefore:    time.Now().Unix(),
				NotAfter:     time.Now().Add(365 * 24 * time.Hour).Unix(),
				SerialNumber: fmt.Sprintf("serial-%d", index),
				Fingerprint:  fmt.Sprintf("fingerprint-%d", index),
				AllDomains:   []string{fmt.Sprintf("test%d.example.com", index)},
			},
			CertIndex: int64(index),
			CertLink:  fmt.Sprintf("https://ct.example.com/cert/%d", index),
			Source: models.Source{
				Name: "Test CT Log",
				URL:  "https://ct.example.com",
			},
			Seen: float64(time.Now().Unix()),
		},
	}
}

func (suite *BufferTestSuite) TestNew() {
	capacity := 100
	buffer := New(capacity)
	
	suite.NotNil(buffer)
	
	cb, ok := buffer.(*CertificateBuffer)
	suite.True(ok)
	suite.Equal(capacity, cb.capacity)
	suite.Equal(0, cb.size)
	suite.Equal(0, cb.head)
	suite.Equal(int64(0), cb.processedCount)
	suite.Len(cb.buffer, capacity)
}

func (suite *BufferTestSuite) TestAddSingleCertificate() {
	buffer := New(10)
	cert := suite.createTestCertificate(1)
	
	buffer.Add(cert)
	
	suite.Equal(int64(1), buffer.GetProcessedCount())
	
	recent := buffer.GetMostRecent()
	suite.NotNil(recent)
	suite.Equal(cert.Data.LeafCert.Subject.CN, recent.Data.LeafCert.Subject.CN)
}

func (suite *BufferTestSuite) TestAddMultipleCertificates() {
	buffer := New(10)
	
	for i := 0; i < 5; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	suite.Equal(int64(5), buffer.GetProcessedCount())
	
	latest := buffer.GetLatest(5)
	suite.Len(latest, 5)
	
	for i := 0; i < 5; i++ {
		suite.Equal(fmt.Sprintf("test%d.example.com", 4-i), latest[i].Data.LeafCert.Subject.CN)
	}
}

func (suite *BufferTestSuite) TestBufferOverflow() {
	capacity := 5
	buffer := New(capacity)
	
	for i := 0; i < 10; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	suite.Equal(int64(10), buffer.GetProcessedCount())
	
	latest := buffer.GetLatest(5)
	suite.Len(latest, 5)
	
	for i := 0; i < 5; i++ {
		suite.Equal(fmt.Sprintf("test%d.example.com", 9-i), latest[i].Data.LeafCert.Subject.CN)
	}
}

func (suite *BufferTestSuite) TestGetLatestWithLimitGreaterThanSize() {
	buffer := New(10)
	
	for i := 0; i < 3; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	latest := buffer.GetLatest(10)
	suite.Len(latest, 3)
}

func (suite *BufferTestSuite) TestGetLatestWithZeroLimit() {
	buffer := New(10)
	
	for i := 0; i < 5; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	latest := buffer.GetLatest(0)
	suite.Len(latest, 0)
}

func (suite *BufferTestSuite) TestGetMostRecentEmptyBuffer() {
	buffer := New(10)
	
	recent := buffer.GetMostRecent()
	suite.Nil(recent)
}

func (suite *BufferTestSuite) TestGetMostRecentAfterOverflow() {
	buffer := New(3)
	
	for i := 0; i < 5; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	recent := buffer.GetMostRecent()
	suite.NotNil(recent)
	suite.Equal("test4.example.com", recent.Data.LeafCert.Subject.CN)
}

func (suite *BufferTestSuite) TestConcurrentAccess() {
	buffer := New(100)
	numGoroutines := 10
	certsPerGoroutine := 10
	
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < certsPerGoroutine; j++ {
				cert := suite.createTestCertificate(goroutineID*100 + j)
				buffer.Add(cert)
			}
		}(i)
	}
	
	go func() {
		for i := 0; i < 50; i++ {
			_ = buffer.GetLatest(10)
			_ = buffer.GetMostRecent()
			time.Sleep(time.Millisecond)
		}
	}()
	
	wg.Wait()
	
	suite.Equal(int64(numGoroutines*certsPerGoroutine), buffer.GetProcessedCount())
}

func (suite *BufferTestSuite) TestGetLatestOrderAfterWrapAround() {
	buffer := New(3)
	
	for i := 0; i < 7; i++ {
		cert := suite.createTestCertificate(i)
		buffer.Add(cert)
	}
	
	latest := buffer.GetLatest(3)
	suite.Len(latest, 3)
	
	suite.Equal("test6.example.com", latest[0].Data.LeafCert.Subject.CN)
	suite.Equal("test5.example.com", latest[1].Data.LeafCert.Subject.CN)
	suite.Equal("test4.example.com", latest[2].Data.LeafCert.Subject.CN)
}

func (suite *BufferTestSuite) TestProcessedCountAtomicity() {
	buffer := New(1000)
	numGoroutines := 100
	certsPerGoroutine := 100
	
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < certsPerGoroutine; j++ {
				cert := suite.createTestCertificate(goroutineID*1000 + j)
				buffer.Add(cert)
			}
		}(i)
	}
	
	wg.Wait()
	
	expectedCount := int64(numGoroutines * certsPerGoroutine)
	suite.Equal(expectedCount, buffer.GetProcessedCount())
}

func (suite *BufferTestSuite) TestInterfaceImplementation() {
	buffer := New(10)
	
	suite.NotNil(buffer)
	
	cert := suite.createTestCertificate(1)
	buffer.Add(cert)
	
	suite.Equal(int64(1), buffer.GetProcessedCount())
	suite.NotNil(buffer.GetMostRecent())
	suite.Len(buffer.GetLatest(1), 1)
}

func (suite *BufferTestSuite) TestEdgeCaseCapacityOne() {
	buffer := New(1)
	
	cert1 := suite.createTestCertificate(1)
	cert2 := suite.createTestCertificate(2)
	
	buffer.Add(cert1)
	suite.Equal("test1.example.com", buffer.GetMostRecent().Data.LeafCert.Subject.CN)
	
	buffer.Add(cert2)
	suite.Equal("test2.example.com", buffer.GetMostRecent().Data.LeafCert.Subject.CN)
	
	latest := buffer.GetLatest(10)
	suite.Len(latest, 1)
	suite.Equal("test2.example.com", latest[0].Data.LeafCert.Subject.CN)
}

func TestBufferTestSuite(t *testing.T) {
	suite.Run(t, new(BufferTestSuite))
}