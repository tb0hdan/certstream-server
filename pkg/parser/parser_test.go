package parser

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/stretchr/testify/suite"
)

type ParserTestSuite struct {
	suite.Suite
	parser ParserInterface
}

func (suite *ParserTestSuite) SetupTest() {
	suite.parser = New()
}

func (suite *ParserTestSuite) createTestCertificate(domains []string, isCA bool) (*x509.Certificate, []byte, error) {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"Test Corp"},
			OrganizationalUnit: []string{"IT"},
			CommonName:         "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              domains,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = 2
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, certDER, nil
}

func (suite *ParserTestSuite) createTestLogEntry(entryType ct.LogEntryType, domains []string) (*ct.LogEntry, error) {
	_, certDER, err := suite.createTestCertificate(domains, false)
	if err != nil {
		return nil, err
	}

	// Create chain certificates
	_, chainDER1, err := suite.createTestCertificate([]string{}, true)
	if err != nil {
		return nil, err
	}

	_, chainDER2, err := suite.createTestCertificate([]string{}, true)
	if err != nil {
		return nil, err
	}

	// Create timestamped entry
	timestamp := uint64(time.Now().UnixNano() / 1e6)
	
	entry := &ct.LogEntry{
		Index: 12345,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: timestamp,
				EntryType: entryType,
			},
		},
	}

	// Set entry data based on type
	switch entryType {
	case ct.X509LogEntryType:
		entry.Leaf.TimestampedEntry.X509Entry = &ct.ASN1Cert{Data: certDER}
	case ct.PrecertLogEntryType:
		// For precert, we need TBS certificate
		entry.Leaf.TimestampedEntry.PrecertEntry = &ct.PreCert{
			IssuerKeyHash:  [32]byte{1, 2, 3, 4}, // Mock issuer key hash
			TBSCertificate: certDER,             // In real case, this would be TBS cert
		}
	}

	// Add chain
	entry.Chain = []ct.ASN1Cert{
		{Data: chainDER1},
		{Data: chainDER2},
	}

	return entry, nil
}

func (suite *ParserTestSuite) TestNew() {
	parser := New()
	suite.NotNil(parser)
	suite.Implements((*ParserInterface)(nil), parser)
}

func (suite *ParserTestSuite) TestParseLogEntryX509() {
	domains := []string{"test.example.com", "www.test.example.com", "api.test.example.com"}
	entry, err := suite.createTestLogEntry(ct.X509LogEntryType, domains)
	suite.NoError(err)

	cert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test CT Log")
	suite.NoError(err)
	suite.NotNil(cert)

	// Verify basic fields
	suite.Equal("certificate_update", cert.MessageType)
	suite.Equal("X509LogEntry", cert.Data.UpdateType)
	suite.Equal(int64(12345), cert.Data.CertIndex)
	suite.Equal("https://ct.example.com/ct/v1/get-entries?start=12345&end=12345", cert.Data.CertLink)
	suite.Equal("Test CT Log", cert.Data.Source.Name)
	suite.Equal("https://ct.example.com", cert.Data.Source.URL)

	// Verify leaf certificate
	suite.Equal("test.example.com", cert.Data.LeafCert.Subject.CN)
	suite.Equal("US", cert.Data.LeafCert.Subject.C)
	suite.Equal("CA", cert.Data.LeafCert.Subject.ST)
	suite.Equal("San Francisco", cert.Data.LeafCert.Subject.L)
	suite.Equal("Test Corp", cert.Data.LeafCert.Subject.O)
	suite.Equal("IT", cert.Data.LeafCert.Subject.OU)
	suite.Equal("12345", cert.Data.LeafCert.SerialNumber)
	suite.NotEmpty(cert.Data.LeafCert.Fingerprint)
	suite.NotEmpty(cert.Data.LeafCert.AsDER)

	// Verify domains
	suite.Contains(cert.Data.LeafCert.AllDomains, "test.example.com")
	for _, domain := range domains {
		suite.Contains(cert.Data.LeafCert.AllDomains, domain)
	}

	// Verify extensions
	suite.Contains(cert.Data.LeafCert.Extensions.KeyUsage, "Digital Signature")
	suite.Contains(cert.Data.LeafCert.Extensions.KeyUsage, "Key Encipherment")
	suite.Contains(cert.Data.LeafCert.Extensions.ExtendedKeyUsage, "TLS Web Server Authentication")
	suite.Contains(cert.Data.LeafCert.Extensions.ExtendedKeyUsage, "TLS Web Client Authentication")
	suite.Equal("CA:FALSE", cert.Data.LeafCert.Extensions.BasicConstraints)
	suite.Contains(cert.Data.LeafCert.Extensions.SubjectAlternativeName, "test.example.com")

	// Verify chain
	suite.Len(cert.Data.Chain, 2)
	for _, chainCert := range cert.Data.Chain {
		suite.NotEmpty(chainCert.SerialNumber)
		suite.NotEmpty(chainCert.Fingerprint)
		suite.NotEmpty(chainCert.AsDER)
		suite.Contains(chainCert.Extensions.BasicConstraints, "CA:TRUE")
	}
}

func (suite *ParserTestSuite) TestParseLogEntryPrecert() {
	// For precert testing, we need to create a proper TBS certificate
	// Let's create an X509 certificate and extract its TBS certificate
	_, certDER, err := suite.createTestCertificate([]string{"precert.example.com"}, false)
	suite.NoError(err)

	// Parse the certificate to get TBS certificate
	cert, err := x509.ParseCertificate(certDER)
	suite.NoError(err)

	// Create a precert log entry
	entry := &ct.LogEntry{
		Index: 12345,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: uint64(time.Now().UnixNano() / 1e6),
				EntryType: ct.PrecertLogEntryType,
				PrecertEntry: &ct.PreCert{
					IssuerKeyHash:  [32]byte{1, 2, 3, 4},
					TBSCertificate: cert.RawTBSCertificate,
				},
			},
		},
	}

	parsedCert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test CT Log")
	suite.NoError(err)
	suite.NotNil(parsedCert)

	suite.Equal("PrecertLogEntry", parsedCert.Data.UpdateType)
}

func (suite *ParserTestSuite) TestParseLogEntryInvalidCert() {
	// Create an entry with invalid certificate data
	entry := &ct.LogEntry{
		Index: 12345,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: uint64(time.Now().UnixNano() / 1e6),
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: []byte("invalid cert data")},
			},
		},
	}

	cert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test CT Log")
	suite.Error(err)
	suite.Nil(cert)
	suite.Contains(err.Error(), "failed to parse X509 certificate")
}

func (suite *ParserTestSuite) TestParseLogEntryInvalidChain() {
	domains := []string{"test.example.com"}
	entry, err := suite.createTestLogEntry(ct.X509LogEntryType, domains)
	suite.NoError(err)

	// Add invalid certificate to chain
	entry.Chain = append(entry.Chain, ct.ASN1Cert{Data: []byte("invalid chain cert")})

	cert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test CT Log")
	suite.NoError(err) // Should not fail, just skip invalid chain cert
	suite.NotNil(cert)
	suite.Len(cert.Data.Chain, 2) // Should only have 2 valid certs
}

func (suite *ParserTestSuite) TestExtractDomains() {
	// Test with various domain configurations
	testCases := []struct {
		name     string
		cn       string
		dnsNames []string
		expected int
	}{
		{
			name:     "CN only",
			cn:       "example.com",
			dnsNames: []string{},
			expected: 1,
		},
		{
			name:     "DNS names only",
			cn:       "",
			dnsNames: []string{"test1.com", "test2.com"},
			expected: 2,
		},
		{
			name:     "CN and DNS names with duplicates",
			cn:       "example.com",
			dnsNames: []string{"example.com", "www.example.com", "api.example.com"},
			expected: 3, // CN duplicate should be removed
		},
		{
			name:     "No domains",
			cn:       "",
			dnsNames: []string{},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: tc.cn,
				},
				DNSNames: tc.dnsNames,
			}
			domains := extractDomains(cert)
			suite.Len(domains, tc.expected)
		})
	}
}

func (suite *ParserTestSuite) TestParseSubject() {
	subject := pkix.Name{
		Country:            []string{"US", "UK"}, // Multiple values
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Example Corp"},
		OrganizationalUnit: []string{"Engineering"},
		CommonName:         "example.com",
	}

	parsed := parseSubject(subject)
	suite.Equal("US", parsed.C) // Should take first value
	suite.Equal("California", parsed.ST)
	suite.Equal("San Francisco", parsed.L)
	suite.Equal("Example Corp", parsed.O)
	suite.Equal("Engineering", parsed.OU)
	suite.Equal("example.com", parsed.CN)
}

func (suite *ParserTestSuite) TestParseSubjectEmpty() {
	subject := pkix.Name{}
	parsed := parseSubject(subject)
	suite.Empty(parsed.C)
	suite.Empty(parsed.ST)
	suite.Empty(parsed.L)
	suite.Empty(parsed.O)
	suite.Empty(parsed.OU)
	suite.Empty(parsed.CN)
}

func (suite *ParserTestSuite) TestParseExtensions() {
	// Test various key usage combinations
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature | 
			x509.KeyUsageKeyEncipherment | 
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:           3,
		DNSNames:             []string{"test1.com", "test2.com"},
	}

	ext := parseExtensions(cert)
	
	// Key Usage
	suite.Contains(ext.KeyUsage, "Digital Signature")
	suite.Contains(ext.KeyUsage, "Key Encipherment")
	suite.Contains(ext.KeyUsage, "Data Encipherment")
	suite.Contains(ext.KeyUsage, "Key Agreement")
	suite.Contains(ext.KeyUsage, "Certificate Sign")
	suite.Contains(ext.KeyUsage, "CRL Sign")

	// Extended Key Usage
	suite.Contains(ext.ExtendedKeyUsage, "TLS Web Server Authentication")
	suite.Contains(ext.ExtendedKeyUsage, "TLS Web Client Authentication")
	suite.Contains(ext.ExtendedKeyUsage, "Code Signing")
	suite.Contains(ext.ExtendedKeyUsage, "E-mail Protection")

	// Basic Constraints
	suite.Equal("CA:TRUE, pathlen:3", ext.BasicConstraints)

	// SAN
	suite.Equal("test1.com, test2.com", ext.SubjectAlternativeName)
}

func (suite *ParserTestSuite) TestParseExtensionsCAWithZeroPathLen() {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	ext := parseExtensions(cert)
	suite.Equal("CA:TRUE, pathlen:0", ext.BasicConstraints)
}

func (suite *ParserTestSuite) TestParseExtensionsNonCA() {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	ext := parseExtensions(cert)
	suite.Equal("CA:FALSE", ext.BasicConstraints)
}

func (suite *ParserTestSuite) TestCalculateFingerprint() {
	data := []byte("test certificate data")
	expectedHash := sha256.Sum256(data)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])

	fingerprint := calculateFingerprint(data)
	suite.Equal(expectedFingerprint, fingerprint)
}

func (suite *ParserTestSuite) TestParseMerkleTreeLeaf() {
	// Create a valid Merkle tree leaf
	timestamp := uint64(time.Now().UnixNano() / 1e6)
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: timestamp,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: []byte("cert data")},
		},
	}

	// Marshal the leaf
	leafData, err := tls.Marshal(leaf)
	suite.NoError(err)

	// Parse it back
	parsedLeaf, err := suite.parser.ParseMerkleTreeLeaf(leafData)
	suite.NoError(err)
	suite.NotNil(parsedLeaf)
	suite.Equal(ct.V1, parsedLeaf.Version)
	suite.Equal(ct.TimestampedEntryLeafType, parsedLeaf.LeafType)
	suite.Equal(timestamp, parsedLeaf.TimestampedEntry.Timestamp)
}

func (suite *ParserTestSuite) TestParseMerkleTreeLeafInvalid() {
	// Test with invalid data
	_, err := suite.parser.ParseMerkleTreeLeaf([]byte("invalid leaf data"))
	suite.Error(err)
	suite.Contains(err.Error(), "failed to unmarshal leaf")
}

func (suite *ParserTestSuite) TestParseMerkleTreeLeafTrailingData() {
	// Create a valid leaf
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: uint64(time.Now().UnixNano() / 1e6),
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: []byte("cert data")},
		},
	}

	// Marshal and add trailing data
	leafData, err := tls.Marshal(leaf)
	suite.NoError(err)
	leafData = append(leafData, []byte("trailing data")...)

	// Should fail due to trailing data
	_, err = suite.parser.ParseMerkleTreeLeaf(leafData)
	suite.Error(err)
	suite.Contains(err.Error(), "trailing data after leaf")
}

func (suite *ParserTestSuite) TestParseLogEntryWithDifferentIndexes() {
	// Test with different index values
	testCases := []struct {
		name  string
		index uint64
	}{
		{"Zero index", 0},
		{"Small index", 100},
		{"Large index", 999999},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			entry, err := suite.createTestLogEntry(ct.X509LogEntryType, []string{"test.com"})
			suite.NoError(err)
			entry.Index = int64(tc.index)

			cert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test Log")
			suite.NoError(err)
			suite.Equal(int64(tc.index), cert.Data.CertIndex)
		})
	}
}

func (suite *ParserTestSuite) TestCertificateLinkFormatting() {
	testCases := []struct {
		name     string
		logURL   string
		index    uint64
		expected string
	}{
		{
			name:     "URL without trailing slash",
			logURL:   "https://ct.example.com",
			index:    12345,
			expected: "https://ct.example.com/ct/v1/get-entries?start=12345&end=12345",
		},
		{
			name:     "URL with trailing slash",
			logURL:   "https://ct.example.com/",
			index:    67890,
			expected: "https://ct.example.com/ct/v1/get-entries?start=67890&end=67890",
		},
		{
			name:     "URL with path",
			logURL:   "https://ct.example.com/logs/2024",
			index:    11111,
			expected: "https://ct.example.com/logs/2024/ct/v1/get-entries?start=11111&end=11111",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			entry, err := suite.createTestLogEntry(ct.X509LogEntryType, []string{"test.com"})
			suite.NoError(err)
			entry.Index = int64(tc.index)

			cert, err := suite.parser.ParseLogEntry(entry, tc.logURL, "Test Log")
			suite.NoError(err)
			suite.Equal(tc.expected, cert.Data.CertLink)
		})
	}
}

func (suite *ParserTestSuite) TestTimestampConversion() {
	// Test that timestamp is properly converted from milliseconds to seconds
	timestampMs := uint64(1700000000123) // milliseconds
	entry, err := suite.createTestLogEntry(ct.X509LogEntryType, []string{"test.com"})
	suite.NoError(err)
	entry.Leaf.TimestampedEntry.Timestamp = timestampMs

	cert, err := suite.parser.ParseLogEntry(entry, "https://ct.example.com", "Test Log")
	suite.NoError(err)
	
	expectedSeconds := float64(timestampMs) / 1000.0
	suite.Equal(expectedSeconds, cert.Data.Seen)
}

func TestParserTestSuite(t *testing.T) {
	suite.Run(t, new(ParserTestSuite))
}