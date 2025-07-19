package parser

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/tb0hdan/certstream-server/pkg/models"
)

type ParserInterface interface {
	ParseLogEntry(entry *ct.LogEntry, logURL string, operatorName string) (*models.Certificate, error)
	ParseMerkleTreeLeaf(leafData []byte) (*ct.MerkleTreeLeaf, error)
}

// Parser handles certificate parsing from CT logs
type Parser struct{}

// New creates a new certificate parser
func New() ParserInterface {
	return &Parser{}
}

// ParseLogEntry parses a CT log entry into a certificate
func (p *Parser) ParseLogEntry(entry *ct.LogEntry, logURL string, operatorName string) (*models.Certificate, error) {
	// Parse the leaf certificate
	var leafCert *x509.Certificate
	var err error

	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		leafCert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
		}

	case ct.PrecertLogEntryType:
		leafCert, err = x509.ParseTBSCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse precert: %w", err)
		}
	}

	// Extract all domains
	allDomains := extractDomains(leafCert)

	// Create leaf certificate data
	leafCertData := models.LeafCertificate{
		Subject:      parseSubject(leafCert.Subject),
		Extensions:   parseExtensions(leafCert),
		NotBefore:    leafCert.NotBefore.Unix(),
		NotAfter:     leafCert.NotAfter.Unix(),
		SerialNumber: leafCert.SerialNumber.String(),
		Fingerprint:  calculateFingerprint(leafCert.Raw),
		AllDomains:   allDomains,
		AsDER:        base64.StdEncoding.EncodeToString(leafCert.Raw),
	}

	// Parse certificate chain
	var chain []models.ChainCertificate
	if entry.Chain != nil {
		for _, certDER := range entry.Chain {
			cert, err := x509.ParseCertificate(certDER.Data)
			if err != nil {
				continue // Skip invalid certificates in chain
			}

			chainCert := models.ChainCertificate{
				Subject:      parseSubject(cert.Subject),
				Extensions:   parseExtensions(cert),
				NotBefore:    cert.NotBefore.Unix(),
				NotAfter:     cert.NotAfter.Unix(),
				SerialNumber: cert.SerialNumber.String(),
				Fingerprint:  calculateFingerprint(cert.Raw),
				AsDER:        base64.StdEncoding.EncodeToString(cert.Raw),
			}
			chain = append(chain, chainCert)
		}
	}

	// Determine update type
	updateType := "X509LogEntry"
	if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		updateType = "PrecertLogEntry"
	}

	// Create certificate link
	certLink := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d",
		strings.TrimSuffix(logURL, "/"), entry.Index, entry.Index)

	// Create the certificate
	cert := &models.Certificate{
		MessageType: "certificate_update",
		Data: models.CertificateData{
			UpdateType: updateType,
			LeafCert:   leafCertData,
			Chain:      chain,
			CertIndex:  int64(entry.Index),
			CertLink:   certLink,
			Source: models.Source{
				Name: operatorName,
				URL:  logURL,
			},
			Seen: float64(entry.Leaf.TimestampedEntry.Timestamp) / 1000.0,
		},
	}

	return cert, nil
}

// extractDomains extracts all domains from a certificate
func extractDomains(cert *x509.Certificate) []string {
	domains := make(map[string]bool)

	// Add Common Name
	if cert.Subject.CommonName != "" {
		domains[cert.Subject.CommonName] = true
	}

	// Add DNS names from SAN
	for _, dns := range cert.DNSNames {
		domains[dns] = true
	}

	// Convert to slice
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}

// parseSubject converts x509 subject to models.Subject
func parseSubject(subject interface{}) models.Subject {
	s := models.Subject{}

	switch v := subject.(type) {
	case pkix.Name:
		if len(v.Country) > 0 {
			s.C = v.Country[0]
		}
		if len(v.Province) > 0 {
			s.ST = v.Province[0]
		}
		if len(v.Locality) > 0 {
			s.L = v.Locality[0]
		}
		if len(v.Organization) > 0 {
			s.O = v.Organization[0]
		}
		if len(v.OrganizationalUnit) > 0 {
			s.OU = v.OrganizationalUnit[0]
		}
		s.CN = v.CommonName
	}

	return s
}

// parseExtensions extracts certificate extensions
func parseExtensions(cert *x509.Certificate) models.Extensions {
	ext := models.Extensions{}

	// Key Usage
	if cert.KeyUsage != 0 {
		var usage []string
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			usage = append(usage, "Digital Signature")
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			usage = append(usage, "Key Encipherment")
		}
		if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
			usage = append(usage, "Data Encipherment")
		}
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			usage = append(usage, "Key Agreement")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			usage = append(usage, "Certificate Sign")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
			usage = append(usage, "CRL Sign")
		}
		ext.KeyUsage = strings.Join(usage, ", ")
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 {
		var usage []string
		for _, eku := range cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageServerAuth:
				usage = append(usage, "TLS Web Server Authentication")
			case x509.ExtKeyUsageClientAuth:
				usage = append(usage, "TLS Web Client Authentication")
			case x509.ExtKeyUsageCodeSigning:
				usage = append(usage, "Code Signing")
			case x509.ExtKeyUsageEmailProtection:
				usage = append(usage, "E-mail Protection")
			}
		}
		ext.ExtendedKeyUsage = strings.Join(usage, ", ")
	}

	// Basic Constraints
	if cert.BasicConstraintsValid {
		if cert.IsCA {
			ext.BasicConstraints = "CA:TRUE"
			if cert.MaxPathLenZero {
				ext.BasicConstraints += ", pathlen:0"
			} else if cert.MaxPathLen > 0 {
				ext.BasicConstraints += fmt.Sprintf(", pathlen:%d", cert.MaxPathLen)
			}
		} else {
			ext.BasicConstraints = "CA:FALSE"
		}
	}

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 {
		ext.SubjectAlternativeName = strings.Join(cert.DNSNames, ", ")
	}

	return ext
}

// calculateFingerprint calculates SHA256 fingerprint of certificate
func calculateFingerprint(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// ParseMerkleTreeLeaf parses a Merkle tree leaf
func (p *Parser) ParseMerkleTreeLeaf(leafData []byte) (*ct.MerkleTreeLeaf, error) {
	var leaf ct.MerkleTreeLeaf
	if rest, err := tls.Unmarshal(leafData, &leaf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal leaf: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after leaf: %d bytes", len(rest))
	}
	return &leaf, nil
}
