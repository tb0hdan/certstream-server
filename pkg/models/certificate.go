package models

import (
	"time"
)

// Certificate represents a parsed certificate from CT logs
type Certificate struct {
	MessageType string                 `json:"message_type"`
	Data        CertificateData        `json:"data"`
}

// CertificateData contains the certificate details
type CertificateData struct {
	UpdateType       string            `json:"update_type"`
	LeafCert         LeafCertificate   `json:"leaf_cert"`
	Chain            []ChainCertificate `json:"chain,omitempty"`
	CertIndex        int64             `json:"cert_index"`
	CertLink         string            `json:"cert_link"`
	Source           Source            `json:"source"`
	Seen             float64           `json:"seen"`
}

// LeafCertificate represents the main certificate data
type LeafCertificate struct {
	Subject          Subject    `json:"subject"`
	Extensions       Extensions `json:"extensions"`
	NotBefore        int64      `json:"not_before"`
	NotAfter         int64      `json:"not_after"`
	SerialNumber     string     `json:"serial_number"`
	Fingerprint      string     `json:"fingerprint"`
	AsDER            string     `json:"as_der,omitempty"`
	AllDomains       []string   `json:"all_domains"`
}

// ChainCertificate represents a certificate in the chain
type ChainCertificate struct {
	Subject      Subject `json:"subject"`
	Extensions   Extensions `json:"extensions"`
	NotBefore    int64   `json:"not_before"`
	NotAfter     int64   `json:"not_after"`
	SerialNumber string  `json:"serial_number"`
	Fingerprint  string  `json:"fingerprint"`
	AsDER        string  `json:"as_der,omitempty"`
}

// Subject contains certificate subject information
type Subject struct {
	C            string `json:"C,omitempty"`
	ST           string `json:"ST,omitempty"`
	L            string `json:"L,omitempty"`
	O            string `json:"O,omitempty"`
	OU           string `json:"OU,omitempty"`
	CN           string `json:"CN,omitempty"`
	EmailAddress string `json:"emailAddress,omitempty"`
}

// Extensions contains certificate extensions
type Extensions struct {
	KeyUsage                  string   `json:"keyUsage,omitempty"`
	ExtendedKeyUsage          string   `json:"extendedKeyUsage,omitempty"`
	BasicConstraints          string   `json:"basicConstraints,omitempty"`
	SubjectKeyIdentifier      string   `json:"subjectKeyIdentifier,omitempty"`
	AuthorityKeyIdentifier    string   `json:"authorityKeyIdentifier,omitempty"`
	AuthorityInfoAccess       string   `json:"authorityInfoAccess,omitempty"`
	SubjectAlternativeName    string   `json:"subjectAlternativeName,omitempty"`
	CertificatePolicies       string   `json:"certificatePolicies,omitempty"`
}

// Source contains information about the CT log source
type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// DomainsOnly represents a simplified message with just domains
type DomainsOnly struct {
	MessageType string              `json:"message_type"`
	Data        DomainsOnlyData    `json:"data"`
}

// DomainsOnlyData contains just the domain information
type DomainsOnlyData struct {
	UpdateType string   `json:"update_type"`
	Domains    []string `json:"domains"`
	CertIndex  int64    `json:"cert_index"`
	CertLink   string   `json:"cert_link"`
	Source     Source   `json:"source"`
	Seen       float64  `json:"seen"`
}

// CTLog represents a Certificate Transparency log
type CTLog struct {
	Description       string    `json:"description"`
	LogID             string    `json:"log_id"`
	Key               string    `json:"key"`
	URL               string    `json:"url"`
	MMD               int       `json:"mmd"`
	State             State     `json:"state"`
	TemporalInterval  *Interval `json:"temporal_interval,omitempty"`
}

// State represents the state of a CT log
type State struct {
	Timestamp    time.Time `json:"timestamp"`
	State        string    `json:"state"`
}

// Interval represents a time interval for a CT log
type Interval struct {
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
}

// CTLogList represents the list of all CT logs
type CTLogList struct {
	Operators []Operator `json:"operators"`
}

// Operator represents a CT log operator
type Operator struct {
	Name string  `json:"name"`
	Logs []CTLog `json:"logs"`
}

// StreamType represents the type of certificate stream
type StreamType int

const (
	StreamFull StreamType = iota
	StreamLite
	StreamDomainsOnly
)

// Client represents a connected WebSocket client
type Client struct {
	ID         string
	StreamType StreamType
	Connection interface{}
	SendChan   chan []byte
	IP         string
	UserAgent  string
	ConnectedAt time.Time
}

// Stats represents server statistics
type Stats struct {
	ProcessedCerts  int64                    `json:"processed_certs"`
	ConnectedClients int                     `json:"connected_clients"`
	WorkerStats     map[string]WorkerStats   `json:"worker_stats"`
}

// WorkerStats represents statistics for a CT log worker
type WorkerStats struct {
	LogURL         string `json:"log_url"`
	ProcessedCount int64  `json:"processed_count"`
	TreeSize       int64  `json:"tree_size"`
	LastUpdate     time.Time `json:"last_update"`
}