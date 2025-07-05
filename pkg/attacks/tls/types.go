package tls

import (
	"crypto/x509"
	"time"
)

// TLSTestResult represents the result of TLS security testing
type TLSTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                `json:"tests_executed"`
	VulnerabilitiesFound []TLSVulnerability `json:"vulnerabilities_found"`

	// TLS-specific results
	CipherTests      []CipherTestResult      `json:"cipher_tests,omitempty"`
	CertificateTests []CertificateTestResult `json:"certificate_tests,omitempty"`
	DowngradeTests   []DowngradeTestResult   `json:"downgrade_tests,omitempty"`

	// Performance metrics
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`
	RequestsPerSecond float64 `json:"requests_per_second"`

	// TLS-specific metrics
	SupportedTLSVersions []string `json:"supported_tls_versions"`
	WeakCiphersFound     int      `json:"weak_ciphers_found"`
	CertificateIssues    int      `json:"certificate_issues"`
}

// TLSVulnerability represents a TLS-specific security vulnerability
type TLSVulnerability struct {
	Type        string `json:"type"`      // weak_cipher, cert_expired, protocol_downgrade, etc.
	Severity    string `json:"severity"`  // low, medium, high, critical
	Component   string `json:"component"` // cipher, certificate, protocol
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// TLS-specific fields
	TLSVersion    string `json:"tls_version,omitempty"`
	CipherSuite   string `json:"cipher_suite,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	Exploitable   bool   `json:"exploitable"`
}

// CipherTestResult represents the result of cipher suite testing
type CipherTestResult struct {
	CipherSuite    string        `json:"cipher_suite"`
	TLSVersion     string        `json:"tls_version"`
	Supported      bool          `json:"supported"`
	Preferred      bool          `json:"preferred"`
	KeyExchange    string        `json:"key_exchange"`
	Authentication string        `json:"authentication"`
	Encryption     string        `json:"encryption"`
	MAC            string        `json:"mac"`
	SecurityLevel  string        `json:"security_level"` // secure, weak, insecure
	ResponseTime   time.Duration `json:"response_time"`

	// Security analysis
	WeakPoints    []string `json:"weak_points,omitempty"`
	IsDeprecated  bool     `json:"is_deprecated"`
	IsExportGrade bool     `json:"is_export_grade"`
	KeyLength     int      `json:"key_length"`
}

// CertificateTestResult represents the result of certificate validation testing
type CertificateTestResult struct {
	CertificateID string    `json:"certificate_id"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	SignatureAlg  string    `json:"signature_algorithm"`
	PublicKeyAlg  string    `json:"public_key_algorithm"`
	KeyLength     int       `json:"key_length"`
	IsCA          bool      `json:"is_ca"`
	IsSelfSigned  bool      `json:"is_self_signed"`

	// Validation results
	IsValid       bool `json:"is_valid"`
	IsExpired     bool `json:"is_expired"`
	IsRevoked     bool `json:"is_revoked"`
	ChainValid    bool `json:"chain_valid"`
	HostnameMatch bool `json:"hostname_match"`

	// Security analysis
	SecurityIssues []string          `json:"security_issues"`
	WeakSignature  bool              `json:"weak_signature"`
	WeakKeyLength  bool              `json:"weak_key_length"`
	Extensions     map[string]string `json:"extensions,omitempty"`

	// Certificate chain
	ChainLength int      `json:"chain_length"`
	ChainIssues []string `json:"chain_issues,omitempty"`
}

// DowngradeTestResult represents the result of protocol downgrade testing
type DowngradeTestResult struct {
	TargetVersion     string        `json:"target_version"`
	NegotiatedVersion string        `json:"negotiated_version"`
	DowngradeForced   bool          `json:"downgrade_forced"`
	AttackVector      string        `json:"attack_vector"` // version_rollback, cipher_downgrade
	ResponseTime      time.Duration `json:"response_time"`

	// Security analysis
	IsVulnerable     bool   `json:"is_vulnerable"`
	SecurityImpact   string `json:"security_impact"`
	AttackComplexity string `json:"attack_complexity"` // low, medium, high
	MITMPossible     bool   `json:"mitm_possible"`

	// Test details
	ClientHello      string   `json:"client_hello,omitempty"`
	ServerHello      string   `json:"server_hello,omitempty"`
	HandshakeDetails []string `json:"handshake_details,omitempty"`
}

// Note: Main TLSTester is defined in tls.go
// Individual testers are defined in their respective files

// TLSConnection represents a TLS connection for testing
type TLSConnection struct {
	Host         string
	Port         int
	TLSVersion   string
	CipherSuite  string
	Certificate  *x509.Certificate
	PeerCerts    []*x509.Certificate
	ConnState    ConnectionState
	Established  bool
	Error        error
	ResponseTime time.Duration
}

// ConnectionState represents the state of a TLS connection
type ConnectionState struct {
	Version                     uint16
	HandshakeComplete           bool
	CipherSuite                 uint16
	NegotiatedProtocol          string
	NegotiatedProtocolIsMutual  bool
	ServerName                  string
	PeerCertificates            []*x509.Certificate
	VerifiedChains              [][]*x509.Certificate
	SignedCertificateTimestamps [][]byte
	OCSPResponse                []byte
	TLSUnique                   []byte
}

// TLSFingerprint represents a TLS fingerprint for analysis
type TLSFingerprint struct {
	JA3            string            `json:"ja3"`
	JA3S           string            `json:"ja3s"`
	CipherSuites   []uint16          `json:"cipher_suites"`
	Extensions     []uint16          `json:"extensions"`
	EllipticCurves []uint16          `json:"elliptic_curves"`
	ECPointFormats []uint8           `json:"ec_point_formats"`
	Versions       []uint16          `json:"versions"`
	Metadata       map[string]string `json:"metadata"`
}

// Common TLS cipher suites for testing
var (
	// Secure cipher suites
	SecureCipherSuites = []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	// Weak/deprecated cipher suites to test for
	WeakCipherSuites = []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_RC4_128_MD5",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	}

	// Export-grade cipher suites (should never be supported)
	ExportCipherSuites = []string{
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	}

	// TLS versions for testing
	TLSVersions = []string{
		"TLS 1.3",
		"TLS 1.2",
		"TLS 1.1",
		"TLS 1.0",
		"SSL 3.0", // Should be disabled
		"SSL 2.0", // Should be disabled
	}
)
