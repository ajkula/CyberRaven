// Package sniffer implements expert-level TLS intelligence for CyberRaven
// File: pkg/sniffer/tls_analyzer.go
package sniffer

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TLSAnalyzer performs expert-level TLS security analysis
type TLSAnalyzer struct {
	mu sync.RWMutex

	// Captured TLS intelligence
	certificates    []CapturedCertificate
	handshakes      []TLSHandshake
	sessions        map[string]*TLSSession
	vulnerabilities []TLSVulnerability
	cipherIntel     map[string]*CipherIntelligence
	extensions      map[string][]TLSExtension

	// Analysis parameters
	expertLevel      bool
	aggressiveMode   bool
	vulnerabilityDB  *TLSVulnerabilityDB
	certificateCache map[string]*CapturedCertificate

	// Statistics
	handshakesAnalyzed   int
	vulnerabilitiesFound int
	weakCiphersDetected  int
	certificateIssues    int
}

// CapturedCertificate represents a captured X.509 certificate with security analysis
type CapturedCertificate struct {
	// Certificate metadata
	Fingerprint     string    `json:"fingerprint"`
	SHA1Fingerprint string    `json:"sha1_fingerprint"`
	SHA256Hash      string    `json:"sha256_hash"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	SerialNumber    string    `json:"serial_number"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	KeyAlgorithm    string    `json:"key_algorithm"`
	KeySize         int       `json:"key_size"`
	SignatureAlg    string    `json:"signature_algorithm"`

	// Security analysis
	IsExpired       bool              `json:"is_expired"`
	IsExpiringSoon  bool              `json:"is_expiring_soon"` // < 30 days
	IsSelfSigned    bool              `json:"is_self_signed"`
	IsWeakKey       bool              `json:"is_weak_key"`       // < 2048 RSA
	IsWeakSignature bool              `json:"is_weak_signature"` // MD5, SHA1
	HasWeakChain    bool              `json:"has_weak_chain"`
	SANs            []string          `json:"sans"` // Subject Alternative Names
	Extensions      map[string]string `json:"extensions"`

	// Vulnerability mapping
	CVEs           []string                   `json:"cves,omitempty"`
	VulnCategories []string                   `json:"vuln_categories"`
	SecurityIssues []CertificateSecurityIssue `json:"security_issues"`
	RiskScore      float64                    `json:"risk_score"` // 0-100

	// Attack intelligence
	PinningBypass   bool     `json:"pinning_bypass_possible"`
	MITMOpportunity bool     `json:"mitm_opportunity"`
	AttackVectors   []string `json:"attack_vectors"`

	// Chain analysis
	ChainLength int                    `json:"chain_length"`
	ChainCerts  []string               `json:"chain_certificates"`
	ChainIssues []string               `json:"chain_issues"`
	TrustPath   []CertificateTrustPath `json:"trust_path"`

	// Capture metadata
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ServerName string    `json:"server_name"` // from SNI
	IPAddress  net.IP    `json:"ip_address"`
	Port       int       `json:"port"`
}

// TLSHandshake represents a complete TLS handshake analysis
type TLSHandshake struct {
	// Connection metadata
	ID         string        `json:"id"`
	ClientIP   net.IP        `json:"client_ip"`
	ServerIP   net.IP        `json:"server_ip"`
	ServerPort int           `json:"server_port"`
	StartTime  time.Time     `json:"start_time"`
	Duration   time.Duration `json:"duration"`

	// TLS negotiation
	ClientVersion     string `json:"client_version"`
	ServerVersion     string `json:"server_version"`
	NegotiatedVersion string `json:"negotiated_version"`
	CipherSuite       string `json:"cipher_suite"`
	CompressionMethod string `json:"compression_method"`

	// Extensions analysis
	ClientExtensions []TLSExtension `json:"client_extensions"`
	ServerExtensions []TLSExtension `json:"server_extensions"`
	SNI              string         `json:"sni"`
	ALPN             []string       `json:"alpn"`

	// Security analysis
	DowngradeDetected     bool     `json:"downgrade_detected"`
	WeakCipher            bool     `json:"weak_cipher"`
	PerfectForwardSecrecy bool     `json:"perfect_forward_secrecy"`
	SupportsRenegotiation bool     `json:"supports_renegotiation"`
	VulnerableToAttacks   []string `json:"vulnerable_to_attacks"`

	// Certificate intelligence
	CertificateChain []string `json:"certificate_chain"`
	CertFingerprint  string   `json:"certificate_fingerprint"`

	// Attack surface
	SessionResumption bool     `json:"session_resumption"`
	SessionTickets    bool     `json:"session_tickets"`
	AttackSurface     []string `json:"attack_surface"`
	RiskScore         float64  `json:"risk_score"`
}

// TLSSession represents session intelligence for attack context
type TLSSession struct {
	SessionID      string            `json:"session_id"`
	ServerName     string            `json:"server_name"`
	CipherSuite    string            `json:"cipher_suite"`
	SessionTicket  string            `json:"session_ticket,omitempty"`
	MasterSecret   string            `json:"master_secret,omitempty"` // if extractable
	IsReusable     bool              `json:"is_reusable"`
	AttackVectors  []string          `json:"attack_vectors"`
	HijackPossible bool              `json:"hijack_possible"`
	Metadata       map[string]string `json:"metadata"`
}

// TLSVulnerability represents a TLS-specific security vulnerability
type TLSVulnerability struct {
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"` // critical, high, medium, low
	Category    string    `json:"category"` // protocol, cipher, certificate, implementation
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	CVE         string    `json:"cve,omitempty"`
	CVSS        float64   `json:"cvss_score,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	Occurrences int       `json:"occurrences"`

	// Technical details
	AffectedVersions []string          `json:"affected_versions"`
	ExploitCode      string            `json:"exploit_code,omitempty"`
	AttackVector     string            `json:"attack_vector"`
	Prerequisites    []string          `json:"prerequisites"`
	References       []string          `json:"references"`
	Metadata         map[string]string `json:"metadata"`
}

// CipherIntelligence represents intelligence about cipher suites
type CipherIntelligence struct {
	Name              string   `json:"name"`
	Protocol          string   `json:"protocol"`
	KeyExchange       string   `json:"key_exchange"`
	Authentication    string   `json:"authentication"`
	Encryption        string   `json:"encryption"`
	MAC               string   `json:"mac"`
	SecurityLevel     string   `json:"security_level"` // secure, weak, insecure, export
	KeyLength         int      `json:"key_length"`
	IsDeprecated      bool     `json:"is_deprecated"`
	IsExportGrade     bool     `json:"is_export_grade"`
	VulnerableTo      []string `json:"vulnerable_to"`
	RecommendedAction string   `json:"recommended_action"`
	AEAD              bool     `json:"aead"` // Authenticated Encryption with Associated Data
	PFS               bool     `json:"pfs"`  // Perfect Forward Secrecy
}

// TLSExtension represents a TLS extension with security analysis
type TLSExtension struct {
	Type     uint16 `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Critical bool   `json:"critical"`
	Security string `json:"security"` // secure, informational, concerning, dangerous
}

// Additional supporting types
type CertificateSecurityIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

type CertificateTrustPath struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Valid   bool   `json:"valid"`
}

type TLSVulnerabilityDB struct {
	mu               sync.RWMutex
	cipherVulns      map[string][]TLSVulnerability
	protocolVulns    map[string][]TLSVulnerability
	extensionVulns   map[string][]TLSVulnerability
	certificateVulns map[string][]TLSVulnerability
	lastUpdated      time.Time
}

// NewTLSAnalyzer creates a new expert-level TLS analyzer
func NewTLSAnalyzer(expertLevel bool) *TLSAnalyzer {
	analyzer := &TLSAnalyzer{
		certificates:     make([]CapturedCertificate, 0),
		handshakes:       make([]TLSHandshake, 0),
		sessions:         make(map[string]*TLSSession),
		vulnerabilities:  make([]TLSVulnerability, 0),
		cipherIntel:      make(map[string]*CipherIntelligence),
		extensions:       make(map[string][]TLSExtension),
		expertLevel:      expertLevel,
		aggressiveMode:   false,
		certificateCache: make(map[string]*CapturedCertificate),
		vulnerabilityDB:  NewTLSVulnerabilityDB(),
	}

	// Initialize cipher intelligence database
	analyzer.initializeCipherIntelligence()

	return analyzer
}

// ProcessTLSPacket processes a TLS packet for intelligence extraction
func (ta *TLSAnalyzer) ProcessTLSPacket(packet gopacket.Packet) {
	fmt.Println("[DEBUG] TLS Analyzer ProcessTLSPacket() called")

	// Try to extract TLS layer first (for standard HTTPS ports)
	tlsLayer := packet.Layer(layers.LayerTypeTLS)
	if tlsLayer != nil {
		fmt.Println("[DEBUG] TLS layer found via gopacket, processing...")
		tls := tlsLayer.(*layers.TLS)
		ta.parseTLSRecordsFromBytes(packet, tls.Contents)
		return
	}

	fmt.Println("[DEBUG] No TLS layer found in packet")

	// **CRITICAL FIX:** Parse TLS directly from TCP payload for non-standard ports
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) >= 5 {
			// Check if this looks like TLS data
			recordType := tcp.Payload[0]
			if recordType >= 0x14 && recordType <= 0x17 && tcp.Payload[1] == 0x03 {
				fmt.Printf("[DEBUG] Found TLS data in TCP payload (type: 0x%02x), parsing manually\n", recordType)
				ta.parseTLSRecordsFromBytes(packet, tcp.Payload)
				return
			}
		}
	}

	fmt.Println("[DEBUG] No TLS data found in packet")
}

// parseTLSRecordsFromBytes manually parses TLS records from raw bytes
func (ta *TLSAnalyzer) parseTLSRecordsFromBytes(packet gopacket.Packet, data []byte) {
	offset := 0
	for offset+5 <= len(data) {
		contentType := data[offset]
		length := int(data[offset+3])<<8 | int(data[offset+4])

		if offset+5+length > len(data) {
			break
		}

		recordData := data[offset+5 : offset+5+length]

		switch contentType {
		case 22: // Handshake
			ta.processHandshakeRecord(packet, recordData)
		case 20: // Change Cipher Spec
			ta.processChangeCipherSpecBytes(packet, recordData)
		case 21: // Alert
			ta.processAlertBytes(packet, recordData)
		case 23: // Application Data
			ta.processApplicationDataBytes(packet, recordData)
		}

		offset += 5 + length
	}
}

// processHandshakeRecord processes TLS handshake messages
func (ta *TLSAnalyzer) processHandshakeRecord(packet gopacket.Packet, recordData []byte) {
	// Parse handshake message from raw data
	handshakeData := recordData
	if len(handshakeData) < 4 {
		return
	}

	msgType := handshakeData[0]
	fmt.Printf("[DEBUG] TLS Handshake message type: 0x%02x\n", msgType)

	switch msgType {
	case 1: // ClientHello
		ta.processClientHello(packet, handshakeData)
		fmt.Println("[DEBUG] Processing ClientHello")
	case 2: // ServerHello
		ta.processServerHello(packet, handshakeData)
		fmt.Println("[DEBUG] Processing ServerHello")
	case 11: // Certificate
		ta.processCertificateMessage(packet, handshakeData)
		fmt.Println("[DEBUG] Processing Certificate")
	case 14: // ServerHelloDone
		ta.processServerHelloDone(packet, handshakeData)
		fmt.Println("[DEBUG] Processing ServerHelloDone")
	case 16: // ClientKeyExchange
		ta.processClientKeyExchange(packet, handshakeData)
		fmt.Println("[DEBUG] Processing ClientKeyExchange")
	case 20: // Finished
		fmt.Println("[DEBUG] Processing Finished")
		ta.processFinished(packet, handshakeData)
	default:
		fmt.Printf("[DEBUG] Unknown handshake message type: 0x%02x\n", msgType)
	}
}

// processClientHello analyzes ClientHello message for intelligence
func (ta *TLSAnalyzer) processClientHello(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// Extract basic connection info
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	clientIP := networkLayer.NetworkFlow().Src()
	serverIP := networkLayer.NetworkFlow().Dst()
	serverPort := int(transportLayer.TransportFlow().Dst().Raw()[0])<<8 | int(transportLayer.TransportFlow().Dst().Raw()[1])

	// Parse ClientHello structure
	if len(data) < 38 {
		return
	}

	// Extract TLS version (bytes 4-5)
	clientVersion := fmt.Sprintf("0x%02x%02x", data[4], data[5])

	// Create handshake record
	handshake := TLSHandshake{
		ID:            fmt.Sprintf("%s:%d->%s:%d", clientIP, 0, serverIP, serverPort),
		ClientIP:      net.ParseIP(clientIP.String()),
		ServerIP:      net.ParseIP(serverIP.String()),
		ServerPort:    serverPort,
		StartTime:     packet.Metadata().Timestamp,
		ClientVersion: ta.translateTLSVersion(clientVersion),
	}

	// Extract and analyze extensions
	extensions := ta.parseClientHelloExtensions(data)
	handshake.ClientExtensions = extensions

	// Extract SNI
	for _, ext := range extensions {
		if ext.Name == "server_name_indication" {
			handshake.SNI = ext.Data
			break
		}
	}

	// Security analysis
	ta.analyzeClientHelloSecurity(&handshake, data)

	ta.handshakes = append(ta.handshakes, handshake)
	ta.handshakesAnalyzed++
}

// processServerHello analyzes ServerHello message
func (ta *TLSAnalyzer) processServerHello(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	if len(data) < 38 {
		return
	}

	// Extract TLS version and cipher suite
	serverVersion := fmt.Sprintf("0x%02x%02x", data[4], data[5])
	cipherSuite := fmt.Sprintf("0x%02x%02x", data[38], data[39])

	// Find matching handshake
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	serverIP := networkLayer.NetworkFlow().Src()
	clientIP := networkLayer.NetworkFlow().Dst()
	serverPort := int(transportLayer.TransportFlow().Src().Raw()[0])<<8 | int(transportLayer.TransportFlow().Src().Raw()[1])

	handshakeID := fmt.Sprintf("%s:%d->%s:%d", clientIP, 0, serverIP, serverPort)

	// Update existing handshake
	for i := range ta.handshakes {
		if ta.handshakes[i].ID == handshakeID {
			ta.handshakes[i].ServerVersion = ta.translateTLSVersion(serverVersion)
			ta.handshakes[i].NegotiatedVersion = ta.handshakes[i].ServerVersion
			ta.handshakes[i].CipherSuite = ta.translateCipherSuite(cipherSuite)

			// Security analysis
			ta.analyzeServerHelloSecurity(&ta.handshakes[i], data)

			break
		}
	}
}

// processCertificateMessage analyzes certificate message
func (ta *TLSAnalyzer) processCertificateMessage(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// Parse certificate chain from TLS message
	certificates := ta.parseCertificateChain(data)

	for _, certData := range certificates {
		cert := ta.analyzeCertificate(certData, packet)
		if cert != nil {
			ta.certificates = append(ta.certificates, *cert)
		}
	}
}

// analyzeCertificate performs comprehensive certificate security analysis
func (ta *TLSAnalyzer) analyzeCertificate(certData []byte, packet gopacket.Packet) *CapturedCertificate {
	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil
	}

	// Calculate fingerprints
	sha1Hash := sha1.Sum(certData)
	sha256Hash := sha256.Sum256(certData)

	captured := &CapturedCertificate{
		Fingerprint:     hex.EncodeToString(sha256Hash[:]),
		SHA1Fingerprint: hex.EncodeToString(sha1Hash[:]),
		SHA256Hash:      hex.EncodeToString(sha256Hash[:]),
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		SerialNumber:    cert.SerialNumber.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		KeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
		SignatureAlg:    cert.SignatureAlgorithm.String(),
		Extensions:      make(map[string]string),
		VulnCategories:  make([]string, 0),
		SecurityIssues:  make([]CertificateSecurityIssue, 0),
		AttackVectors:   make([]string, 0),
		ChainIssues:     make([]string, 0),
		FirstSeen:       packet.Metadata().Timestamp,
		LastSeen:        packet.Metadata().Timestamp,
	}

	// Extract key size
	captured.KeySize = ta.extractKeySize(cert)

	// Extract SANs
	captured.SANs = cert.DNSNames

	// Security analysis
	ta.performCertificateSecurityAnalysis(captured, cert)

	return captured
}

// performCertificateSecurityAnalysis performs comprehensive security analysis
func (ta *TLSAnalyzer) performCertificateSecurityAnalysis(captured *CapturedCertificate, cert *x509.Certificate) {
	// Check expiration
	now := time.Now()
	if cert.NotAfter.Before(now) {
		captured.IsExpired = true
		captured.SecurityIssues = append(captured.SecurityIssues, CertificateSecurityIssue{
			Type:        "expired",
			Severity:    "high",
			Description: "Certificate has expired",
			Impact:      "Connection security cannot be verified",
		})
		captured.AttackVectors = append(captured.AttackVectors, "certificate_expiration_bypass")
	}

	// Check expiring soon (30 days)
	if cert.NotAfter.Before(now.Add(30*24*time.Hour)) && !captured.IsExpired {
		captured.IsExpiringSoon = true
		captured.SecurityIssues = append(captured.SecurityIssues, CertificateSecurityIssue{
			Type:        "expiring_soon",
			Severity:    "medium",
			Description: "Certificate expires within 30 days",
			Impact:      "Service interruption risk",
		})
	}

	// Check self-signed
	if cert.Subject.String() == cert.Issuer.String() {
		captured.IsSelfSigned = true
		captured.SecurityIssues = append(captured.SecurityIssues, CertificateSecurityIssue{
			Type:        "self_signed",
			Severity:    "medium",
			Description: "Certificate is self-signed",
			Impact:      "No trusted CA validation",
		})
		captured.AttackVectors = append(captured.AttackVectors, "self_signed_mitm")
		captured.MITMOpportunity = true
	}

	// Check weak key
	if captured.KeySize < 2048 && captured.KeyAlgorithm == "RSA" {
		captured.IsWeakKey = true
		captured.SecurityIssues = append(captured.SecurityIssues, CertificateSecurityIssue{
			Type:        "weak_key",
			Severity:    "high",
			Description: fmt.Sprintf("Weak RSA key size: %d bits", captured.KeySize),
			Impact:      "Cryptographic strength insufficient",
		})
		captured.AttackVectors = append(captured.AttackVectors, "weak_key_factorization")
	}

	// Check weak signature algorithm
	weakSigAlgs := []string{"MD5", "SHA1"}
	for _, weak := range weakSigAlgs {
		if strings.Contains(captured.SignatureAlg, weak) {
			captured.IsWeakSignature = true
			captured.SecurityIssues = append(captured.SecurityIssues, CertificateSecurityIssue{
				Type:        "weak_signature",
				Severity:    "high",
				Description: fmt.Sprintf("Weak signature algorithm: %s", captured.SignatureAlg),
				Impact:      "Signature forgery possible",
			})
			captured.AttackVectors = append(captured.AttackVectors, "signature_forgery")
			break
		}
	}

	// Calculate risk score
	captured.RiskScore = ta.calculateCertificateRiskScore(captured)

	// Add to vulnerability categories
	if captured.IsExpired || captured.IsWeakKey || captured.IsWeakSignature {
		captured.VulnCategories = append(captured.VulnCategories, "certificate_weakness")
	}
	if captured.IsSelfSigned {
		captured.VulnCategories = append(captured.VulnCategories, "trust_issues")
	}
}

// initializeCipherIntelligence initializes the cipher intelligence database
func (ta *TLSAnalyzer) initializeCipherIntelligence() {
	// Export-grade ciphers (extremely weak)
	ta.addCipherIntelligence("TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherIntelligence{
		Name:              "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		Protocol:          "TLS",
		KeyExchange:       "RSA",
		Authentication:    "RSA",
		Encryption:        "RC4_40",
		MAC:               "MD5",
		SecurityLevel:     "insecure",
		KeyLength:         40,
		IsDeprecated:      true,
		IsExportGrade:     true,
		VulnerableTo:      []string{"FREAK", "export_cipher_attack", "rc4_biases", "md5_collision"},
		RecommendedAction: "Disable immediately - critical security risk",
		AEAD:              false,
		PFS:               false,
	})

	// RC4 ciphers (weak)
	ta.addCipherIntelligence("TLS_RSA_WITH_RC4_128_SHA", CipherIntelligence{
		Name:              "TLS_RSA_WITH_RC4_128_SHA",
		Protocol:          "TLS",
		KeyExchange:       "RSA",
		Authentication:    "RSA",
		Encryption:        "RC4_128",
		MAC:               "SHA",
		SecurityLevel:     "weak",
		KeyLength:         128,
		IsDeprecated:      true,
		IsExportGrade:     false,
		VulnerableTo:      []string{"rc4_biases", "bar_mitzvah_attack"},
		RecommendedAction: "Replace with AEAD cipher",
		AEAD:              false,
		PFS:               false,
	})

	// 3DES ciphers (weak)
	ta.addCipherIntelligence("TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherIntelligence{
		Name:              "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:          "TLS",
		KeyExchange:       "RSA",
		Authentication:    "RSA",
		Encryption:        "3DES_EDE_CBC",
		MAC:               "SHA",
		SecurityLevel:     "weak",
		KeyLength:         168,
		IsDeprecated:      true,
		IsExportGrade:     false,
		VulnerableTo:      []string{"sweet32", "cbc_padding_oracle"},
		RecommendedAction: "Upgrade to AES-GCM",
		AEAD:              false,
		PFS:               false,
	})

	// Modern secure ciphers
	ta.addCipherIntelligence("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherIntelligence{
		Name:              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:          "TLS",
		KeyExchange:       "ECDHE",
		Authentication:    "RSA",
		Encryption:        "AES_256_GCM",
		MAC:               "SHA384",
		SecurityLevel:     "secure",
		KeyLength:         256,
		IsDeprecated:      false,
		IsExportGrade:     false,
		VulnerableTo:      []string{},
		RecommendedAction: "Secure - no action needed",
		AEAD:              true,
		PFS:               true,
	})

	// ChaCha20-Poly1305
	ta.addCipherIntelligence("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", CipherIntelligence{
		Name:              "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		Protocol:          "TLS",
		KeyExchange:       "ECDHE",
		Authentication:    "RSA",
		Encryption:        "CHACHA20_POLY1305",
		MAC:               "SHA256",
		SecurityLevel:     "secure",
		KeyLength:         256,
		IsDeprecated:      false,
		IsExportGrade:     false,
		VulnerableTo:      []string{},
		RecommendedAction: "Secure - excellent choice",
		AEAD:              true,
		PFS:               true,
	})
}

// addCipherIntelligence adds cipher intelligence to the database
func (ta *TLSAnalyzer) addCipherIntelligence(name string, intel CipherIntelligence) {
	ta.cipherIntel[name] = &intel
}

// GetTLSIntelligence returns comprehensive TLS intelligence for attack context
func (ta *TLSAnalyzer) GetTLSIntelligence() TLSIntelligence {
	ta.mu.RLock()
	defer ta.mu.RUnlock()

	return TLSIntelligence{
		Certificates:         ta.certificates,
		Handshakes:           ta.handshakes,
		Sessions:             ta.convertSessionsToSlice(),
		Vulnerabilities:      ta.vulnerabilities,
		WeakCiphers:          ta.getWeakCiphers(),
		AttackSurface:        ta.generateAttackSurface(),
		SecurityScore:        ta.calculateOverallSecurityScore(),
		Recommendations:      ta.generateSecurityRecommendations(),
		LastAnalyzed:         time.Now(),
		TotalHandshakes:      ta.handshakesAnalyzed,
		VulnerabilitiesFound: ta.vulnerabilitiesFound,
	}
}

// Helper methods

func (ta *TLSAnalyzer) translateTLSVersion(version string) string {
	versions := map[string]string{
		"0x0300": "SSL 3.0",
		"0x0301": "TLS 1.0",
		"0x0302": "TLS 1.1",
		"0x0303": "TLS 1.2",
		"0x0304": "TLS 1.3",
	}

	if name, exists := versions[version]; exists {
		return name
	}
	return version
}

func (ta *TLSAnalyzer) translateCipherSuite(suite string) string {
	// Map cipher suite codes to names
	suites := map[string]string{
		"0x0004": "TLS_RSA_WITH_RC4_128_MD5",
		"0x0005": "TLS_RSA_WITH_RC4_128_SHA",
		"0x000A": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"0x002F": "TLS_RSA_WITH_AES_128_CBC_SHA",
		"0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
		"0x009C": "TLS_RSA_WITH_AES_128_GCM_SHA256",
		"0x009D": "TLS_RSA_WITH_AES_256_GCM_SHA384",
		"0xC013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"0xC014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"0xC027": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"0xC028": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"0xCCA8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	if name, exists := suites[suite]; exists {
		return name
	}
	return suite
}

func (ta *TLSAnalyzer) extractKeySize(cert *x509.Certificate) int {
	// Extract key size based on algorithm
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// Implementation would extract RSA key size
		return 2048 // Default
	case x509.ECDSA:
		// Implementation would extract ECDSA key size
		return 256 // Default
	default:
		return 0
	}
}

func (ta *TLSAnalyzer) calculateCertificateRiskScore(cert *CapturedCertificate) float64 {
	score := 0.0

	if cert.IsExpired {
		score += 40.0
	}
	if cert.IsExpiringSoon {
		score += 15.0
	}
	if cert.IsSelfSigned {
		score += 25.0
	}
	if cert.IsWeakKey {
		score += 30.0
	}
	if cert.IsWeakSignature {
		score += 35.0
	}

	return minF64(100.0, score)
}

// Additional helper methods would be implemented here...

// Placeholder implementations for complex parsing methods
func (ta *TLSAnalyzer) parseClientHelloExtensions(data []byte) []TLSExtension {
	extensions := make([]TLSExtension, 0)

	if len(data) < 43 {
		return extensions
	}

	// ClientHello structure:
	// [0-3]: handshake header
	// [4-5]: client version
	// [6-37]: random (32 bytes)
	// [38]: session ID length

	sessionIDLen := int(data[38])
	offset := 39 + sessionIDLen

	if offset+2 >= len(data) {
		return extensions
	}

	// Cipher suites length + cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 >= len(data) {
		return extensions
	}

	// Compression methods length + compression methods
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	if offset+2 >= len(data) {
		return extensions
	}

	// Extensions length
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+extensionsLen > len(data) {
		return extensions
	}

	// Parse individual extensions
	endOffset := offset + extensionsLen
	for offset < endOffset && offset+4 <= len(data) {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+extLen > len(data) {
			break
		}

		extData := data[offset : offset+extLen]
		extension := TLSExtension{
			Type: extType,
			Name: ta.getExtensionName(extType),
			Data: ta.parseExtensionData(extType, extData),
		}

		extensions = append(extensions, extension)
		offset += extLen
	}

	return extensions
}

func (ta *TLSAnalyzer) getExtensionName(extType uint16) string {
	extensionNames := map[uint16]string{
		0:  "server_name_indication",
		1:  "max_fragment_length",
		5:  "status_request",
		10: "supported_groups",
		11: "ec_point_formats",
		13: "signature_algorithms",
		16: "application_layer_protocol_negotiation",
		18: "signed_certificate_timestamp",
		21: "padding",
		23: "session_ticket",
		35: "session_ticket_tls",
		43: "supported_versions",
		51: "key_share",
	}

	if name, exists := extensionNames[extType]; exists {
		return name
	}
	return fmt.Sprintf("unknown_%d", extType)
}

func (ta *TLSAnalyzer) parseExtensionData(extType uint16, data []byte) string {
	switch extType {
	case 0: // SNI
		return ta.parseSNIExtension(data)
	case 16: // ALPN
		return ta.parseALPNExtension(data)
	default:
		return hex.EncodeToString(data)
	}
}

func (ta *TLSAnalyzer) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI extension structure:
	// [0-1]: server name list length
	// [2]: name type (0 = hostname)
	// [3-4]: name length
	// [5+]: hostname

	nameLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+nameLen {
		return ""
	}

	return string(data[5 : 5+nameLen])
}

func (ta *TLSAnalyzer) parseALPNExtension(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	// ALPN extension structure:
	// [0-1]: protocol list length
	// [2]: first protocol length
	// [3+]: first protocol name

	protocolLen := int(data[2])
	if len(data) < 3+protocolLen {
		return ""
	}

	return string(data[3 : 3+protocolLen])
}

func (ta *TLSAnalyzer) parseCertificateChain(data []byte) [][]byte {
	certificates := make([][]byte, 0)

	if len(data) < 7 {
		return certificates
	}

	// TLS Certificate message structure:
	// [0-2]: message length (3 bytes)
	// [3-5]: certificates length (3 bytes)
	// [6+]: certificate entries

	certsTotalLen := int(data[3])<<16 | int(data[4])<<8 | int(data[5])
	if len(data) < 6+certsTotalLen {
		return certificates
	}

	offset := 6 // Start after certificates length

	for offset < 6+certsTotalLen && offset+3 <= len(data) {
		// Each certificate entry:
		// [0-2]: certificate length (3 bytes)
		// [3+]: certificate data

		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > len(data) {
			break
		}

		certData := make([]byte, certLen)
		copy(certData, data[offset:offset+certLen])
		certificates = append(certificates, certData)

		offset += certLen
	}

	return certificates
}

func (ta *TLSAnalyzer) analyzeClientHelloSecurity(handshake *TLSHandshake, data []byte) {
	vulnerabilities := make([]string, 0)
	attackSurface := make([]string, 0)
	riskScore := 0.0

	// Analyze TLS version
	if handshake.ClientVersion == "SSL 3.0" {
		vulnerabilities = append(vulnerabilities, "sslv3_poodle")
		attackSurface = append(attackSurface, "ssl3_downgrade")
		riskScore += 30.0
	}

	if handshake.ClientVersion == "TLS 1.0" {
		vulnerabilities = append(vulnerabilities, "tls10_beast")
		attackSurface = append(attackSurface, "tls10_downgrade")
		riskScore += 20.0
	}

	if handshake.ClientVersion == "TLS 1.1" {
		vulnerabilities = append(vulnerabilities, "tls11_lucky13")
		attackSurface = append(attackSurface, "tls11_downgrade")
		riskScore += 15.0
	}

	// Analyze supported extensions for security features
	hasSecureRenegotiation := false
	hasSessionTicket := false

	for _, ext := range handshake.ClientExtensions {
		switch ext.Name {
		case "renegotiation_info":
			hasSecureRenegotiation = true
		case "session_ticket":
			hasSessionTicket = true
			handshake.SessionTickets = true
		case "heartbeat":
			vulnerabilities = append(vulnerabilities, "heartbleed_risk")
			attackSurface = append(attackSurface, "heartbeat_exploit")
			riskScore += 25.0
		}
	}

	if !hasSecureRenegotiation {
		vulnerabilities = append(vulnerabilities, "insecure_renegotiation")
		attackSurface = append(attackSurface, "renegotiation_attack")
		riskScore += 10.0
	}

	if hasSessionTicket {
		attackSurface = append(attackSurface, "session_ticket_replay")
		riskScore += 5.0
	}

	// Check for compression support (CRIME attack)
	if len(data) >= 40 {
		sessionIDLen := int(data[38])
		offset := 39 + sessionIDLen + 2 // Skip to compression methods

		if offset < len(data) {
			compressionLen := int(data[offset])
			if compressionLen > 1 { // More than just null compression
				vulnerabilities = append(vulnerabilities, "crime_compression")
				attackSurface = append(attackSurface, "compression_attack")
				riskScore += 15.0
			}
		}
	}

	handshake.VulnerableToAttacks = vulnerabilities
	handshake.AttackSurface = attackSurface
	handshake.RiskScore = riskScore
}

func (ta *TLSAnalyzer) analyzeServerHelloSecurity(handshake *TLSHandshake, _ []byte) {
	vulnerabilities := make([]string, 0)
	attackSurface := make([]string, 0)
	riskScore := handshake.RiskScore // Start with client risk score

	// Analyze negotiated cipher suite
	if handshake.CipherSuite != "" {
		cipherIntel := ta.analyzeCipherSuiteSecurity(handshake.CipherSuite)
		if cipherIntel != nil {
			switch cipherIntel.SecurityLevel {
			case "insecure":
				handshake.WeakCipher = true
				riskScore += 40.0
				vulnerabilities = append(vulnerabilities, cipherIntel.VulnerableTo...)
				attackSurface = append(attackSurface, "cipher_exploitation")
			case "weak":
				handshake.WeakCipher = true
				riskScore += 25.0
				vulnerabilities = append(vulnerabilities, cipherIntel.VulnerableTo...)
				attackSurface = append(attackSurface, "weak_cipher_attack")
			case "export":
				handshake.WeakCipher = true
				riskScore += 50.0
				vulnerabilities = append(vulnerabilities, "freak_attack", "logjam_attack")
				attackSurface = append(attackSurface, "export_grade_exploitation")
			}

			handshake.PerfectForwardSecrecy = cipherIntel.PFS
			if !cipherIntel.PFS {
				vulnerabilities = append(vulnerabilities, "no_perfect_forward_secrecy")
				attackSurface = append(attackSurface, "key_compromise_risk")
				riskScore += 10.0
			}
		}
	}

	// Analyze version downgrade
	if handshake.ClientVersion != handshake.ServerVersion {
		handshake.DowngradeDetected = true
		vulnerabilities = append(vulnerabilities, "version_downgrade")
		attackSurface = append(attackSurface, "downgrade_attack")
		riskScore += 20.0
	}

	// Analyze server extensions
	hasSecureRenegotiation := false
	hasSessionTicket := false

	for _, ext := range handshake.ServerExtensions {
		switch ext.Name {
		case "renegotiation_info":
			hasSecureRenegotiation = true
		case "session_ticket":
			hasSessionTicket = true
			handshake.SessionTickets = true
			attackSurface = append(attackSurface, "session_ticket_manipulation")
		case "heartbeat":
			vulnerabilities = append(vulnerabilities, "heartbleed_vulnerable")
			attackSurface = append(attackSurface, "heartbleed_exploit")
			riskScore += 30.0
		}
	}

	if !hasSecureRenegotiation {
		handshake.SupportsRenegotiation = false
		vulnerabilities = append(vulnerabilities, "renegotiation_vulnerability")
		attackSurface = append(attackSurface, "mitm_renegotiation")
		riskScore += 15.0
	} else {
		handshake.SupportsRenegotiation = true
	}

	// Session resumption analysis
	if hasSessionTicket {
		handshake.SessionResumption = true
		attackSurface = append(attackSurface, "session_hijacking", "session_fixation")
		riskScore += 5.0
	}

	// Compression analysis (CRIME/BREACH)
	if handshake.CompressionMethod != "" && handshake.CompressionMethod != "null" {
		vulnerabilities = append(vulnerabilities, "crime_breach_compression")
		attackSurface = append(attackSurface, "compression_oracle")
		riskScore += 20.0
	}

	// Update handshake with analysis results
	if len(vulnerabilities) > 0 {
		handshake.VulnerableToAttacks = append(handshake.VulnerableToAttacks, vulnerabilities...)
	}
	if len(attackSurface) > 0 {
		handshake.AttackSurface = append(handshake.AttackSurface, attackSurface...)
	}
	handshake.RiskScore = minF64(100.0, riskScore)
}

func (ta *TLSAnalyzer) analyzeCipherSuiteSecurity(cipherSuite string) *CipherIntelligence {
	if intel, exists := ta.cipherIntel[cipherSuite]; exists {
		return intel
	}

	// Try to translate cipher suite code to name and lookup
	cipherName := ta.translateCipherSuite(cipherSuite)
	if intel, exists := ta.cipherIntel[cipherName]; exists {
		return intel
	}

	return nil
}

func (ta *TLSAnalyzer) convertSessionsToSlice() []TLSSession {
	sessions := make([]TLSSession, 0, len(ta.sessions))
	for _, session := range ta.sessions {
		sessions = append(sessions, *session)
	}
	return sessions
}

func (ta *TLSAnalyzer) getWeakCiphers() []string {
	weak := make([]string, 0)
	for name, intel := range ta.cipherIntel {
		if intel.SecurityLevel == "weak" || intel.SecurityLevel == "insecure" {
			weak = append(weak, name)
		}
	}
	return weak
}

func (ta *TLSAnalyzer) generateAttackSurface() []string {
	surface := make([]string, 0)

	// Add attack vectors based on findings
	for _, cert := range ta.certificates {
		surface = append(surface, cert.AttackVectors...)
	}

	return surface
}

func (ta *TLSAnalyzer) calculateOverallSecurityScore() float64 {
	if len(ta.certificates) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, cert := range ta.certificates {
		totalScore += cert.RiskScore
	}

	return 100.0 - (totalScore / float64(len(ta.certificates)))
}

func (ta *TLSAnalyzer) generateSecurityRecommendations() []string {
	recommendations := make([]string, 0)

	// Generate recommendations based on findings
	if ta.vulnerabilitiesFound > 0 {
		recommendations = append(recommendations, "Address identified TLS vulnerabilities")
	}

	if ta.weakCiphersDetected > 0 {
		recommendations = append(recommendations, "Disable weak cipher suites")
	}

	return recommendations
}

func (ta *TLSAnalyzer) processChangeCipherSpecBytes(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	if len(data) < 1 {
		// Invalid Change Cipher Spec message
		vuln := TLSVulnerability{
			Type:        "invalid_change_cipher_spec",
			Name:        "Invalid Change Cipher Spec",
			Severity:    "medium",
			Category:    "protocol",
			Description: "Invalid Change Cipher Spec message received",
			Impact:      "Potential protocol violation or attack attempt",
			Evidence:    fmt.Sprintf("Message length: %d bytes (expected >= 1)", len(data)),
			Remediation: "Investigate protocol compliance",
			FirstSeen:   packet.Metadata().Timestamp,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
		return
	}

	// Validate Change Cipher Spec message content
	if data[0] != 1 {
		// Invalid Change Cipher Spec value
		vuln := TLSVulnerability{
			Type:        "malformed_change_cipher_spec",
			Name:        "Malformed Change Cipher Spec",
			Severity:    "high",
			Category:    "protocol",
			Description: fmt.Sprintf("Invalid Change Cipher Spec value: %d (expected 1)", data[0]),
			Impact:      "Protocol violation - possible attack or implementation bug",
			Evidence:    fmt.Sprintf("CCS value: 0x%02x", data[0]),
			Remediation: "Check for TLS implementation vulnerabilities",
			FirstSeen:   packet.Metadata().Timestamp,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
		return
	}

	// Analyze timing and context
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	// Determine if this is from client or server
	isFromClient := false
	clientIP := networkLayer.NetworkFlow().Src()
	serverIP := networkLayer.NetworkFlow().Dst()
	serverPort := int(transportLayer.TransportFlow().Dst().Raw()[0])<<8 | int(transportLayer.TransportFlow().Dst().Raw()[1])

	// Check if this matches a known handshake pattern
	var handshakeID string
	if serverPort == 8080 || serverPort == 443 || serverPort == 8443 {
		// This is client -> server
		isFromClient = true
		handshakeID = fmt.Sprintf("%s:%d->%s:%d", clientIP, 0, serverIP, serverPort)
	} else {
		// This is server -> client
		handshakeID = fmt.Sprintf("%s:%d->%s:%d", serverIP, 0, clientIP, serverPort)
	}

	// Find matching handshake and update it
	for i := range ta.handshakes {
		if ta.handshakes[i].ID == handshakeID {
			if isFromClient {
				ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "client_cipher_change")
			} else {
				ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "server_cipher_change")
			}

			// Check timing since handshake start
			elapsed := packet.Metadata().Timestamp.Sub(ta.handshakes[i].StartTime)

			if elapsed < 100*time.Millisecond {
				// Very fast cipher change - suspicious
				vuln := TLSVulnerability{
					Type:        "premature_cipher_change",
					Name:        "Premature Cipher Change",
					Severity:    "medium",
					Category:    "protocol",
					Description: fmt.Sprintf("Change Cipher Spec received too quickly: %v", elapsed),
					Impact:      "Potential bypass of handshake validation",
					Evidence:    fmt.Sprintf("Time since handshake start: %v", elapsed),
					Remediation: "Validate proper handshake sequence",
					FirstSeen:   packet.Metadata().Timestamp,
					Occurrences: 1,
				}
				ta.vulnerabilities = append(ta.vulnerabilities, vuln)
				ta.vulnerabilitiesFound++
			}

			if elapsed > 30*time.Second {
				// Very slow cipher change - potential attack
				vuln := TLSVulnerability{
					Type:        "delayed_cipher_change",
					Name:        "Delayed Cipher Change",
					Severity:    "low",
					Category:    "protocol",
					Description: fmt.Sprintf("Change Cipher Spec received after long delay: %v", elapsed),
					Impact:      "Potential DoS or timing attack",
					Evidence:    fmt.Sprintf("Time since handshake start: %v", elapsed),
					Remediation: "Monitor for timing-based attacks",
					FirstSeen:   packet.Metadata().Timestamp,
					Occurrences: 1,
				}
				ta.vulnerabilities = append(ta.vulnerabilities, vuln)
				ta.vulnerabilitiesFound++
			}

			break
		}
	}

	// Check for multiple Change Cipher Spec messages (potential attack)
	ta.detectMultipleCipherChanges(packet)
}

func (ta *TLSAnalyzer) detectMultipleCipherChanges(packet gopacket.Packet) {
	// Count Change Cipher Spec messages in short time window
	currentTime := packet.Metadata().Timestamp
	recentCCS := 0

	for _, vuln := range ta.vulnerabilities {
		if vuln.Type == "change_cipher_spec_received" &&
			currentTime.Sub(vuln.FirstSeen) < 5*time.Second {
			recentCCS++
		}
	}

	if recentCCS > 1 {
		// Multiple CCS in short time - potential attack
		vuln := TLSVulnerability{
			Type:        "multiple_cipher_changes",
			Name:        "Multiple Change Cipher Spec Messages",
			Severity:    "high",
			Category:    "protocol",
			Description: fmt.Sprintf("Multiple Change Cipher Spec messages in short timeframe: %d", recentCCS+1),
			Impact:      "Potential CCS injection attack or protocol confusion",
			Evidence:    fmt.Sprintf("CCS count in 5s window: %d", recentCCS+1),
			Remediation: "Check for CCS injection vulnerabilities",
			FirstSeen:   currentTime,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
	}

	// Track this CCS message
	vuln := TLSVulnerability{
		Type:        "change_cipher_spec_received",
		Name:        "Change Cipher Spec Processed",
		Severity:    "info",
		Category:    "protocol",
		Description: "Valid Change Cipher Spec message processed",
		Impact:      "Normal TLS handshake progression",
		Evidence:    "CCS value: 0x01",
		Remediation: "No action required",
		FirstSeen:   currentTime,
		Occurrences: 1,
	}
	ta.vulnerabilities = append(ta.vulnerabilities, vuln)
}

func (ta *TLSAnalyzer) processAlertBytes(packet gopacket.Packet, data []byte) {
	// Process TLS Alert record
	ta.mu.Lock()
	defer ta.mu.Unlock()

	if len(data) >= 2 {
		alertLevel := data[0] // 1 = warning, 2 = fatal
		alertDesc := data[1]  // Alert description

		// Create vulnerability for fatal alerts
		if alertLevel == 2 {
			vuln := TLSVulnerability{
				Type:        "tls_alert",
				Name:        fmt.Sprintf("TLS Fatal Alert: %d", alertDesc),
				Severity:    "medium",
				Category:    "protocol",
				Description: fmt.Sprintf("TLS fatal alert received: level=%d, description=%d", alertLevel, alertDesc),
				Impact:      "Connection terminated due to TLS error",
				Evidence:    fmt.Sprintf("Alert data: %02x %02x", alertLevel, alertDesc),
				Remediation: "Investigate TLS configuration and certificate issues",
				FirstSeen:   packet.Metadata().Timestamp,
				Occurrences: 1,
			}
			ta.vulnerabilities = append(ta.vulnerabilities, vuln)
			ta.vulnerabilitiesFound++
		}
	}
}

func (ta *TLSAnalyzer) processApplicationDataBytes(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	dataLength := len(data)
	timestamp := packet.Metadata().Timestamp

	// Analyze application data patterns for security issues
	if dataLength > 16384 {
		// Large data transfer - potential data exfiltration
		vuln := TLSVulnerability{
			Type:        "large_data_transfer",
			Name:        "Suspicious Large TLS Record",
			Severity:    "medium",
			Category:    "protocol",
			Description: fmt.Sprintf("Unusually large TLS application data record: %d bytes", dataLength),
			Impact:      "Potential data exfiltration or DoS attack",
			Evidence:    fmt.Sprintf("Record size: %d bytes (>16KB)", dataLength),
			Remediation: "Monitor for data exfiltration patterns",
			FirstSeen:   timestamp,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
	}

	if dataLength < 10 && dataLength > 0 {
		// Very small data - potential heartbeat or timing attack
		vuln := TLSVulnerability{
			Type:        "small_data_pattern",
			Name:        "Suspicious Small TLS Record",
			Severity:    "low",
			Category:    "protocol",
			Description: fmt.Sprintf("Very small TLS application data: %d bytes", dataLength),
			Impact:      "Potential timing attack or heartbeat abuse",
			Evidence:    fmt.Sprintf("Record size: %d bytes (<10 bytes)", dataLength),
			Remediation: "Investigate small record patterns",
			FirstSeen:   timestamp,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
	}

	// Pattern analysis for potential attacks
	if dataLength == 1 {
		// Single byte records can indicate heartbeat or timing probes
		vuln := TLSVulnerability{
			Type:        "single_byte_probe",
			Name:        "Single Byte TLS Record",
			Severity:    "medium",
			Category:    "protocol",
			Description: "Single byte TLS record detected - potential heartbeat probe",
			Impact:      "Possible heartbleed or timing attack reconnaissance",
			Evidence:    "1-byte application data record",
			Remediation: "Check for heartbleed vulnerability",
			FirstSeen:   timestamp,
			Occurrences: 1,
		}
		ta.vulnerabilities = append(ta.vulnerabilities, vuln)
		ta.vulnerabilitiesFound++
	}
}

func (ta *TLSAnalyzer) processServerHelloDone(packet gopacket.Packet, _ []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// ServerHelloDone marks end of server hello phase
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	serverIP := networkLayer.NetworkFlow().Src()
	clientIP := networkLayer.NetworkFlow().Dst()
	serverPort := int(transportLayer.TransportFlow().Src().Raw()[0])<<8 | int(transportLayer.TransportFlow().Src().Raw()[1])

	handshakeID := fmt.Sprintf("%s:%d->%s:%d", clientIP, 0, serverIP, serverPort)

	// Find and update handshake progression
	for i := range ta.handshakes {
		if ta.handshakes[i].ID == handshakeID {
			// Mark server hello phase complete
			ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "server_hello_complete")

			// Analyze handshake timing for potential issues
			elapsed := packet.Metadata().Timestamp.Sub(ta.handshakes[i].StartTime)
			if elapsed > 5*time.Second {
				// Slow handshake - potential DoS or processing issue
				vuln := TLSVulnerability{
					Type:        "slow_handshake",
					Name:        "Slow TLS Handshake",
					Severity:    "low",
					Category:    "protocol",
					Description: fmt.Sprintf("TLS handshake taking unusually long: %v", elapsed),
					Impact:      "Potential DoS or server processing issue",
					Evidence:    fmt.Sprintf("Handshake duration: %v", elapsed),
					Remediation: "Investigate server performance",
					FirstSeen:   packet.Metadata().Timestamp,
					Occurrences: 1,
				}
				ta.vulnerabilities = append(ta.vulnerabilities, vuln)
				ta.vulnerabilitiesFound++
			}
			break
		}
	}
}

func (ta *TLSAnalyzer) processClientKeyExchange(packet gopacket.Packet, data []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	clientIP := networkLayer.NetworkFlow().Src()
	serverIP := networkLayer.NetworkFlow().Dst()
	serverPort := int(transportLayer.TransportFlow().Dst().Raw()[0])<<8 | int(transportLayer.TransportFlow().Dst().Raw()[1])

	handshakeID := fmt.Sprintf("%s:%d->%s:%d", clientIP, 0, serverIP, serverPort)

	// Find matching handshake for key exchange analysis
	for i := range ta.handshakes {
		if ta.handshakes[i].ID == handshakeID {
			// Analyze key exchange method
			if len(data) > 0 {
				// Check for weak key exchange patterns
				if len(data) < 48 { // Unusually short key exchange
					vuln := TLSVulnerability{
						Type:        "weak_key_exchange",
						Name:        "Weak Key Exchange",
						Severity:    "high",
						Category:    "protocol",
						Description: fmt.Sprintf("Unusually short key exchange data: %d bytes", len(data)),
						Impact:      "Potential weak key generation or export-grade cryptography",
						Evidence:    fmt.Sprintf("Key exchange size: %d bytes", len(data)),
						Remediation: "Ensure strong key exchange mechanisms",
						FirstSeen:   packet.Metadata().Timestamp,
						Occurrences: 1,
					}
					ta.vulnerabilities = append(ta.vulnerabilities, vuln)
					ta.vulnerabilitiesFound++
				}

				// Check for RSA key exchange (no PFS)
				if strings.Contains(ta.handshakes[i].CipherSuite, "RSA") && !strings.Contains(ta.handshakes[i].CipherSuite, "ECDHE") {
					ta.handshakes[i].PerfectForwardSecrecy = false
					ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "rsa_key_exchange_no_pfs")
				}

				ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "key_exchange_analysis")
			}
			break
		}
	}
}

func (ta *TLSAnalyzer) processFinished(packet gopacket.Packet, _ []byte) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer != nil && transportLayer != nil {
		// Find and update corresponding handshake
		for i := range ta.handshakes {
			if ta.handshakes[i].Duration == 0 {
				ta.handshakes[i].Duration = packet.Metadata().Timestamp.Sub(ta.handshakes[i].StartTime)

				// Mark handshake as complete
				ta.handshakes[i].AttackSurface = append(ta.handshakes[i].AttackSurface, "handshake_complete")

				// Generate session if applicable
				if ta.handshakes[i].SessionTickets {
					sessionID := fmt.Sprintf("session_%d", packet.Metadata().Timestamp.Unix())
					session := &TLSSession{
						SessionID:      sessionID,
						ServerName:     ta.handshakes[i].SNI,
						CipherSuite:    ta.handshakes[i].CipherSuite,
						SessionTicket:  fmt.Sprintf("ticket_%s", sessionID),
						IsReusable:     true,
						HijackPossible: ta.handshakes[i].WeakCipher || ta.handshakes[i].RiskScore > 50,
						AttackVectors:  []string{"session_replay", "session_hijacking"},
						Metadata:       map[string]string{"handshake_id": ta.handshakes[i].ID},
					}
					ta.sessions[sessionID] = session
				}
				break
			}
		}
	}
}

// NewTLSVulnerabilityDB creates a new vulnerability database
func NewTLSVulnerabilityDB() *TLSVulnerabilityDB {
	return &TLSVulnerabilityDB{
		cipherVulns:      make(map[string][]TLSVulnerability),
		protocolVulns:    make(map[string][]TLSVulnerability),
		extensionVulns:   make(map[string][]TLSVulnerability),
		certificateVulns: make(map[string][]TLSVulnerability),
		lastUpdated:      time.Now(),
	}
}

func minF64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// TLSIntelligence represents the complete TLS intelligence for discovery.json
type TLSIntelligence struct {
	Certificates         []CapturedCertificate `json:"certificates"`
	Handshakes           []TLSHandshake        `json:"handshakes"`
	Sessions             []TLSSession          `json:"sessions"`
	Vulnerabilities      []TLSVulnerability    `json:"vulnerabilities"`
	WeakCiphers          []string              `json:"weak_ciphers"`
	AttackSurface        []string              `json:"attack_surface"`
	SecurityScore        float64               `json:"security_score"`
	Recommendations      []string              `json:"recommendations"`
	LastAnalyzed         time.Time             `json:"last_analyzed"`
	TotalHandshakes      int                   `json:"total_handshakes"`
	VulnerabilitiesFound int                   `json:"vulnerabilities_found"`
}
