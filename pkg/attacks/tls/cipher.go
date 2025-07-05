package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// CipherTester handles cipher suite security testing
type CipherTester struct {
	config *config.TLSAttackConfig
	target *config.TargetConfig
	host   string
	port   string

	// Results tracking
	mu              sync.RWMutex
	testsExecuted   int
	cipherResults   []CipherTestResult
	vulnerabilities []TLSVulnerability
}

// NewCipherTester creates a new cipher suite tester
func NewCipherTester(tlsConfig *config.TLSAttackConfig, targetConfig *config.TargetConfig) (*CipherTester, error) {
	// Parse target URL to extract host and port
	targetURL, err := url.Parse(targetConfig.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	host := targetURL.Hostname()
	port := targetURL.Port()
	if port == "" {
		if targetURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return &CipherTester{
		config: tlsConfig,
		target: targetConfig,
		host:   host,
		port:   port,
	}, nil
}

// TestCipherSuites performs comprehensive cipher suite testing
func (ct *CipherTester) TestCipherSuites(ctx context.Context) error {
	if !ct.config.TestCipherSuites {
		return nil
	}

	// Test for weak cipher suites
	if err := ct.testWeakCipherSuites(ctx); err != nil {
		return fmt.Errorf("weak cipher testing failed: %w", err)
	}

	// Test for export-grade cipher suites
	if err := ct.testExportCipherSuites(ctx); err != nil {
		return fmt.Errorf("export cipher testing failed: %w", err)
	}

	// Test cipher suite preference
	if err := ct.testCipherSuitePreference(ctx); err != nil {
		return fmt.Errorf("cipher preference testing failed: %w", err)
	}

	// Test supported secure ciphers
	if err := ct.testSecureCipherSuites(ctx); err != nil {
		return fmt.Errorf("secure cipher testing failed: %w", err)
	}

	return nil
}

// testWeakCipherSuites tests for support of weak/deprecated cipher suites
func (ct *CipherTester) testWeakCipherSuites(ctx context.Context) error {
	for _, cipherName := range WeakCipherSuites {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cipherSuite := ct.getCipherSuiteByName(cipherName)
		if cipherSuite == 0 {
			continue // Skip unknown cipher suites
		}

		result := ct.testSingleCipherSuite(ctx, cipherSuite, cipherName, "TLS 1.2")
		ct.recordCipherResult(result)

		// Check if weak cipher is supported
		if result.Supported {
			vulnerability := TLSVulnerability{
				Type:        "weak_cipher",
				Severity:    ct.calculateCipherSeverity(cipherName),
				Component:   "cipher",
				Description: fmt.Sprintf("Weak cipher suite %s is supported", cipherName),
				Evidence:    fmt.Sprintf("Server accepts connections using %s", cipherName),
				Remediation: "Disable weak cipher suites and use only modern, secure algorithms",
				RiskScore:   ct.calculateCipherRiskScore(cipherName),
				CipherSuite: cipherName,
				TLSVersion:  "TLS 1.2",
				Exploitable: ct.isCipherExploitable(cipherName),
			}
			ct.recordVulnerability(vulnerability)
		}
	}

	return nil
}

// testExportCipherSuites tests for export-grade cipher suites (critical vulnerability)
func (ct *CipherTester) testExportCipherSuites(ctx context.Context) error {
	for _, cipherName := range ExportCipherSuites {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cipherSuite := ct.getCipherSuiteByName(cipherName)
		if cipherSuite == 0 {
			continue
		}

		result := ct.testSingleCipherSuite(ctx, cipherSuite, cipherName, "TLS 1.0")
		ct.recordCipherResult(result)

		// Export ciphers should NEVER be supported
		if result.Supported {
			vulnerability := TLSVulnerability{
				Type:        "export_cipher",
				Severity:    "critical",
				Component:   "cipher",
				Description: fmt.Sprintf("Export-grade cipher suite %s is supported (FREAK/Logjam vulnerability)", cipherName),
				Evidence:    fmt.Sprintf("Server accepts export-grade cipher %s", cipherName),
				Remediation: "Immediately disable all export-grade cipher suites",
				RiskScore:   95,
				CipherSuite: cipherName,
				TLSVersion:  "TLS 1.0",
				Exploitable: true,
			}
			ct.recordVulnerability(vulnerability)
		}
	}

	return nil
}

// testCipherSuitePreference tests server cipher suite preference order
func (ct *CipherTester) testCipherSuitePreference(ctx context.Context) error {
	// Test with different cipher order to see if server has preference
	testCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	// Test with cipher order 1
	selectedCipher1 := ct.testCipherPreference(ctx, testCiphers)

	// Test with reversed cipher order
	reversedCiphers := make([]uint16, len(testCiphers))
	for i, j := 0, len(testCiphers)-1; i < len(testCiphers); i, j = i+1, j-1 {
		reversedCiphers[i] = testCiphers[j]
	}
	selectedCipher2 := ct.testCipherPreference(ctx, reversedCiphers)

	// Analyze server preference
	if selectedCipher1 != selectedCipher2 {
		// Server follows client preference (potential security concern)
		vulnerability := TLSVulnerability{
			Type:        "client_cipher_preference",
			Severity:    "low",
			Component:   "cipher",
			Description: "Server follows client cipher suite preference instead of enforcing its own",
			Evidence:    fmt.Sprintf("Different ciphers selected: %x vs %x", selectedCipher1, selectedCipher2),
			Remediation: "Configure server to enforce its own cipher suite preference order",
			RiskScore:   30,
			Exploitable: false,
		}
		ct.recordVulnerability(vulnerability)
	}

	return nil
}

// testSecureCipherSuites tests support for modern, secure cipher suites
func (ct *CipherTester) testSecureCipherSuites(ctx context.Context) error {
	secureCount := 0
	totalSecure := len(SecureCipherSuites)

	for _, cipherName := range SecureCipherSuites {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cipherSuite := ct.getCipherSuiteByName(cipherName)
		if cipherSuite == 0 {
			continue
		}

		result := ct.testSingleCipherSuite(ctx, cipherSuite, cipherName, "TLS 1.3")
		ct.recordCipherResult(result)

		if result.Supported {
			secureCount++
		}
	}

	// Check if server supports enough modern ciphers
	secureRatio := float64(secureCount) / float64(totalSecure)
	if secureRatio < 0.5 {
		vulnerability := TLSVulnerability{
			Type:        "limited_secure_ciphers",
			Severity:    "medium",
			Component:   "cipher",
			Description: fmt.Sprintf("Server supports only %d/%d modern cipher suites", secureCount, totalSecure),
			Evidence:    fmt.Sprintf("Secure cipher support ratio: %.1f%%", secureRatio*100),
			Remediation: "Enable support for modern cipher suites (AES-GCM, ChaCha20-Poly1305)",
			RiskScore:   50,
			Exploitable: false,
		}
		ct.recordVulnerability(vulnerability)
	}

	return nil
}

// testSingleCipherSuite tests a specific cipher suite
func (ct *CipherTester) testSingleCipherSuite(ctx context.Context, cipherSuite uint16, cipherName, tlsVersion string) CipherTestResult {
	ct.incrementTestCount()

	result := CipherTestResult{
		CipherSuite:   cipherName,
		TLSVersion:    tlsVersion,
		Supported:     false,
		SecurityLevel: "unknown",
	}

	// Create TLS config with only this cipher suite
	tlsConfig := &tls.Config{
		CipherSuites:       []uint16{cipherSuite},
		InsecureSkipVerify: ct.target.TLS.InsecureSkipVerify,
		ServerName:         ct.host,
	}

	// Set TLS version based on test
	switch tlsVersion {
	case "TLS 1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	case "TLS 1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	case "TLS 1.1":
		tlsConfig.MinVersion = tls.VersionTLS11
		tlsConfig.MaxVersion = tls.VersionTLS11
	case "TLS 1.0":
		tlsConfig.MinVersion = tls.VersionTLS10
		tlsConfig.MaxVersion = tls.VersionTLS10
	}

	// Test connection with timeout
	startTime := time.Now()
	conn, err := ct.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		return result // Cipher not supported
	}
	defer conn.Close()

	// Cipher is supported
	result.Supported = true

	// Analyze cipher security
	ct.analyzeCipherSecurity(&result)

	return result
}

// testCipherPreference tests which cipher is selected with a given list
func (ct *CipherTester) testCipherPreference(ctx context.Context, ciphers []uint16) uint16 {
	tlsConfig := &tls.Config{
		CipherSuites:       ciphers,
		InsecureSkipVerify: true,
		ServerName:         ct.host,
	}

	conn, err := ct.connectWithTimeout(ctx, tlsConfig, 5*time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		return tlsConn.ConnectionState().CipherSuite
	}

	return 0
}

// connectWithTimeout creates a TLS connection with timeout
func (ct *CipherTester) connectWithTimeout(ctx context.Context, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	address := net.JoinHostPort(ct.host, ct.port)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(timeoutCtx, "tcp", address)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Perform handshake with timeout
	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- tlsConn.Handshake()
	}()

	select {
	case err := <-handshakeDone:
		if err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	case <-timeoutCtx.Done():
		conn.Close()
		return nil, timeoutCtx.Err()
	}
}

// analyzeCipherSecurity analyzes the security properties of a cipher suite
func (ct *CipherTester) analyzeCipherSecurity(result *CipherTestResult) {
	cipherName := strings.ToUpper(result.CipherSuite)

	// Determine security level
	if ct.isSecureCipher(cipherName) {
		result.SecurityLevel = "secure"
	} else if ct.isWeakCipher(cipherName) {
		result.SecurityLevel = "weak"
	} else if ct.isExportCipher(cipherName) {
		result.SecurityLevel = "insecure"
		result.IsExportGrade = true
	}

	// Extract cipher components
	result.KeyExchange = ct.extractKeyExchange(cipherName)
	result.Authentication = ct.extractAuthentication(cipherName)
	result.Encryption = ct.extractEncryption(cipherName)
	result.MAC = ct.extractMAC(cipherName)

	// Identify weak points
	result.WeakPoints = ct.identifyWeakPoints(cipherName)
	result.IsDeprecated = ct.isDeprecatedCipher(cipherName)

	// Extract key length
	result.KeyLength = ct.extractKeyLength(cipherName)
}

// Helper methods for cipher analysis

func (ct *CipherTester) isSecureCipher(cipherName string) bool {
	for _, secure := range SecureCipherSuites {
		if strings.EqualFold(secure, cipherName) {
			return true
		}
	}
	return false
}

func (ct *CipherTester) isWeakCipher(cipherName string) bool {
	for _, weak := range WeakCipherSuites {
		if strings.EqualFold(weak, cipherName) {
			return true
		}
	}
	return false
}

func (ct *CipherTester) isExportCipher(cipherName string) bool {
	return strings.Contains(cipherName, "EXPORT") || strings.Contains(cipherName, "40")
}

func (ct *CipherTester) extractKeyExchange(cipherName string) string {
	if strings.Contains(cipherName, "ECDHE") {
		return "ECDHE"
	} else if strings.Contains(cipherName, "DHE") {
		return "DHE"
	} else if strings.Contains(cipherName, "RSA") {
		return "RSA"
	}
	return "unknown"
}

func (ct *CipherTester) extractAuthentication(cipherName string) string {
	if strings.Contains(cipherName, "ECDSA") {
		return "ECDSA"
	} else if strings.Contains(cipherName, "RSA") {
		return "RSA"
	} else if strings.Contains(cipherName, "DSS") {
		return "DSS"
	}
	return "unknown"
}

func (ct *CipherTester) extractEncryption(cipherName string) string {
	if strings.Contains(cipherName, "AES_256_GCM") {
		return "AES-256-GCM"
	} else if strings.Contains(cipherName, "AES_128_GCM") {
		return "AES-128-GCM"
	} else if strings.Contains(cipherName, "CHACHA20") {
		return "ChaCha20"
	} else if strings.Contains(cipherName, "AES_256_CBC") {
		return "AES-256-CBC"
	} else if strings.Contains(cipherName, "AES_128_CBC") {
		return "AES-128-CBC"
	} else if strings.Contains(cipherName, "3DES") {
		return "3DES"
	} else if strings.Contains(cipherName, "RC4") {
		return "RC4"
	}
	return "unknown"
}

func (ct *CipherTester) extractMAC(cipherName string) string {
	if strings.Contains(cipherName, "GCM") || strings.Contains(cipherName, "POLY1305") {
		return "AEAD"
	} else if strings.Contains(cipherName, "SHA384") {
		return "SHA384"
	} else if strings.Contains(cipherName, "SHA256") {
		return "SHA256"
	} else if strings.Contains(cipherName, "SHA") {
		return "SHA1"
	} else if strings.Contains(cipherName, "MD5") {
		return "MD5"
	}
	return "unknown"
}

func (ct *CipherTester) identifyWeakPoints(cipherName string) []string {
	var weakPoints []string

	if strings.Contains(cipherName, "RC4") {
		weakPoints = append(weakPoints, "RC4 stream cipher vulnerabilities")
	}
	if strings.Contains(cipherName, "MD5") {
		weakPoints = append(weakPoints, "MD5 hash collision vulnerabilities")
	}
	if strings.Contains(cipherName, "3DES") {
		weakPoints = append(weakPoints, "3DES sweet32 attack vulnerability")
	}
	if strings.Contains(cipherName, "CBC") && !strings.Contains(cipherName, "GCM") {
		weakPoints = append(weakPoints, "CBC padding oracle vulnerabilities")
	}
	if !strings.Contains(cipherName, "ECDHE") && !strings.Contains(cipherName, "DHE") {
		weakPoints = append(weakPoints, "No forward secrecy")
	}

	return weakPoints
}

func (ct *CipherTester) isDeprecatedCipher(cipherName string) bool {
	deprecated := []string{"RC4", "3DES", "MD5", "SHA1"}
	for _, dep := range deprecated {
		if strings.Contains(cipherName, dep) {
			return true
		}
	}
	return false
}

func (ct *CipherTester) extractKeyLength(cipherName string) int {
	if strings.Contains(cipherName, "256") {
		return 256
	} else if strings.Contains(cipherName, "128") {
		return 128
	} else if strings.Contains(cipherName, "40") {
		return 40
	}
	return 0
}

// Severity and risk calculation methods

func (ct *CipherTester) calculateCipherSeverity(cipherName string) string {
	if ct.isExportCipher(cipherName) {
		return "critical"
	}
	if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "MD5") {
		return "high"
	}
	if strings.Contains(cipherName, "3DES") || strings.Contains(cipherName, "CBC") {
		return "medium"
	}
	return "low"
}

func (ct *CipherTester) calculateCipherRiskScore(cipherName string) int {
	score := 30 // Base score for weak cipher

	if ct.isExportCipher(cipherName) {
		return 95 // Critical
	}
	if strings.Contains(cipherName, "RC4") {
		score += 40
	}
	if strings.Contains(cipherName, "MD5") {
		score += 35
	}
	if strings.Contains(cipherName, "3DES") {
		score += 25
	}
	if !strings.Contains(cipherName, "ECDHE") && !strings.Contains(cipherName, "DHE") {
		score += 15 // No forward secrecy
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (ct *CipherTester) isCipherExploitable(cipherName string) bool {
	exploitable := []string{"RC4", "EXPORT", "MD5", "40"}
	for _, exp := range exploitable {
		if strings.Contains(cipherName, exp) {
			return true
		}
	}
	return false
}

// getCipherSuiteByName maps cipher suite names to Go TLS constants
func (ct *CipherTester) getCipherSuiteByName(name string) uint16 {
	// Only include cipher suites that are actually defined in crypto/tls
	cipherMap := map[string]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":              tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":         tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":          tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":          tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":   tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_AES_128_GCM_SHA256":                tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":          tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	if suite, exists := cipherMap[name]; exists {
		return suite
	}
	return 0
}

// Thread-safe result recording methods

func (ct *CipherTester) incrementTestCount() {
	ct.mu.Lock()
	ct.testsExecuted++
	ct.mu.Unlock()
}

func (ct *CipherTester) recordCipherResult(result CipherTestResult) {
	ct.mu.Lock()
	ct.cipherResults = append(ct.cipherResults, result)
	ct.mu.Unlock()
}

func (ct *CipherTester) recordVulnerability(vuln TLSVulnerability) {
	ct.mu.Lock()
	ct.vulnerabilities = append(ct.vulnerabilities, vuln)
	ct.mu.Unlock()
}

// GetResults returns the current cipher testing results
func (ct *CipherTester) GetResults() ([]CipherTestResult, []TLSVulnerability) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	// Make copies to avoid race conditions
	results := make([]CipherTestResult, len(ct.cipherResults))
	copy(results, ct.cipherResults)

	vulns := make([]TLSVulnerability, len(ct.vulnerabilities))
	copy(vulns, ct.vulnerabilities)

	return results, vulns
}
