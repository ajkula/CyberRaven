package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// DowngradeTester handles TLS protocol downgrade testing
type DowngradeTester struct {
	config *config.TLSAttackConfig
	target *config.TargetConfig
	host   string
	port   string

	// Results tracking
	mu               sync.RWMutex
	testsExecuted    int
	downgradeResults []DowngradeTestResult
	vulnerabilities  []TLSVulnerability
}

// NewDowngradeTester creates a new downgrade tester
func NewDowngradeTester(tlsConfig *config.TLSAttackConfig, targetConfig *config.TargetConfig) (*DowngradeTester, error) {
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
			return nil, fmt.Errorf("downgrade testing requires HTTPS target")
		}
	}

	return &DowngradeTester{
		config: tlsConfig,
		target: targetConfig,
		host:   host,
		port:   port,
	}, nil
}

// TestDowngrade performs comprehensive TLS downgrade testing
func (dt *DowngradeTester) TestDowngrade(ctx context.Context) error {
	if !dt.config.TestDowngrade {
		return nil
	}

	// Test TLS version downgrade attacks
	if err := dt.testTLSVersionDowngrade(ctx); err != nil {
		return fmt.Errorf("TLS version downgrade testing failed: %w", err)
	}

	// Test cipher suite downgrade attacks
	if err := dt.testCipherDowngrade(ctx); err != nil {
		return fmt.Errorf("cipher downgrade testing failed: %w", err)
	}

	// Test protocol downgrade (HTTPS to HTTP)
	if err := dt.testProtocolDowngrade(ctx); err != nil {
		return fmt.Errorf("protocol downgrade testing failed: %w", err)
	}

	// Test MITM simulation
	if err := dt.testMITMSimulation(ctx); err != nil {
		return fmt.Errorf("MITM simulation testing failed: %w", err)
	}

	return nil
}

// testTLSVersionDowngrade tests for TLS version rollback vulnerabilities
func (dt *DowngradeTester) testTLSVersionDowngrade(ctx context.Context) error {
	// Define TLS versions to test (from newest to oldest)
	testVersions := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.3", tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10},
	}

	// First, determine the highest supported version
	highestSupported := dt.findHighestSupportedVersion(ctx, testVersions)
	if highestSupported == "" {
		return fmt.Errorf("no supported TLS versions found")
	}

	// Test downgrade to each lower version
	for _, version := range testVersions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip versions equal to or higher than the highest supported
		if version.name >= highestSupported {
			continue
		}

		result := dt.testVersionDowngradeAttempt(ctx, version.name, version.version, highestSupported)
		dt.recordDowngradeResult(result)

		// Check if downgrade was successful (vulnerability)
		if result.DowngradeForced {
			severity := dt.calculateVersionDowngradeSeverity(version.name, highestSupported)
			vuln := TLSVulnerability{
				Type:        "protocol_downgrade",
				Severity:    severity,
				Component:   "protocol",
				Description: fmt.Sprintf("TLS version downgrade from %s to %s successful", highestSupported, version.name),
				Evidence:    fmt.Sprintf("Server accepted %s when %s was available", version.name, highestSupported),
				Remediation: "Configure server to require minimum TLS version and reject downgrades",
				RiskScore:   dt.calculateVersionDowngradeRisk(version.name),
				TLSVersion:  version.name,
				Exploitable: dt.isVersionDowngradeExploitable(version.name),
			}
			dt.recordVulnerability(vuln)
		}
	}

	return nil
}

// testCipherDowngrade tests for cipher suite downgrade attacks
func (dt *DowngradeTester) testCipherDowngrade(ctx context.Context) error {
	// Test if server can be forced to use weak ciphers when strong ones are available
	strongCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}

	// First, check if server supports strong ciphers
	strongSupported := dt.testCipherSupport(ctx, strongCiphers)
	if !strongSupported {
		return nil // If no strong ciphers supported, no downgrade possible
	}

	// Test if server can be forced to use weak ciphers
	for _, weakCipher := range weakCiphers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result := dt.testCipherDowngradeAttempt(ctx, weakCipher)
		dt.recordDowngradeResult(result)

		if result.DowngradeForced {
			cipherName := dt.getCipherName(weakCipher)
			vuln := TLSVulnerability{
				Type:        "cipher_downgrade",
				Severity:    "medium",
				Component:   "cipher",
				Description: fmt.Sprintf("Cipher suite downgrade to %s successful", cipherName),
				Evidence:    fmt.Sprintf("Server accepted weak cipher %s despite strong ciphers being available", cipherName),
				Remediation: "Configure server cipher suite preference and disable weak ciphers",
				RiskScore:   65,
				CipherSuite: cipherName,
				Exploitable: true,
			}
			dt.recordVulnerability(vuln)
		}
	}

	return nil
}

// testProtocolDowngrade tests for HTTPS to HTTP downgrade
func (dt *DowngradeTester) testProtocolDowngrade(ctx context.Context) error {
	dt.incrementTestCount()

	// Test if server responds to HTTP on the same port
	httpURL := strings.Replace(dt.target.BaseURL, "https://", "http://", 1)

	// Create HTTP client with short timeout
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return err
	}

	startTime := time.Now()
	resp, err := httpClient.Do(req)
	responseTime := time.Since(startTime)

	result := DowngradeTestResult{
		TargetVersion:     "HTTPS",
		NegotiatedVersion: "HTTP",
		AttackVector:      "protocol_downgrade",
		ResponseTime:      responseTime,
		IsVulnerable:      false,
		SecurityImpact:    "none",
		AttackComplexity:  "low",
	}

	if err == nil && resp != nil {
		resp.Body.Close()

		// Server responded to HTTP - potential vulnerability
		result.DowngradeForced = true
		result.IsVulnerable = true
		result.SecurityImpact = "high"
		result.MITMPossible = true

		vuln := TLSVulnerability{
			Type:        "protocol_downgrade_http",
			Severity:    "high",
			Component:   "protocol",
			Description: "Server accepts HTTP connections on HTTPS port",
			Evidence:    fmt.Sprintf("HTTP response received on port %s", dt.port),
			Remediation: "Disable HTTP on HTTPS ports and implement HSTS",
			RiskScore:   85,
			Exploitable: true,
		}
		dt.recordVulnerability(vuln)
	}

	dt.recordDowngradeResult(result)
	return nil
}

// testMITMSimulation simulates man-in-the-middle attack scenarios
func (dt *DowngradeTester) testMITMSimulation(ctx context.Context) error {
	// Test various MITM scenarios that could lead to downgrade

	// Test 1: Accept any certificate (simulating MITM with fake cert)
	if err := dt.testAcceptAnyCertificate(ctx); err != nil {
		return err
	}

	// Test 2: Test SSL/TLS renegotiation vulnerabilities
	if err := dt.testSSLRenegotiation(ctx); err != nil {
		return err
	}

	return nil
}

// testVersionDowngradeAttempt attempts to downgrade to a specific TLS version
func (dt *DowngradeTester) testVersionDowngradeAttempt(ctx context.Context, versionName string, version uint16, highestSupported string) DowngradeTestResult {
	dt.incrementTestCount()

	result := DowngradeTestResult{
		TargetVersion:     highestSupported,
		NegotiatedVersion: versionName,
		AttackVector:      "version_rollback",
		DowngradeForced:   false,
		IsVulnerable:      false,
		SecurityImpact:    "none",
		AttackComplexity:  "medium",
	}

	// Configure TLS to use only the target version
	tlsConfig := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: dt.target.TLS.InsecureSkipVerify,
		ServerName:         dt.host,
	}

	startTime := time.Now()
	conn, err := dt.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		// Connection failed - downgrade not possible
		return result
	}
	defer conn.Close()

	// Downgrade successful
	result.DowngradeForced = true
	result.IsVulnerable = true
	result.SecurityImpact = dt.calculateDowngradeImpact(versionName)
	result.MITMPossible = dt.isMITMPossible(versionName)

	// Record handshake details
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		result.HandshakeDetails = []string{
			fmt.Sprintf("Negotiated Version: %x", state.Version),
			fmt.Sprintf("Cipher Suite: %x", state.CipherSuite),
		}
	}

	return result
}

// testCipherDowngradeAttempt attempts cipher downgrade
func (dt *DowngradeTester) testCipherDowngradeAttempt(ctx context.Context, weakCipher uint16) DowngradeTestResult {
	dt.incrementTestCount()

	result := DowngradeTestResult{
		TargetVersion:     "Strong Cipher",
		NegotiatedVersion: dt.getCipherName(weakCipher),
		AttackVector:      "cipher_downgrade",
		DowngradeForced:   false,
		IsVulnerable:      false,
		SecurityImpact:    "medium",
		AttackComplexity:  "low",
	}

	tlsConfig := &tls.Config{
		CipherSuites:       []uint16{weakCipher},
		InsecureSkipVerify: dt.target.TLS.InsecureSkipVerify,
		ServerName:         dt.host,
	}

	startTime := time.Now()
	conn, err := dt.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		return result
	}
	defer conn.Close()

	result.DowngradeForced = true
	result.IsVulnerable = true
	result.MITMPossible = true

	return result
}

// testAcceptAnyCertificate tests if server accepts invalid certificates
func (dt *DowngradeTester) testAcceptAnyCertificate(ctx context.Context) error {
	dt.incrementTestCount()

	// Test with completely invalid certificate validation
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "invalid-hostname-test.example.com", // Wrong hostname
	}

	conn, err := dt.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	if err != nil {
		// Good - server rejected invalid certificate
		return nil
	}
	defer conn.Close()

	// Server accepted invalid certificate - vulnerability
	result := DowngradeTestResult{
		TargetVersion:     "Valid Certificate",
		NegotiatedVersion: "Invalid Certificate Accepted",
		AttackVector:      "certificate_bypass",
		DowngradeForced:   true,
		IsVulnerable:      true,
		SecurityImpact:    "high",
		AttackComplexity:  "low",
		MITMPossible:      true,
	}
	dt.recordDowngradeResult(result)

	vuln := TLSVulnerability{
		Type:        "cert_validation_bypass",
		Severity:    "high",
		Component:   "certificate",
		Description: "Server accepts connections with invalid certificates",
		Evidence:    "Connection established with invalid hostname",
		Remediation: "Implement proper certificate validation",
		RiskScore:   80,
		Exploitable: true,
	}
	dt.recordVulnerability(vuln)

	return nil
}

// testSSLRenegotiation tests for SSL/TLS renegotiation vulnerabilities
func (dt *DowngradeTester) testSSLRenegotiation(ctx context.Context) error {
	dt.incrementTestCount()

	// Test if server supports renegotiation
	tlsConfig := &tls.Config{
		InsecureSkipVerify: dt.target.TLS.InsecureSkipVerify,
		ServerName:         dt.host,
		Renegotiation:      tls.RenegotiateOnceAsClient,
	}

	conn, err := dt.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Attempt renegotiation
		err := tlsConn.Handshake()
		if err == nil {
			// Renegotiation successful - potential vulnerability
			vuln := TLSVulnerability{
				Type:        "ssl_renegotiation",
				Severity:    "medium",
				Component:   "protocol",
				Description: "SSL/TLS renegotiation is supported",
				Evidence:    "Server allowed TLS renegotiation",
				Remediation: "Disable SSL/TLS renegotiation or implement secure renegotiation",
				RiskScore:   50,
				Exploitable: false,
			}
			dt.recordVulnerability(vuln)
		}
	}

	return nil
}

// Helper methods

func (dt *DowngradeTester) findHighestSupportedVersion(ctx context.Context, versions []struct {
	name    string
	version uint16
}) string {
	for _, version := range versions {
		tlsConfig := &tls.Config{
			MinVersion:         version.version,
			MaxVersion:         version.version,
			InsecureSkipVerify: dt.target.TLS.InsecureSkipVerify,
			ServerName:         dt.host,
		}

		conn, err := dt.connectWithTimeout(ctx, tlsConfig, 5*time.Second)
		if err == nil {
			conn.Close()
			return version.name
		}
	}
	return ""
}

func (dt *DowngradeTester) testCipherSupport(ctx context.Context, ciphers []uint16) bool {
	tlsConfig := &tls.Config{
		CipherSuites:       ciphers,
		InsecureSkipVerify: dt.target.TLS.InsecureSkipVerify,
		ServerName:         dt.host,
	}

	conn, err := dt.connectWithTimeout(ctx, tlsConfig, 5*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func (dt *DowngradeTester) connectWithTimeout(ctx context.Context, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	address := net.JoinHostPort(dt.host, dt.port)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(timeoutCtx, "tcp", address)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

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

func (dt *DowngradeTester) getCipherName(cipher uint16) string {
	cipherNames := map[uint16]string{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:                "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:                "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	if name, exists := cipherNames[cipher]; exists {
		return name
	}
	return fmt.Sprintf("Unknown_Cipher_%x", cipher)
}

// Risk calculation methods

func (dt *DowngradeTester) calculateVersionDowngradeSeverity(version, highest string) string {
	if version == "TLS 1.0" || version == "SSL 3.0" {
		return "high"
	}
	if version == "TLS 1.1" {
		return "medium"
	}
	return "low"
}

func (dt *DowngradeTester) calculateVersionDowngradeRisk(version string) int {
	switch version {
	case "SSL 2.0":
		return 95
	case "SSL 3.0":
		return 90
	case "TLS 1.0":
		return 75
	case "TLS 1.1":
		return 60
	default:
		return 40
	}
}

func (dt *DowngradeTester) isVersionDowngradeExploitable(version string) bool {
	exploitableVersions := []string{"SSL 2.0", "SSL 3.0", "TLS 1.0"}
	for _, exp := range exploitableVersions {
		if version == exp {
			return true
		}
	}
	return false
}

func (dt *DowngradeTester) calculateDowngradeImpact(version string) string {
	switch version {
	case "SSL 2.0", "SSL 3.0":
		return "critical"
	case "TLS 1.0":
		return "high"
	case "TLS 1.1":
		return "medium"
	default:
		return "low"
	}
}

func (dt *DowngradeTester) isMITMPossible(version string) bool {
	vulnerableVersions := []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
	for _, vuln := range vulnerableVersions {
		if version == vuln {
			return true
		}
	}
	return false
}

// Thread-safe result recording methods

func (dt *DowngradeTester) incrementTestCount() {
	dt.mu.Lock()
	dt.testsExecuted++
	dt.mu.Unlock()
}

func (dt *DowngradeTester) recordDowngradeResult(result DowngradeTestResult) {
	dt.mu.Lock()
	dt.downgradeResults = append(dt.downgradeResults, result)
	dt.mu.Unlock()
}

func (dt *DowngradeTester) recordVulnerability(vuln TLSVulnerability) {
	dt.mu.Lock()
	dt.vulnerabilities = append(dt.vulnerabilities, vuln)
	dt.mu.Unlock()
}

// GetResults returns the current downgrade testing results
func (dt *DowngradeTester) GetResults() ([]DowngradeTestResult, []TLSVulnerability) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	// Make copies to avoid race conditions
	results := make([]DowngradeTestResult, len(dt.downgradeResults))
	copy(results, dt.downgradeResults)

	vulns := make([]TLSVulnerability, len(dt.vulnerabilities))
	copy(vulns, dt.vulnerabilities)

	return results, vulns
}
