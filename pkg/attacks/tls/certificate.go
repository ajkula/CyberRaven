package tls

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// CertificateTester handles certificate security testing
type CertificateTester struct {
	config *config.TLSAttackConfig
	target *config.TargetConfig
	host   string
	port   string

	// Results tracking
	mu                 sync.RWMutex
	testsExecuted      int
	certificateResults []CertificateTestResult
	vulnerabilities    []TLSVulnerability
}

// NewCertificateTester creates a new certificate tester
func NewCertificateTester(tlsConfig *config.TLSAttackConfig, targetConfig *config.TargetConfig) (*CertificateTester, error) {
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
			return nil, fmt.Errorf("certificate testing requires HTTPS target")
		}
	}

	return &CertificateTester{
		config: tlsConfig,
		target: targetConfig,
		host:   host,
		port:   port,
	}, nil
}

// TestCertificates performs comprehensive certificate testing
func (ct *CertificateTester) TestCertificates(ctx context.Context) error {
	if !ct.config.TestCertificates {
		return nil
	}

	// Get server certificates
	certs, err := ct.getServerCertificates(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve server certificates: %w", err)
	}

	// Test each certificate in the chain
	for i, cert := range certs {
		certResult := ct.analyzeCertificate(cert, i == 0) // First cert is server cert
		ct.recordCertificateResult(certResult)

		// Check for vulnerabilities
		ct.checkCertificateVulnerabilities(certResult)
	}

	// Test certificate chain validation
	if err := ct.testCertificateChain(ctx, certs); err != nil {
		return fmt.Errorf("certificate chain testing failed: %w", err)
	}

	// Test self-signed certificates if enabled
	if ct.config.TestSelfSigned {
		if err := ct.testSelfSignedCertificates(ctx); err != nil {
			return fmt.Errorf("self-signed certificate testing failed: %w", err)
		}
	}

	// Test expired certificates if enabled
	if ct.config.TestExpiredCerts {
		if err := ct.testExpiredCertificates(ctx); err != nil {
			return fmt.Errorf("expired certificate testing failed: %w", err)
		}
	}

	return nil
}

// getServerCertificates retrieves the server's certificate chain
func (ct *CertificateTester) getServerCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	ct.incrementTestCount()

	// Connect with TLS to get certificates
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // We want to get certs even if invalid
		ServerName:         ct.host,
	}

	conn, err := ct.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		return state.PeerCertificates, nil
	}

	return nil, fmt.Errorf("not a TLS connection")
}

// analyzeCertificate performs detailed analysis of a certificate
func (ct *CertificateTester) analyzeCertificate(cert *x509.Certificate, isServerCert bool) CertificateTestResult {
	result := CertificateTestResult{
		CertificateID:  ct.generateCertificateID(cert),
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		SignatureAlg:   cert.SignatureAlgorithm.String(),
		PublicKeyAlg:   cert.PublicKeyAlgorithm.String(),
		IsCA:           cert.IsCA,
		IsSelfSigned:   ct.isSelfSigned(cert),
		SecurityIssues: []string{},
		Extensions:     make(map[string]string),
	}

	// Extract key length
	result.KeyLength = ct.extractKeyLength(cert)

	// Check if certificate is expired
	now := time.Now()
	result.IsExpired = now.After(cert.NotAfter)

	// Basic validation
	result.IsValid = !result.IsExpired && result.KeyLength >= 2048

	// Check hostname match for server certificate
	if isServerCert {
		result.HostnameMatch = ct.checkHostnameMatch(cert)
		if !result.HostnameMatch {
			result.SecurityIssues = append(result.SecurityIssues, "Hostname mismatch")
		}
	}

	// Analyze signature algorithm
	if ct.isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		result.WeakSignature = true
		result.SecurityIssues = append(result.SecurityIssues, "Weak signature algorithm: "+cert.SignatureAlgorithm.String())
	}

	// Check key length
	if result.KeyLength > 0 && result.KeyLength < 2048 {
		result.WeakKeyLength = true
		result.SecurityIssues = append(result.SecurityIssues, fmt.Sprintf("Weak key length: %d bits", result.KeyLength))
	}

	// Extract important extensions
	ct.extractCertificateExtensions(cert, &result)

	return result
}

// checkCertificateVulnerabilities checks for certificate-related vulnerabilities
func (ct *CertificateTester) checkCertificateVulnerabilities(certResult CertificateTestResult) {
	// Check for expired certificate
	if certResult.IsExpired {
		vuln := TLSVulnerability{
			Type:          "cert_expired",
			Severity:      "high",
			Component:     "certificate",
			Description:   "Certificate has expired",
			Evidence:      fmt.Sprintf("Certificate expired on %v", certResult.NotAfter),
			Remediation:   "Renew the certificate immediately",
			RiskScore:     85,
			CertificateID: certResult.CertificateID,
			Exploitable:   true,
		}
		ct.recordVulnerability(vuln)
	}

	// Check for self-signed certificate
	if certResult.IsSelfSigned {
		severity := "medium"
		if strings.Contains(strings.ToLower(ct.host), "prod") {
			severity = "high" // Higher severity in production
		}

		vuln := TLSVulnerability{
			Type:          "cert_self_signed",
			Severity:      severity,
			Component:     "certificate",
			Description:   "Self-signed certificate detected",
			Evidence:      "Certificate issuer and subject are identical",
			Remediation:   "Use a certificate signed by a trusted Certificate Authority",
			RiskScore:     ct.calculateSelfSignedRisk(),
			CertificateID: certResult.CertificateID,
			Exploitable:   true,
		}
		ct.recordVulnerability(vuln)
	}

	// Check for weak signature algorithm
	if certResult.WeakSignature {
		vuln := TLSVulnerability{
			Type:          "cert_weak_signature",
			Severity:      "medium",
			Component:     "certificate",
			Description:   "Certificate uses weak signature algorithm",
			Evidence:      "Signature algorithm: " + certResult.SignatureAlg,
			Remediation:   "Replace certificate with one using SHA-256 or stronger",
			RiskScore:     60,
			CertificateID: certResult.CertificateID,
			Exploitable:   false,
		}
		ct.recordVulnerability(vuln)
	}

	// Check for weak key length
	if certResult.WeakKeyLength {
		vuln := TLSVulnerability{
			Type:          "cert_weak_key",
			Severity:      "high",
			Component:     "certificate",
			Description:   fmt.Sprintf("Certificate uses weak key length: %d bits", certResult.KeyLength),
			Evidence:      fmt.Sprintf("Key length: %d bits (minimum recommended: 2048)", certResult.KeyLength),
			Remediation:   "Replace certificate with 2048-bit RSA or 256-bit ECDSA key",
			RiskScore:     75,
			CertificateID: certResult.CertificateID,
			Exploitable:   true,
		}
		ct.recordVulnerability(vuln)
	}

	// Check for hostname mismatch
	if !certResult.HostnameMatch && certResult.CertificateID != "" {
		vuln := TLSVulnerability{
			Type:          "cert_hostname_mismatch",
			Severity:      "high",
			Component:     "certificate",
			Description:   "Certificate hostname does not match server hostname",
			Evidence:      fmt.Sprintf("Server: %s, Certificate: %s", ct.host, certResult.Subject),
			Remediation:   "Obtain certificate with correct hostname or configure proper certificate",
			RiskScore:     80,
			CertificateID: certResult.CertificateID,
			Exploitable:   true,
		}
		ct.recordVulnerability(vuln)
	}
}

// testCertificateChain tests the certificate chain validation
func (ct *CertificateTester) testCertificateChain(ctx context.Context, certs []*x509.Certificate) error {
	ct.incrementTestCount()

	if len(certs) == 0 {
		return nil
	}

	// Test with proper certificate verification
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Proper verification
		ServerName:         ct.host,
	}

	conn, err := ct.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	if err != nil {
		// Certificate chain validation failed
		vuln := TLSVulnerability{
			Type:        "cert_chain_invalid",
			Severity:    "high",
			Component:   "certificate",
			Description: "Certificate chain validation failed",
			Evidence:    err.Error(),
			Remediation: "Fix certificate chain by installing intermediate certificates",
			RiskScore:   85,
			Exploitable: true,
		}
		ct.recordVulnerability(vuln)
		return nil // Don't return error, just record vulnerability
	}
	defer conn.Close()

	return nil
}

// testSelfSignedCertificates performs additional tests for self-signed certificates
func (ct *CertificateTester) testSelfSignedCertificates(ctx context.Context) error {
	// Test with self-signed certificate acceptance
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ct.host,
	}

	conn, err := ct.connectWithTimeout(ctx, tlsConfig, 10*time.Second)
	if err != nil {
		return nil // If we can't connect, no self-signed cert issue
	}
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			if ct.isSelfSigned(cert) {
				// Additional analysis for self-signed certificates
				ct.analyzeSelfSignedCertificate(cert)
			}
		}
	}

	return nil
}

// testExpiredCertificates tests behavior with expired certificates
func (ct *CertificateTester) testExpiredCertificates(ctx context.Context) error {
	// Get certificates to check expiration
	certs, err := ct.getServerCertificates(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			// Certificate is expired
			vuln := TLSVulnerability{
				Type:          "cert_expired_detected",
				Severity:      "critical",
				Component:     "certificate",
				Description:   "Server is using an expired certificate",
				Evidence:      fmt.Sprintf("Certificate expired on %v (current time: %v)", cert.NotAfter, now),
				Remediation:   "Immediately renew and install new certificate",
				RiskScore:     95,
				CertificateID: ct.generateCertificateID(cert),
				Exploitable:   true,
			}
			ct.recordVulnerability(vuln)
		}

		// Check if certificate expires soon (within 30 days)
		expiresIn := cert.NotAfter.Sub(now)
		if expiresIn > 0 && expiresIn < 30*24*time.Hour {
			vuln := TLSVulnerability{
				Type:          "cert_expires_soon",
				Severity:      "medium",
				Component:     "certificate",
				Description:   fmt.Sprintf("Certificate expires in %d days", int(expiresIn.Hours()/24)),
				Evidence:      fmt.Sprintf("Certificate expires on %v", cert.NotAfter),
				Remediation:   "Schedule certificate renewal",
				RiskScore:     50,
				CertificateID: ct.generateCertificateID(cert),
				Exploitable:   false,
			}
			ct.recordVulnerability(vuln)
		}
	}

	return nil
}

// Helper methods

func (ct *CertificateTester) connectWithTimeout(ctx context.Context, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	address := net.JoinHostPort(ct.host, ct.port)

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

func (ct *CertificateTester) generateCertificateID(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", cert.SerialNumber)
}

func (ct *CertificateTester) isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func (ct *CertificateTester) checkHostnameMatch(cert *x509.Certificate) bool {
	err := cert.VerifyHostname(ct.host)
	return err == nil
}

func (ct *CertificateTester) isWeakSignatureAlgorithm(sigAlg x509.SignatureAlgorithm) bool {
	weakAlgorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
	}

	for _, weak := range weakAlgorithms {
		if sigAlg == weak {
			return true
		}
	}
	return false
}

func (ct *CertificateTester) extractKeyLength(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case *dsa.PublicKey:
		return pub.P.BitLen()
	default:
		return 0
	}
}

func (ct *CertificateTester) extractCertificateExtensions(cert *x509.Certificate, result *CertificateTestResult) {
	// Extract Subject Alternative Names
	if len(cert.DNSNames) > 0 {
		result.Extensions["Subject Alternative Names"] = strings.Join(cert.DNSNames, ", ")
	}

	// Extract Key Usage
	var keyUsages []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsages = append(keyUsages, "Data Encipherment")
	}
	if len(keyUsages) > 0 {
		result.Extensions["Key Usage"] = strings.Join(keyUsages, ", ")
	}

	// Extract Extended Key Usage
	var extKeyUsages []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsages = append(extKeyUsages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsages = append(extKeyUsages, "Client Authentication")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsages = append(extKeyUsages, "Email Protection")
		}
	}
	if len(extKeyUsages) > 0 {
		result.Extensions["Extended Key Usage"] = strings.Join(extKeyUsages, ", ")
	}

	// Extract Basic Constraints
	if cert.IsCA {
		result.Extensions["Basic Constraints"] = "CA: TRUE"
	} else {
		result.Extensions["Basic Constraints"] = "CA: FALSE"
	}
}

func (ct *CertificateTester) analyzeSelfSignedCertificate(cert *x509.Certificate) {
	// Additional analysis for self-signed certificates
	issues := []string{}

	// Check if used in production context
	if strings.Contains(strings.ToLower(ct.host), "prod") ||
		strings.Contains(strings.ToLower(ct.host), "www") {
		issues = append(issues, "Self-signed certificate in production environment")
	}

	// Check validity period
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore)
	if validityPeriod > 365*24*time.Hour {
		issues = append(issues, "Unusually long validity period for self-signed certificate")
	}

	if len(issues) > 0 {
		for _, issue := range issues {
			vuln := TLSVulnerability{
				Type:          "cert_self_signed_issues",
				Severity:      "low",
				Component:     "certificate",
				Description:   issue,
				Evidence:      fmt.Sprintf("Self-signed certificate with issue: %s", issue),
				Remediation:   "Use proper CA-signed certificate",
				RiskScore:     35,
				CertificateID: ct.generateCertificateID(cert),
				Exploitable:   false,
			}
			ct.recordVulnerability(vuln)
		}
	}
}

func (ct *CertificateTester) calculateSelfSignedRisk() int {
	score := 50 // Base score

	// Higher risk in production-like environments
	if strings.Contains(strings.ToLower(ct.host), "prod") ||
		strings.Contains(strings.ToLower(ct.host), "www") ||
		!strings.Contains(strings.ToLower(ct.host), "test") {
		score += 25
	}

	return score
}

// Thread-safe result recording methods

func (ct *CertificateTester) incrementTestCount() {
	ct.mu.Lock()
	ct.testsExecuted++
	ct.mu.Unlock()
}

func (ct *CertificateTester) recordCertificateResult(result CertificateTestResult) {
	ct.mu.Lock()
	ct.certificateResults = append(ct.certificateResults, result)
	ct.mu.Unlock()
}

func (ct *CertificateTester) recordVulnerability(vuln TLSVulnerability) {
	ct.mu.Lock()
	ct.vulnerabilities = append(ct.vulnerabilities, vuln)
	ct.mu.Unlock()
}

// GetResults returns the current certificate testing results
func (ct *CertificateTester) GetResults() ([]CertificateTestResult, []TLSVulnerability) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	// Make copies to avoid race conditions
	results := make([]CertificateTestResult, len(ct.certificateResults))
	copy(results, ct.certificateResults)

	vulns := make([]TLSVulnerability, len(ct.vulnerabilities))
	copy(vulns, ct.vulnerabilities)

	return results, vulns
}
