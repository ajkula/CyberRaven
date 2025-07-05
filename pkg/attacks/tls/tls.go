package tls

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// TLSTester handles comprehensive TLS/SSL security testing
type TLSTester struct {
	config     *config.TLSAttackConfig
	target     *config.TargetConfig
	httpClient *utils.HTTPClient

	// Sub-testers for different aspects
	cipherTester      *CipherTester
	certificateTester *CertificateTester
	downgradeTester   *DowngradeTester

	// Results tracking
	mu                 sync.RWMutex
	testsExecuted      int
	successfulTests    int
	failedTests        int
	vulnerabilities    []TLSVulnerability
	cipherResults      []CipherTestResult
	certificateResults []CertificateTestResult
	downgradeResults   []DowngradeTestResult
}

// NewTLSTester creates a new TLS security tester
func NewTLSTester(tlsConfig *config.TLSAttackConfig, targetConfig *config.TargetConfig) (*TLSTester, error) {
	// Validate target URL for TLS testing
	targetURL, err := url.Parse(targetConfig.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if targetURL.Scheme != "https" {
		return nil, fmt.Errorf("TLS testing requires HTTPS target, got: %s", targetURL.Scheme)
	}

	// Create engine config for HTTP client
	engineConfig := &config.EngineConfig{
		MaxWorkers: 5,                // Limited for TLS testing
		Timeout:    30 * time.Second, // Longer timeout for TLS handshakes
		RateLimit:  5,                // Conservative rate for TLS tests
		MaxRetries: 2,
		RetryDelay: 2 * time.Second,
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	tester := &TLSTester{
		config:     tlsConfig,
		target:     targetConfig,
		httpClient: httpClient,
	}

	// Initialize sub-testers
	if err := tester.initializeSubTesters(); err != nil {
		return nil, fmt.Errorf("failed to initialize sub-testers: %w", err)
	}

	return tester, nil
}

// initializeSubTesters creates the specialized testers for each TLS aspect
func (tt *TLSTester) initializeSubTesters() error {
	var err error

	// Initialize cipher tester
	if tt.config.TestCipherSuites {
		tt.cipherTester, err = NewCipherTester(tt.config, tt.target)
		if err != nil {
			return fmt.Errorf("failed to create cipher tester: %w", err)
		}
	}

	// Initialize certificate tester
	if tt.config.TestCertificates {
		tt.certificateTester, err = NewCertificateTester(tt.config, tt.target)
		if err != nil {
			return fmt.Errorf("failed to create certificate tester: %w", err)
		}
	}

	// Initialize downgrade tester
	if tt.config.TestDowngrade {
		tt.downgradeTester, err = NewDowngradeTester(tt.config, tt.target)
		if err != nil {
			return fmt.Errorf("failed to create downgrade tester: %w", err)
		}
	}

	return nil
}

// Execute performs comprehensive TLS security testing
func (tt *TLSTester) Execute(ctx context.Context) (*TLSTestResult, error) {
	startTime := time.Now()

	// Initialize result
	result := &TLSTestResult{
		StartTime:            startTime,
		TestType:             "TLS/SSL Security Assessment",
		BaseURL:              tt.target.BaseURL,
		SupportedTLSVersions: []string{},
	}

	// Execute cipher suite testing
	if tt.cipherTester != nil {
		if err := tt.executeCipherTesting(ctx); err != nil {
			return nil, fmt.Errorf("cipher testing failed: %w", err)
		}
	}

	// Execute certificate testing
	if tt.certificateTester != nil {
		if err := tt.executeCertificateTesting(ctx); err != nil {
			return nil, fmt.Errorf("certificate testing failed: %w", err)
		}
	}

	// Execute downgrade testing
	if tt.downgradeTester != nil {
		if err := tt.executeDowngradeTesting(ctx); err != nil {
			return nil, fmt.Errorf("downgrade testing failed: %w", err)
		}
	}

	// Collect and aggregate results
	tt.collectResults(result)

	// Finalize results
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculate metrics
	tt.mu.RLock()
	result.TestsExecuted = tt.testsExecuted
	result.SuccessfulTests = tt.successfulTests
	result.FailedTests = tt.failedTests
	tt.mu.RUnlock()

	if result.Duration.Seconds() > 0 {
		result.RequestsPerSecond = float64(result.TestsExecuted) / result.Duration.Seconds()
	}

	return result, nil
}

// executeCipherTesting runs cipher suite security tests
func (tt *TLSTester) executeCipherTesting(ctx context.Context) error {
	if err := tt.cipherTester.TestCipherSuites(ctx); err != nil {
		tt.recordFailedTest()
		return err
	}

	// Get results from cipher tester
	cipherResults, cipherVulns := tt.cipherTester.GetResults()

	tt.mu.Lock()
	tt.cipherResults = append(tt.cipherResults, cipherResults...)
	tt.vulnerabilities = append(tt.vulnerabilities, cipherVulns...)
	tt.testsExecuted += len(cipherResults)
	tt.successfulTests += len(cipherResults)
	tt.mu.Unlock()

	return nil
}

// executeCertificateTesting runs certificate security tests
func (tt *TLSTester) executeCertificateTesting(ctx context.Context) error {
	if err := tt.certificateTester.TestCertificates(ctx); err != nil {
		tt.recordFailedTest()
		return err
	}

	// Get results from certificate tester
	certResults, certVulns := tt.certificateTester.GetResults()

	tt.mu.Lock()
	tt.certificateResults = append(tt.certificateResults, certResults...)
	tt.vulnerabilities = append(tt.vulnerabilities, certVulns...)
	tt.testsExecuted += len(certResults)
	tt.successfulTests += len(certResults)
	tt.mu.Unlock()

	return nil
}

// executeDowngradeTesting runs protocol downgrade tests
func (tt *TLSTester) executeDowngradeTesting(ctx context.Context) error {
	if err := tt.downgradeTester.TestDowngrade(ctx); err != nil {
		tt.recordFailedTest()
		return err
	}

	// Get results from downgrade tester
	downgradeResults, downgradeVulns := tt.downgradeTester.GetResults()

	tt.mu.Lock()
	tt.downgradeResults = append(tt.downgradeResults, downgradeResults...)
	tt.vulnerabilities = append(tt.vulnerabilities, downgradeVulns...)
	tt.testsExecuted += len(downgradeResults)
	tt.successfulTests += len(downgradeResults)
	tt.mu.Unlock()

	return nil
}

// collectResults aggregates results from all sub-testers
func (tt *TLSTester) collectResults(result *TLSTestResult) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	// Copy vulnerabilities
	result.VulnerabilitiesFound = make([]TLSVulnerability, len(tt.vulnerabilities))
	copy(result.VulnerabilitiesFound, tt.vulnerabilities)

	// Copy cipher results
	if len(tt.cipherResults) > 0 {
		result.CipherTests = make([]CipherTestResult, len(tt.cipherResults))
		copy(result.CipherTests, tt.cipherResults)
	}

	// Copy certificate results
	if len(tt.certificateResults) > 0 {
		result.CertificateTests = make([]CertificateTestResult, len(tt.certificateResults))
		copy(result.CertificateTests, tt.certificateResults)
	}

	// Copy downgrade results
	if len(tt.downgradeResults) > 0 {
		result.DowngradeTests = make([]DowngradeTestResult, len(tt.downgradeResults))
		copy(result.DowngradeTests, tt.downgradeResults)
	}

	// Calculate TLS-specific metrics
	result.WeakCiphersFound = tt.countWeakCiphers()
	result.CertificateIssues = tt.countCertificateIssues()
	result.SupportedTLSVersions = tt.extractSupportedVersions()
}

// countWeakCiphers counts the number of weak cipher suites found
func (tt *TLSTester) countWeakCiphers() int {
	count := 0
	for _, cipher := range tt.cipherResults {
		if cipher.SecurityLevel == "weak" || cipher.SecurityLevel == "insecure" {
			count++
		}
	}
	return count
}

// countCertificateIssues counts certificate-related security issues
func (tt *TLSTester) countCertificateIssues() int {
	count := 0
	for _, cert := range tt.certificateResults {
		if len(cert.SecurityIssues) > 0 || cert.IsExpired || cert.WeakSignature || cert.WeakKeyLength {
			count++
		}
	}
	return count
}

// extractSupportedVersions extracts supported TLS versions from test results
func (tt *TLSTester) extractSupportedVersions() []string {
	versionMap := make(map[string]bool)

	// From cipher tests
	for _, cipher := range tt.cipherResults {
		if cipher.Supported {
			versionMap[cipher.TLSVersion] = true
		}
	}

	// From downgrade tests
	for _, downgrade := range tt.downgradeResults {
		if downgrade.DowngradeForced {
			versionMap[downgrade.NegotiatedVersion] = true
		}
	}

	versions := make([]string, 0, len(versionMap))
	for version := range versionMap {
		versions = append(versions, version)
	}

	return versions
}

// recordFailedTest increments the failed test counter
func (tt *TLSTester) recordFailedTest() {
	tt.mu.Lock()
	tt.failedTests++
	tt.testsExecuted++
	tt.mu.Unlock()
}

// GetDetailedResults returns detailed results from all sub-testers
func (tt *TLSTester) GetDetailedResults() ([]CipherTestResult, []CertificateTestResult, []DowngradeTestResult, []TLSVulnerability) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	// Make copies to avoid race conditions
	cipherResults := make([]CipherTestResult, len(tt.cipherResults))
	copy(cipherResults, tt.cipherResults)

	certResults := make([]CertificateTestResult, len(tt.certificateResults))
	copy(certResults, tt.certificateResults)

	downgradeResults := make([]DowngradeTestResult, len(tt.downgradeResults))
	copy(downgradeResults, tt.downgradeResults)

	vulnerabilities := make([]TLSVulnerability, len(tt.vulnerabilities))
	copy(vulnerabilities, tt.vulnerabilities)

	return cipherResults, certResults, downgradeResults, vulnerabilities
}

// GetStats returns testing statistics
func (tt *TLSTester) GetStats() (int, int, int, float64) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	totalVulns := len(tt.vulnerabilities)
	return tt.testsExecuted, tt.successfulTests, totalVulns, 0.0 // RequestsPerSecond calculated in Execute
}

// GetSummary returns a summary of TLS security findings
func (tt *TLSTester) GetSummary() map[string]interface{} {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	summary := map[string]interface{}{
		"tests_executed":     tt.testsExecuted,
		"vulnerabilities":    len(tt.vulnerabilities),
		"weak_ciphers":       tt.countWeakCiphers(),
		"certificate_issues": tt.countCertificateIssues(),
		"supported_versions": tt.extractSupportedVersions(),
		"critical_issues":    tt.countVulnerabilitiesBySeverity("critical"),
		"high_issues":        tt.countVulnerabilitiesBySeverity("high"),
		"medium_issues":      tt.countVulnerabilitiesBySeverity("medium"),
		"low_issues":         tt.countVulnerabilitiesBySeverity("low"),
	}

	return summary
}

// countVulnerabilitiesBySeverity counts vulnerabilities by severity level
func (tt *TLSTester) countVulnerabilitiesBySeverity(severity string) int {
	count := 0
	for _, vuln := range tt.vulnerabilities {
		if vuln.Severity == severity {
			count++
		}
	}
	return count
}

// Close cleans up resources used by the tester and all sub-testers
func (tt *TLSTester) Close() {
	// Close HTTP client
	if tt.httpClient != nil {
		tt.httpClient.Close()
	}

	// Sub-testers don't have Close methods as they don't hold persistent resources
	// The individual testers use the main HTTP client or create temporary connections
}

// Validate performs pre-execution validation
func (tt *TLSTester) Validate() error {
	// Validate target URL
	if tt.target.BaseURL == "" {
		return fmt.Errorf("target URL is required for TLS testing")
	}

	targetURL, err := url.Parse(tt.target.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if targetURL.Scheme != "https" {
		return fmt.Errorf("TLS testing requires HTTPS target")
	}

	// Validate that at least one test type is enabled
	if !tt.config.TestCipherSuites && !tt.config.TestCertificates && !tt.config.TestDowngrade {
		return fmt.Errorf("at least one TLS test type must be enabled")
	}

	return nil
}

// GetConfiguration returns the current TLS testing configuration
func (tt *TLSTester) GetConfiguration() *config.TLSAttackConfig {
	return tt.config
}

// SetConfiguration updates the TLS testing configuration
func (tt *TLSTester) SetConfiguration(newConfig *config.TLSAttackConfig) error {
	if newConfig == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	tt.config = newConfig

	// Reinitialize sub-testers with new config
	return tt.initializeSubTesters()
}
