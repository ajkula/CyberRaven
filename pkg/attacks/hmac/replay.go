package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// HMACTestResult represents the result of HMAC security testing
type HMACTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                 `json:"tests_executed"`
	VulnerabilitiesFound []HMACVulnerability `json:"vulnerabilities_found"`
	SignatureTests       []SignatureTest     `json:"signature_tests"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`

	// HMAC-specific metrics
	ReplayAttemptsSuccessful int           `json:"replay_attempts_successful"`
	TimingAnomaliesDetected  int           `json:"timing_anomalies_detected"`
	AverageResponseTime      time.Duration `json:"average_response_time"`
}

// HMACVulnerability represents an HMAC-specific security vulnerability
type HMACVulnerability struct {
	Type        string `json:"type"`     // replay, timing, weak_secret, bypass
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// HMAC-specific fields
	Algorithm         string        `json:"algorithm"`
	TimestampUsed     *time.Time    `json:"timestamp_used,omitempty"`
	ResponseTime      time.Duration `json:"response_time"`
	AttackVector      string        `json:"attack_vector"`
	OriginalSignature string        `json:"original_signature,omitempty"`
	ForgedSignature   string        `json:"forged_signature,omitempty"`
}

// SignatureTest represents a tested HMAC signature
type SignatureTest struct {
	Endpoint     string        `json:"endpoint"`
	Method       string        `json:"method"`
	Algorithm    string        `json:"algorithm"`
	Timestamp    time.Time     `json:"timestamp"`
	Signature    string        `json:"signature"`
	Valid        bool          `json:"valid"`
	ResponseTime time.Duration `json:"response_time"`
	ResponseCode int           `json:"response_code"`
	TestType     string        `json:"test_type"` // normal, replay, timing, forged
}

// HMACTester handles HMAC security testing
type HMACTester struct {
	config     *config.HMACAttackConfig
	target     *config.TargetConfig
	httpClient *utils.HTTPClient

	// Test parameters
	testEndpoints []string
	algorithms    map[string]func() hash.Hash
	commonSecrets []string

	// Results tracking
	mu                       sync.RWMutex
	testsExecuted            int
	vulnerabilities          []HMACVulnerability
	signatureTests           []SignatureTest
	successfulTests          int
	failedTests              int
	replayAttemptsSuccessful int
	timingAnomalies          int
	responseTimes            []time.Duration
}

// NewHMACTester creates a new HMAC security tester
func NewHMACTester(hmacConfig *config.HMACAttackConfig, targetConfig *config.TargetConfig) (*HMACTester, error) {
	// Create default engine config for HTTP client
	engineConfig := &config.EngineConfig{
		MaxWorkers: 5,                // Lower concurrency for timing attacks
		Timeout:    10 * time.Second, // Longer timeout for timing analysis
		RateLimit:  10,
		MaxRetries: 1, // Minimal retries for timing consistency
		RetryDelay: 1 * time.Second,
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Initialize algorithms map
	algorithms := map[string]func() hash.Hash{
		"sha256": sha256.New,
		"sha512": sha512.New,
	}

	return &HMACTester{
		config:        hmacConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		testEndpoints: getDefaultHMACEndpoints(),
		algorithms:    algorithms,
		commonSecrets: getDefaultHMACSecrets(),
	}, nil
}

// Execute performs comprehensive HMAC security testing
func (ht *HMACTester) Execute(ctx context.Context) (*HMACTestResult, error) {
	startTime := time.Now()

	result := &HMACTestResult{
		StartTime: startTime,
		TestType:  "HMAC Security Assessment",
		BaseURL:   ht.target.BaseURL,
	}

	// Execute different HMAC tests based on configuration
	if ht.config.TestReplay {
		if err := ht.testReplayAttacks(ctx); err != nil {
			return nil, fmt.Errorf("HMAC replay testing failed: %w", err)
		}
	}

	if ht.config.TestTiming {
		if err := ht.testTimingAttacks(ctx); err != nil {
			return nil, fmt.Errorf("HMAC timing testing failed: %w", err)
		}
	}

	// Test signature bypass attempts
	if err := ht.testSignatureBypass(ctx); err != nil {
		return nil, fmt.Errorf("HMAC signature bypass testing failed: %w", err)
	}

	// Finalize results
	ht.mu.RLock()
	result.TestsExecuted = ht.testsExecuted
	result.VulnerabilitiesFound = make([]HMACVulnerability, len(ht.vulnerabilities))
	copy(result.VulnerabilitiesFound, ht.vulnerabilities)
	result.SignatureTests = make([]SignatureTest, len(ht.signatureTests))
	copy(result.SignatureTests, ht.signatureTests)
	result.SuccessfulTests = ht.successfulTests
	result.FailedTests = ht.failedTests
	result.ReplayAttemptsSuccessful = ht.replayAttemptsSuccessful
	result.TimingAnomaliesDetected = ht.timingAnomalies

	// Calculate average response time
	if len(ht.responseTimes) > 0 {
		var total time.Duration
		for _, rt := range ht.responseTimes {
			total += rt
		}
		result.AverageResponseTime = total / time.Duration(len(ht.responseTimes))
	}
	ht.mu.RUnlock()

	// Calculate metrics
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Get HTTP client statistics
	_, _, requestsPerSecond := ht.httpClient.GetStats()
	result.RequestsPerSecond = requestsPerSecond

	return result, nil
}

// testReplayAttacks tests for HMAC replay vulnerabilities
func (ht *HMACTester) testReplayAttacks(ctx context.Context) error {
	for _, endpoint := range ht.testEndpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// First, make a legitimate request to capture the signature
		originalSig, originalTimestamp, err := ht.captureValidSignature(ctx, endpoint)
		if err != nil {
			continue // Skip if we can't capture a valid signature
		}

		// Wait for replay window to potentially expire
		time.Sleep(1 * time.Second)

		// Attempt to replay the request with the same signature
		if err := ht.attemptReplayAttack(ctx, endpoint, originalSig, originalTimestamp); err != nil {
			continue
		}
	}

	return nil
}

// testTimingAttacks tests for timing-based HMAC vulnerabilities
func (ht *HMACTester) testTimingAttacks(ctx context.Context) error {
	if ht.config.TimingRequests < 10 {
		ht.config.TimingRequests = 50 // Default to 50 requests for statistical significance
	}

	for _, endpoint := range ht.testEndpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Perform timing analysis
		if err := ht.performTimingAnalysis(ctx, endpoint); err != nil {
			continue
		}
	}

	return nil
}

// testSignatureBypass tests various signature bypass techniques
func (ht *HMACTester) testSignatureBypass(ctx context.Context) error {
	for _, endpoint := range ht.testEndpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Test different bypass techniques
		ht.testEmptySignature(ctx, endpoint)
		ht.testNullSignature(ctx, endpoint)
		ht.testMalformedSignature(ctx, endpoint)
		ht.testSignatureRemoval(ctx, endpoint)
	}

	return nil
}

// captureValidSignature captures a valid HMAC signature from the target
func (ht *HMACTester) captureValidSignature(ctx context.Context, endpoint string) (string, time.Time, error) {
	ht.incrementTestCount()

	// Create a request with proper HMAC authentication if configured
	timestamp := time.Now()
	signature := ""

	// If we have HMAC config, generate a proper signature
	if ht.target.Auth.Type == "hmac" && ht.target.Auth.HMAC.Secret != "" {
		signature = ht.generateHMAC(endpoint, "GET", timestamp)
	}

	headers := map[string]string{}
	if ht.target.Auth.HMAC.SignatureHeader != "" {
		headers[ht.target.Auth.HMAC.SignatureHeader] = signature
	}
	if ht.target.Auth.HMAC.TimestampHeader != "" {
		headers[ht.target.Auth.HMAC.TimestampHeader] = strconv.FormatInt(timestamp.Unix(), 10)
	}

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, "GET", ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		ht.recordFailedTest()
		return "", timestamp, err
	}
	defer resp.Body.Close()

	ht.recordSuccessfulTest()
	ht.recordResponseTime(responseTime)

	// Record signature test
	sigTest := SignatureTest{
		Endpoint:     endpoint,
		Method:       "GET",
		Algorithm:    ht.target.Auth.HMAC.Algorithm,
		Timestamp:    timestamp,
		Signature:    signature,
		Valid:        resp.StatusCode < 400,
		ResponseTime: responseTime,
		ResponseCode: resp.StatusCode,
		TestType:     "normal",
	}
	ht.recordSignatureTest(sigTest)

	return signature, timestamp, nil
}

// attemptReplayAttack attempts to replay a captured signature
func (ht *HMACTester) attemptReplayAttack(ctx context.Context, endpoint, signature string, timestamp time.Time) error {
	ht.incrementTestCount()

	headers := map[string]string{}
	if ht.target.Auth.HMAC.SignatureHeader != "" {
		headers[ht.target.Auth.HMAC.SignatureHeader] = signature
	}
	if ht.target.Auth.HMAC.TimestampHeader != "" {
		headers[ht.target.Auth.HMAC.TimestampHeader] = strconv.FormatInt(timestamp.Unix(), 10)
	}

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, "GET", ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		ht.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	ht.recordSuccessfulTest()
	ht.recordResponseTime(responseTime)

	// Record signature test
	sigTest := SignatureTest{
		Endpoint:     endpoint,
		Method:       "GET",
		Algorithm:    ht.target.Auth.HMAC.Algorithm,
		Timestamp:    timestamp,
		Signature:    signature,
		Valid:        resp.StatusCode < 400,
		ResponseTime: responseTime,
		ResponseCode: resp.StatusCode,
		TestType:     "replay",
	}
	ht.recordSignatureTest(sigTest)

	// Check if replay was successful (vulnerability)
	if resp.StatusCode < 400 {
		ht.recordReplaySuccess()

		vuln := HMACVulnerability{
			Type:              "replay",
			Severity:          "high",
			Endpoint:          endpoint,
			Method:            "GET",
			Description:       "HMAC signature replay attack successful",
			Evidence:          fmt.Sprintf("Replayed signature accepted after %v delay", time.Since(timestamp)),
			Remediation:       "Implement timestamp validation and nonce tracking to prevent replay attacks",
			RiskScore:         85,
			Algorithm:         ht.target.Auth.HMAC.Algorithm,
			TimestampUsed:     &timestamp,
			ResponseTime:      responseTime,
			AttackVector:      "Signature replay attack",
			OriginalSignature: signature,
		}
		ht.recordVulnerability(vuln)
	}

	return nil
}

// performTimingAnalysis performs statistical timing analysis
func (ht *HMACTester) performTimingAnalysis(ctx context.Context, endpoint string) error {
	var validTimes, invalidTimes []time.Duration

	// Test with valid signatures
	for i := 0; i < ht.config.TimingRequests/2; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		responseTime, err := ht.testSignatureValidation(ctx, endpoint, true)
		if err == nil {
			validTimes = append(validTimes, responseTime)
		}
	}

	// Test with invalid signatures
	for i := 0; i < ht.config.TimingRequests/2; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		responseTime, err := ht.testSignatureValidation(ctx, endpoint, false)
		if err == nil {
			invalidTimes = append(invalidTimes, responseTime)
		}
	}

	// Analyze timing differences
	if len(validTimes) > 5 && len(invalidTimes) > 5 {
		validAvg := calculateAverage(validTimes)
		invalidAvg := calculateAverage(invalidTimes)

		// Check for significant timing difference (potential vulnerability)
		timeDiff := validAvg - invalidAvg
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}

		// If difference is > 10ms or > 20% of average time, consider it suspicious
		threshold := time.Duration(float64(validAvg) * 0.2)
		if threshold < 10*time.Millisecond {
			threshold = 10 * time.Millisecond
		}

		if timeDiff > threshold {
			ht.recordTimingAnomaly()

			vuln := HMACVulnerability{
				Type:         "timing",
				Severity:     "medium",
				Endpoint:     endpoint,
				Method:       "GET",
				Description:  "HMAC timing attack vulnerability detected",
				Evidence:     fmt.Sprintf("Timing difference between valid and invalid signatures: %v", timeDiff),
				Remediation:  "Implement constant-time HMAC verification to prevent timing attacks",
				RiskScore:    65,
				Algorithm:    ht.target.Auth.HMAC.Algorithm,
				ResponseTime: timeDiff,
				AttackVector: "Timing analysis attack",
			}
			ht.recordVulnerability(vuln)
		}
	}

	return nil
}

// testSignatureValidation tests a signature and returns response time
func (ht *HMACTester) testSignatureValidation(ctx context.Context, endpoint string, useValidSignature bool) (time.Duration, error) {
	ht.incrementTestCount()

	timestamp := time.Now()
	var signature string

	if useValidSignature && ht.target.Auth.Type == "hmac" {
		signature = ht.generateHMAC(endpoint, "GET", timestamp)
	} else {
		// Generate invalid signature
		signature = ht.generateInvalidHMAC()
	}

	headers := map[string]string{}
	if ht.target.Auth.HMAC.SignatureHeader != "" {
		headers[ht.target.Auth.HMAC.SignatureHeader] = signature
	}
	if ht.target.Auth.HMAC.TimestampHeader != "" {
		headers[ht.target.Auth.HMAC.TimestampHeader] = strconv.FormatInt(timestamp.Unix(), 10)
	}

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, "GET", ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		ht.recordFailedTest()
		return 0, err
	}
	defer resp.Body.Close()

	ht.recordSuccessfulTest()
	ht.recordResponseTime(responseTime)

	return responseTime, nil
}

// Signature bypass tests

func (ht *HMACTester) testEmptySignature(ctx context.Context, endpoint string) {
	ht.testBypassTechnique(ctx, endpoint, "", "empty_signature")
}

func (ht *HMACTester) testNullSignature(ctx context.Context, endpoint string) {
	ht.testBypassTechnique(ctx, endpoint, "null", "null_signature")
}

func (ht *HMACTester) testMalformedSignature(ctx context.Context, endpoint string) {
	malformed := []string{
		"invalid_base64!@#",
		"000000000000000000000000000000000000000000000000000000000000000",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}

	for _, sig := range malformed {
		ht.testBypassTechnique(ctx, endpoint, sig, "malformed_signature")
	}
}

func (ht *HMACTester) testSignatureRemoval(ctx context.Context, endpoint string) {
	ht.incrementTestCount()

	// Test request without signature header
	headers := map[string]string{}
	if ht.target.Auth.HMAC.TimestampHeader != "" {
		headers[ht.target.Auth.HMAC.TimestampHeader] = strconv.FormatInt(time.Now().Unix(), 10)
	}

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, "GET", ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		ht.recordFailedTest()
		return
	}
	defer resp.Body.Close()

	ht.recordSuccessfulTest()

	// Check if request was accepted without signature
	if resp.StatusCode < 400 {
		vuln := HMACVulnerability{
			Type:         "bypass",
			Severity:     "critical",
			Endpoint:     endpoint,
			Method:       "GET",
			Description:  "HMAC signature requirement bypassed",
			Evidence:     "Request accepted without HMAC signature header",
			Remediation:  "Enforce mandatory HMAC signature validation for all protected endpoints",
			RiskScore:    95,
			ResponseTime: responseTime,
			AttackVector: "Signature removal bypass",
		}
		ht.recordVulnerability(vuln)
	}
}

// testBypassTechnique tests a specific signature bypass technique
func (ht *HMACTester) testBypassTechnique(ctx context.Context, endpoint, signature, technique string) {
	ht.incrementTestCount()

	headers := map[string]string{}
	if ht.target.Auth.HMAC.SignatureHeader != "" {
		headers[ht.target.Auth.HMAC.SignatureHeader] = signature
	}
	if ht.target.Auth.HMAC.TimestampHeader != "" {
		headers[ht.target.Auth.HMAC.TimestampHeader] = strconv.FormatInt(time.Now().Unix(), 10)
	}

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, "GET", ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		ht.recordFailedTest()
		return
	}
	defer resp.Body.Close()

	ht.recordSuccessfulTest()

	// Check if bypass was successful
	if resp.StatusCode < 400 {
		vuln := HMACVulnerability{
			Type:            "bypass",
			Severity:        "high",
			Endpoint:        endpoint,
			Method:          "GET",
			Description:     fmt.Sprintf("HMAC signature bypass using %s", technique),
			Evidence:        fmt.Sprintf("Request accepted with %s signature", technique),
			Remediation:     "Implement proper HMAC signature validation and reject malformed signatures",
			RiskScore:       80,
			ResponseTime:    responseTime,
			AttackVector:    fmt.Sprintf("Signature bypass (%s)", technique),
			ForgedSignature: signature,
		}
		ht.recordVulnerability(vuln)
	}
}

// HMAC utility functions

// generateHMAC generates a proper HMAC signature
func (ht *HMACTester) generateHMAC(endpoint, method string, timestamp time.Time) string {
	if ht.target.Auth.HMAC.Secret == "" {
		return ""
	}

	// Create message to sign
	message := fmt.Sprintf("%s\n%s\n%d", method, endpoint, timestamp.Unix())

	// Select hash function
	var h func() hash.Hash
	switch strings.ToLower(ht.target.Auth.HMAC.Algorithm) {
	case "sha512":
		h = sha512.New
	default:
		h = sha256.New
	}

	// Generate HMAC
	mac := hmac.New(h, []byte(ht.target.Auth.HMAC.Secret))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature)
}

// generateInvalidHMAC generates an invalid HMAC signature
func (ht *HMACTester) generateInvalidHMAC() string {
	// Generate random invalid signatures
	invalid := []string{
		hex.EncodeToString([]byte("invalid_signature_123456789")),
		base64.StdEncoding.EncodeToString([]byte("fake_signature")),
		"0123456789abcdef" + hex.EncodeToString([]byte("wrong")),
	}

	// Rotate through invalid signatures
	index := ht.testsExecuted % len(invalid)
	return invalid[index]
}

// Default endpoints and secrets

func getDefaultHMACEndpoints() []string {
	return []string{
		"/api/authenticate", "/api/auth", "/api/login",
		"/api/user", "/api/profile", "/api/account",
		"/api/admin", "/api/secure", "/api/protected",
		"/webhook", "/api/webhook", "/callback",
	}
}

func getDefaultHMACSecrets() []string {
	return []string{
		"secret", "key", "password", "hmac_secret",
		"your-secret-key", "shared_secret", "api_key",
		"webhook_secret", "signing_key", "auth_secret",
	}
}

// Utility functions

func calculateAverage(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}

// Thread-safe methods

func (ht *HMACTester) incrementTestCount() {
	ht.mu.Lock()
	ht.testsExecuted++
	ht.mu.Unlock()
}

func (ht *HMACTester) recordSuccessfulTest() {
	ht.mu.Lock()
	ht.successfulTests++
	ht.mu.Unlock()
}

func (ht *HMACTester) recordFailedTest() {
	ht.mu.Lock()
	ht.failedTests++
	ht.mu.Unlock()
}

func (ht *HMACTester) recordVulnerability(vuln HMACVulnerability) {
	ht.mu.Lock()
	ht.vulnerabilities = append(ht.vulnerabilities, vuln)
	ht.mu.Unlock()
}

func (ht *HMACTester) recordSignatureTest(test SignatureTest) {
	ht.mu.Lock()
	ht.signatureTests = append(ht.signatureTests, test)
	ht.mu.Unlock()
}

func (ht *HMACTester) recordReplaySuccess() {
	ht.mu.Lock()
	ht.replayAttemptsSuccessful++
	ht.mu.Unlock()
}

func (ht *HMACTester) recordTimingAnomaly() {
	ht.mu.Lock()
	ht.timingAnomalies++
	ht.mu.Unlock()
}

func (ht *HMACTester) recordResponseTime(duration time.Duration) {
	ht.mu.Lock()
	ht.responseTimes = append(ht.responseTimes, duration)
	ht.mu.Unlock()
}

// Close cleans up resources used by the tester
func (ht *HMACTester) Close() {
	if ht.httpClient != nil {
		ht.httpClient.Close()
	}
}
