package hmac

import (
	"context"
	"fmt"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// NewHMACTester creates a new HMAC security tester
func NewHMACTester(hmacConfig *config.HMACAttackConfig, targetConfig *config.TargetConfig) (*HMACTester, error) {
	engineConfig := &config.EngineConfig{
		MaxWorkers: 5,
		Timeout:    1 * time.Second,
		RateLimit:  10,
		MaxRetries: 1,
		RetryDelay: 500 * time.Millisecond,
	}

	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// ✅ Load discovery intelligence
	discoveryLoader := discovery.NewDiscoveryLoader()
	var attackContext *discovery.AttackContext

	if discoveryLoader.HasDiscoveries() {
		attackContext, err = discoveryLoader.LoadAttackContext()
		if err != nil {
			printWarning(fmt.Sprintf("Failed to load discovery intelligence: %v", err), false)
			printInfo("Falling back to standard testing mode", false)
		} else {
			hmacSigs := attackContext.GetHMACSignatures()
			printSuccess(fmt.Sprintf("Loaded discovery intelligence - found %d HMAC signatures", len(hmacSigs)), false)
			age, _ := discoveryLoader.GetDiscoveryAge()
			printInfo(fmt.Sprintf("Discovery age: %v", age.Round(time.Second)), false)
		}
	} else {
		printInfo("No discovery file found - using standard testing", false)
		printInfo("Run 'cyberraven sniff' first for intelligent targeting", false)
	}

	return &HMACTester{
		config:        hmacConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		discoveryCtx:  attackContext, // ✅ Store discovery context
		testEndpoints: getDefaultHMACEndpoints(),
		algorithms:    getAlgorithmMapping(),
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

	// Initialize result tracking
	ht.resetCounters()

	// Execute different HMAC tests based on configuration
	if ht.config.TestReplay {
		replayTester := NewReplayTester(ht)
		if err := replayTester.Execute(ctx); err != nil {
			return nil, fmt.Errorf("HMAC replay testing failed: %w", err)
		}
	}

	if ht.config.TestTiming {
		timingTester := NewTimingTester(ht)
		if err := timingTester.Execute(ctx); err != nil {
			return nil, fmt.Errorf("HMAC timing testing failed: %w", err)
		}
	}

	signatureTester := NewSignatureTester(ht)
	if err := signatureTester.Execute(ctx); err != nil {
		return nil, fmt.Errorf("HMAC signature bypass testing failed: %w", err)
	}

	ht.ExploitTLSIntelligence()

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

	if len(ht.responseTimes) > 0 {
		result.AverageResponseTime = calculateAverage(ht.responseTimes)
	}
	ht.mu.RUnlock()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	_, _, requestsPerSecond := ht.httpClient.GetStats()
	result.RequestsPerSecond = requestsPerSecond

	return result, nil
}

// Thread-safe recording methods

func (ht *HMACTester) resetCounters() {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	ht.testsExecuted = 0
	ht.vulnerabilities = make([]HMACVulnerability, 0)
	ht.signatureTests = make([]SignatureTest, 0)
	ht.successfulTests = 0
	ht.failedTests = 0
	ht.replayAttemptsSuccessful = 0
	ht.timingAnomalies = 0
	ht.responseTimes = make([]time.Duration, 0)
}

func (ht *HMACTester) IncrementTestCount() {
	ht.mu.Lock()
	ht.testsExecuted++
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordSuccessfulTest() {
	ht.mu.Lock()
	ht.successfulTests++
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordFailedTest() {
	ht.mu.Lock()
	ht.failedTests++
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordVulnerability(vuln HMACVulnerability) {
	ht.mu.Lock()
	ht.vulnerabilities = append(ht.vulnerabilities, vuln)
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordSignatureTest(test SignatureTest) {
	ht.mu.Lock()
	ht.signatureTests = append(ht.signatureTests, test)
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordReplaySuccess() {
	ht.mu.Lock()
	ht.replayAttemptsSuccessful++
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordTimingAnomaly() {
	ht.mu.Lock()
	ht.timingAnomalies++
	ht.mu.Unlock()
}

func (ht *HMACTester) RecordResponseTime(duration time.Duration) {
	ht.mu.Lock()
	ht.responseTimes = append(ht.responseTimes, duration)
	ht.mu.Unlock()
}

// Accessor methods for sub-testers

func (ht *HMACTester) GetConfig() *config.HMACAttackConfig {
	return ht.config
}

func (ht *HMACTester) GetTarget() *config.TargetConfig {
	return ht.target
}

func (ht *HMACTester) GetHTTPClient() *utils.HTTPClient {
	return ht.httpClient
}

func (ht *HMACTester) GetTestEndpoints() []string {
	return ht.testEndpoints
}

func (ht *HMACTester) GetTestsExecuted() int {
	ht.mu.RLock()
	defer ht.mu.RUnlock()
	return ht.testsExecuted
}

// GetDiscoveryContext returns the discovery context for intelligent testing
func (ht *HMACTester) GetDiscoveryContext() *discovery.AttackContext {
	return ht.discoveryCtx
}

// GetIntelligentEndpoints returns discovered endpoints suitable for HMAC testing
func (ht *HMACTester) GetIntelligentEndpoints() []string {
	if ht.discoveryCtx == nil || !ht.discoveryCtx.IsIntelligenceAvailable() {
		return ht.testEndpoints
	}

	targetedEndpoints := ht.discoveryCtx.GetTargetedEndpoints("hmac")
	if len(targetedEndpoints) == 0 {
		return ht.testEndpoints
	}

	endpoints := make([]string, 0, len(targetedEndpoints))
	for _, endpoint := range targetedEndpoints {
		endpoints = append(endpoints, endpoint.Path)
	}

	return endpoints
}

// HasIntelligence returns true if discovery intelligence is available
func (ht *HMACTester) HasIntelligence() bool {
	return ht.discoveryCtx != nil && ht.discoveryCtx.IsIntelligenceAvailable()
}

// Helper method for standardized HTTP testing
func (ht *HMACTester) ExecuteHTTPTest(ctx context.Context, endpoint, method, signature string, timestamp time.Time, testType string) (*TestResponse, *SignatureTest) {
	ht.IncrementTestCount()

	headers := buildHMACHeaders(signature, timestamp, ht.target)

	startTime := time.Now()
	resp, err := ht.httpClient.Do(ctx, method, ht.target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	response := &TestResponse{
		ResponseTime: responseTime,
		Error:        err,
	}

	sigTest := &SignatureTest{
		Endpoint:     endpoint,
		Method:       method,
		Algorithm:    ht.target.Auth.HMAC.Algorithm,
		Timestamp:    timestamp,
		Signature:    signature,
		ResponseTime: responseTime,
		TestType:     testType,
	}

	if err != nil {
		ht.RecordFailedTest()
		response.Success = false
		sigTest.Valid = false
		sigTest.ResponseCode = 0
	} else {
		defer resp.Body.Close()
		ht.RecordSuccessfulTest()
		ht.RecordResponseTime(responseTime)

		response.Success = true
		response.StatusCode = resp.StatusCode
		sigTest.Valid = resp.StatusCode < 400
		sigTest.ResponseCode = resp.StatusCode
	}

	ht.RecordSignatureTest(*sigTest)
	return response, sigTest
}

func (ht *HMACTester) Close() {
	if ht.httpClient != nil {
		ht.httpClient.Close()
	}
}
