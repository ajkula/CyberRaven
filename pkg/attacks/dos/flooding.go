package dos

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// DoSTestResult represents the result of DoS security testing
type DoSTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                `json:"tests_executed"`
	VulnerabilitiesFound []DoSVulnerability `json:"vulnerabilities_found"`
	AttackResults        []AttackResult     `json:"attack_results"`

	// Performance metrics
	TotalRequestsSent  int64   `json:"total_requests_sent"`
	RequestsPerSecond  float64 `json:"requests_per_second"`
	SuccessfulRequests int64   `json:"successful_requests"`
	FailedRequests     int64   `json:"failed_requests"`
	TimeoutRequests    int64   `json:"timeout_requests"`

	// DoS-specific metrics
	MaxConcurrentConns  int           `json:"max_concurrent_connections"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	ResponseTimeSpike   time.Duration `json:"response_time_spike"`
	ServiceDegradation  bool          `json:"service_degradation"`
}

// DoSVulnerability represents a DoS-specific security vulnerability
type DoSVulnerability struct {
	Type        string `json:"type"`     // flooding, large_payload, conn_exhaustion, slowloris
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// DoS-specific fields
	AttackDuration     time.Duration `json:"attack_duration"`
	RequestsToOverload int64         `json:"requests_to_overload"`
	RecoveryTime       time.Duration `json:"recovery_time,omitempty"`
	ServiceUnavailable bool          `json:"service_unavailable"`
	ResponseTimeDelta  time.Duration `json:"response_time_delta"`
}

// AttackResult represents the result of a specific DoS attack
type AttackResult struct {
	AttackType          string        `json:"attack_type"`
	Endpoint            string        `json:"endpoint"`
	RequestsSent        int64         `json:"requests_sent"`
	Duration            time.Duration `json:"duration"`
	SuccessRate         float64       `json:"success_rate"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	MinResponseTime     time.Duration `json:"min_response_time"`
	ServiceImpacted     bool          `json:"service_impacted"`
}

// DoSTester handles DoS attack testing
type DoSTester struct {
	config     *config.DoSAttackConfig
	target     *config.TargetConfig
	httpClient *utils.HTTPClient

	// Test parameters
	testEndpoints []string

	// Results tracking
	mu                 sync.RWMutex
	testsExecuted      int
	vulnerabilities    []DoSVulnerability
	attackResults      []AttackResult
	totalRequests      int64
	successfulRequests int64
	failedRequests     int64
	timeoutRequests    int64
	responseTimes      []time.Duration
}

// NewDoSTester creates a new DoS security tester
func NewDoSTester(dosConfig *config.DoSAttackConfig, targetConfig *config.TargetConfig) (*DoSTester, error) {
	// Create engine config specifically for DoS testing - VERY controlled
	engineConfig := &config.EngineConfig{
		MaxWorkers: dosConfig.MaxConnections, // Use configured max connections
		Timeout:    15 * time.Second,         // Longer timeout to detect slowness
		RateLimit:  dosConfig.FloodingRate,   // Use configured flooding rate
		MaxRetries: 0,                        // No retries for DoS tests
		RetryDelay: 0,
	}

	// Ensure safe limits to prevent actual DoS of our own network
	if engineConfig.MaxWorkers > 50 {
		engineConfig.MaxWorkers = 50 // Hard limit
	}
	if engineConfig.RateLimit > 100 {
		engineConfig.RateLimit = 100 // Hard limit 100 req/sec
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &DoSTester{
		config:        dosConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		testEndpoints: getDefaultDoSEndpoints(),
	}, nil
}

// Execute performs comprehensive DoS security testing
func (dt *DoSTester) Execute(ctx context.Context) (*DoSTestResult, error) {
	startTime := time.Now()

	// CRITICAL: Limit total test duration to prevent accidental DoS
	maxTestDuration := dt.config.FloodingDuration
	if maxTestDuration > 2*time.Minute {
		maxTestDuration = 10 * time.Second // Hard limit: 2 minutes max
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, maxTestDuration+30*time.Second)
	defer cancel()

	result := &DoSTestResult{
		StartTime: startTime,
		TestType:  "DoS Security Assessment (Controlled)",
		BaseURL:   dt.target.BaseURL,
	}

	// Execute different DoS tests based on configuration
	if dt.config.TestFlooding {
		if err := dt.testRequestFlooding(timeoutCtx); err != nil {
			return nil, fmt.Errorf("request flooding testing failed: %w", err)
		}
	}

	if dt.config.TestLargePayloads {
		if err := dt.testLargePayloads(timeoutCtx); err != nil {
			return nil, fmt.Errorf("large payload testing failed: %w", err)
		}
	}

	if dt.config.TestConnExhaustion {
		if err := dt.testConnectionExhaustion(timeoutCtx); err != nil {
			return nil, fmt.Errorf("connection exhaustion testing failed: %w", err)
		}
	}

	// Finalize results
	dt.mu.RLock()
	result.TestsExecuted = dt.testsExecuted
	result.VulnerabilitiesFound = make([]DoSVulnerability, len(dt.vulnerabilities))
	copy(result.VulnerabilitiesFound, dt.vulnerabilities)
	result.AttackResults = make([]AttackResult, len(dt.attackResults))
	copy(result.AttackResults, dt.attackResults)
	result.TotalRequestsSent = dt.totalRequests
	result.SuccessfulRequests = dt.successfulRequests
	result.FailedRequests = dt.failedRequests
	result.TimeoutRequests = dt.timeoutRequests
	result.MaxConcurrentConns = dt.config.MaxConnections

	// Calculate average response time
	if len(dt.responseTimes) > 0 {
		var total time.Duration
		var maxTime time.Duration
		for _, t := range dt.responseTimes {
			total += t
			if t > maxTime {
				maxTime = t
			}
		}
		result.AverageResponseTime = total / time.Duration(len(dt.responseTimes))
		result.ResponseTimeSpike = maxTime

		// Detect service degradation (response time > 5x average)
		if maxTime > result.AverageResponseTime*5 && result.AverageResponseTime > 100*time.Millisecond {
			result.ServiceDegradation = true
		}
	}
	dt.mu.RUnlock()

	// Calculate metrics
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if result.Duration.Seconds() > 0 {
		result.RequestsPerSecond = float64(result.TotalRequestsSent) / result.Duration.Seconds()
	}

	return result, nil
}

// testRequestFlooding tests request flooding DoS attacks
func (dt *DoSTester) testRequestFlooding(ctx context.Context) error {
	// Test limited endpoints to prevent actual DoS
	maxEndpoints := 2
	endpoints := dt.testEndpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := dt.performFloodingAttack(ctx, endpoint); err != nil {
			continue // Log error but continue testing
		}
	}

	return nil
}

// performFloodingAttack performs a controlled flooding attack
func (dt *DoSTester) performFloodingAttack(ctx context.Context, endpoint string) error {
	dt.incrementTestCount()

	floodingDuration := dt.config.FloodingDuration
	if floodingDuration > 30*time.Second {
		floodingDuration = 10 * time.Second // Hard limit: 30 seconds max
	}

	floodingRate := dt.config.FloodingRate
	if floodingRate > 50 {
		floodingRate = 50 // Hard limit: 50 req/sec max
	}

	// Create flooding context with timeout
	floodCtx, cancel := context.WithTimeout(ctx, floodingDuration)
	defer cancel()

	var wg sync.WaitGroup
	requestCount := int64(0)
	successCount := int64(0)
	errorCount := int64(0)
	timeoutCount := int64(0)

	var responseTimes []time.Duration
	var responseTimesMutex sync.Mutex

	// Calculate baseline response time first
	baselineTime, err := dt.measureBaselineResponseTime(ctx, endpoint)
	if err != nil {
		baselineTime = 100 * time.Millisecond // Default baseline
	}

	// Start flooding attack
	ticker := time.NewTicker(time.Second / time.Duration(floodingRate))
	defer ticker.Stop()

	attackStart := time.Now()

flood_loop:
	for {
		select {
		case <-floodCtx.Done():
			break flood_loop
		case <-ticker.C:
			wg.Add(1)
			go func() {
				defer wg.Done()

				atomic.AddInt64(&requestCount, 1)
				dt.recordTotalRequest()

				startTime := time.Now()
				resp, err := dt.httpClient.Get(floodCtx, dt.target.BaseURL+endpoint)
				responseTime := time.Since(startTime)

				responseTimesMutex.Lock()
				responseTimes = append(responseTimes, responseTime)
				dt.recordResponseTime(responseTime)
				responseTimesMutex.Unlock()

				if err != nil {
					if strings.Contains(err.Error(), "timeout") {
						atomic.AddInt64(&timeoutCount, 1)
						dt.recordTimeoutRequest()
					} else {
						atomic.AddInt64(&errorCount, 1)
						dt.recordFailedRequest()
					}
					return
				}
				defer resp.Body.Close()

				atomic.AddInt64(&successCount, 1)
				dt.recordSuccessfulRequest()
			}()
		}
	}

	// Wait for all requests to complete
	wg.Wait()

	attackDuration := time.Since(attackStart)

	// Analyze results
	responseTimesMutex.Lock()
	var avgResponseTime, maxResponseTime time.Duration
	if len(responseTimes) > 0 {
		var total time.Duration
		maxResponseTime = responseTimes[0]
		for _, t := range responseTimes {
			total += t
			if t > maxResponseTime {
				maxResponseTime = t
			}
		}
		avgResponseTime = total / time.Duration(len(responseTimes))
	}
	responseTimesMutex.Unlock()

	// Record attack result
	attackResult := AttackResult{
		AttackType:          "request_flooding",
		Endpoint:            endpoint,
		RequestsSent:        requestCount,
		Duration:            attackDuration,
		SuccessRate:         float64(successCount) / float64(requestCount) * 100,
		AverageResponseTime: avgResponseTime,
		MaxResponseTime:     maxResponseTime,
		MinResponseTime:     baselineTime,
		ServiceImpacted:     maxResponseTime > baselineTime*3, // 3x slowdown = impact
	}
	dt.recordAttackResult(attackResult)

	// Check for DoS vulnerability
	if attackResult.ServiceImpacted || float64(timeoutCount)/float64(requestCount) > 0.1 {
		vuln := DoSVulnerability{
			Type:               "flooding",
			Severity:           dt.calculateFloodingSeverity(attackResult, float64(timeoutCount)/float64(requestCount)),
			Endpoint:           endpoint,
			Method:             "GET",
			Description:        "Service vulnerable to request flooding DoS attacks",
			Evidence:           fmt.Sprintf("Response time increased from %v to %v, %d timeouts out of %d requests", baselineTime, maxResponseTime, timeoutCount, requestCount),
			Remediation:        "Implement rate limiting, request throttling, and DDoS protection",
			RiskScore:          dt.calculateFloodingRiskScore(attackResult, float64(timeoutCount)/float64(requestCount)),
			AttackDuration:     attackDuration,
			RequestsToOverload: requestCount,
			ServiceUnavailable: float64(timeoutCount)/float64(requestCount) > 0.5,
			ResponseTimeDelta:  maxResponseTime - baselineTime,
		}
		dt.recordVulnerability(vuln)
	}

	return nil
}

// testLargePayloads tests large payload DoS attacks
func (dt *DoSTester) testLargePayloads(ctx context.Context) error {
	// Test limited endpoints with large payloads
	endpoint := "/api/upload" // Common upload endpoint
	if len(dt.testEndpoints) > 0 {
		endpoint = dt.testEndpoints[0] // Use first endpoint as test
	}

	payloadSizes := []int{
		1024 * 1024,      // 1MB
		5 * 1024 * 1024,  // 5MB
		10 * 1024 * 1024, // 10MB (if configured)
	}

	maxSize := dt.config.MaxPayloadSize
	if maxSize <= 0 {
		maxSize = 5 * 1024 * 1024 // Default 5MB max
	}

	for _, size := range payloadSizes {
		if size > maxSize {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := dt.testLargePayload(ctx, endpoint, size); err != nil {
			continue
		}

		// Add delay between large payload tests
		time.Sleep(2 * time.Second)
	}

	return nil
}

// testLargePayload tests a specific large payload size
func (dt *DoSTester) testLargePayload(ctx context.Context, endpoint string, payloadSize int) error {
	dt.incrementTestCount()

	// Create large payload
	payload := strings.Repeat("A", payloadSize)

	// Measure baseline first
	baselineTime, _ := dt.measureBaselineResponseTime(ctx, endpoint)

	// Send large payload
	headers := map[string]string{
		"Content-Type": "application/octet-stream",
	}

	startTime := time.Now()
	resp, err := dt.httpClient.Post(ctx, dt.target.BaseURL+endpoint, strings.NewReader(payload), headers)
	responseTime := time.Since(startTime)

	dt.recordTotalRequest()
	dt.recordResponseTime(responseTime)

	if err != nil {
		dt.recordFailedRequest()

		// Check if it's a timeout (potential DoS)
		if strings.Contains(err.Error(), "timeout") {
			dt.recordTimeoutRequest()

			vuln := DoSVulnerability{
				Type:               "large_payload",
				Severity:           "medium",
				Endpoint:           endpoint,
				Method:             "POST",
				Description:        fmt.Sprintf("Service vulnerable to large payload DoS attacks (%d bytes)", payloadSize),
				Evidence:           fmt.Sprintf("Request with %d bytes payload caused timeout", payloadSize),
				Remediation:        "Implement payload size limits and request timeout protection",
				RiskScore:          70,
				AttackDuration:     responseTime,
				ServiceUnavailable: true,
			}
			dt.recordVulnerability(vuln)
		}
		return err
	}
	defer resp.Body.Close()

	dt.recordSuccessfulRequest()

	// Check for significant slowdown
	if responseTime > baselineTime*5 && responseTime > 5*time.Second {
		vuln := DoSVulnerability{
			Type:              "large_payload",
			Severity:          "low",
			Endpoint:          endpoint,
			Method:            "POST",
			Description:       fmt.Sprintf("Service shows performance degradation with large payloads (%d bytes)", payloadSize),
			Evidence:          fmt.Sprintf("Response time increased from %v to %v with large payload", baselineTime, responseTime),
			Remediation:       "Implement efficient payload processing and streaming",
			RiskScore:         45,
			AttackDuration:    responseTime,
			ResponseTimeDelta: responseTime - baselineTime,
		}
		dt.recordVulnerability(vuln)
	}

	return nil
}

// testConnectionExhaustion tests connection exhaustion attacks
func (dt *DoSTester) testConnectionExhaustion(ctx context.Context) error {
	// Very conservative connection exhaustion test
	maxConnections := dt.config.MaxConnections
	if maxConnections > 20 {
		maxConnections = 20 // Hard limit for safety
	}

	if maxConnections < 5 {
		maxConnections = 5 // Minimum for meaningful test
	}

	endpoint := dt.testEndpoints[0]

	dt.incrementTestCount()

	// Open multiple connections simultaneously
	var wg sync.WaitGroup
	connectionCount := int64(0)
	successCount := int64(0)
	errorCount := int64(0)

	// Create connections
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			atomic.AddInt64(&connectionCount, 1)
			dt.recordTotalRequest()

			// Hold connection open for a short time
			resp, err := dt.httpClient.Get(ctx, dt.target.BaseURL+endpoint)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				dt.recordFailedRequest()
				return
			}
			defer resp.Body.Close()

			atomic.AddInt64(&successCount, 1)
			dt.recordSuccessfulRequest()

			// Hold connection briefly
			time.Sleep(5 * time.Second)
		}()

		// Small delay between connection attempts
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	// Analyze connection exhaustion results
	errorRate := float64(errorCount) / float64(connectionCount)
	if errorRate > 0.2 { // More than 20% errors
		vuln := DoSVulnerability{
			Type:               "conn_exhaustion",
			Severity:           "medium",
			Endpoint:           endpoint,
			Method:             "GET",
			Description:        "Service vulnerable to connection exhaustion attacks",
			Evidence:           fmt.Sprintf("%.1f%% connection failures with %d concurrent connections", errorRate*100, maxConnections),
			Remediation:        "Implement connection limits, connection pooling, and proper resource management",
			RiskScore:          60,
			RequestsToOverload: connectionCount,
			ServiceUnavailable: errorRate > 0.5,
		}
		dt.recordVulnerability(vuln)
	}

	return nil
}

// Helper methods

func (dt *DoSTester) measureBaselineResponseTime(ctx context.Context, endpoint string) (time.Duration, error) {
	startTime := time.Now()
	resp, err := dt.httpClient.Get(ctx, dt.target.BaseURL+endpoint)
	responseTime := time.Since(startTime)

	if resp != nil {
		resp.Body.Close()
	}

	return responseTime, err
}

func (dt *DoSTester) calculateFloodingSeverity(result AttackResult, timeoutRate float64) string {
	if timeoutRate > 0.5 || !result.ServiceImpacted {
		return "high"
	}
	if timeoutRate > 0.2 || result.MaxResponseTime > result.MinResponseTime*10 {
		return "medium"
	}
	return "low"
}

func (dt *DoSTester) calculateFloodingRiskScore(result AttackResult, timeoutRate float64) int {
	score := 30 // Base score

	if timeoutRate > 0.5 {
		score += 40
	} else if timeoutRate > 0.2 {
		score += 25
	}

	if result.MaxResponseTime > result.MinResponseTime*10 {
		score += 20
	}

	if result.SuccessRate < 50 {
		score += 15
	}

	return min(100, score)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Default endpoints for DoS testing
func getDefaultDoSEndpoints() []string {
	return []string{
		"/", "/api", "/login", // Very limited for safety
	}
}

// Thread-safe methods

func (dt *DoSTester) incrementTestCount() {
	dt.mu.Lock()
	dt.testsExecuted++
	dt.mu.Unlock()
}

func (dt *DoSTester) recordVulnerability(vuln DoSVulnerability) {
	dt.mu.Lock()
	dt.vulnerabilities = append(dt.vulnerabilities, vuln)
	dt.mu.Unlock()
}

func (dt *DoSTester) recordAttackResult(result AttackResult) {
	dt.mu.Lock()
	dt.attackResults = append(dt.attackResults, result)
	dt.mu.Unlock()
}

func (dt *DoSTester) recordTotalRequest() {
	atomic.AddInt64(&dt.totalRequests, 1)
}

func (dt *DoSTester) recordSuccessfulRequest() {
	atomic.AddInt64(&dt.successfulRequests, 1)
}

func (dt *DoSTester) recordFailedRequest() {
	atomic.AddInt64(&dt.failedRequests, 1)
}

func (dt *DoSTester) recordTimeoutRequest() {
	atomic.AddInt64(&dt.timeoutRequests, 1)
}

func (dt *DoSTester) recordResponseTime(duration time.Duration) {
	dt.mu.Lock()
	dt.responseTimes = append(dt.responseTimes, duration)
	dt.mu.Unlock()
}

// Close cleans up resources used by the tester
func (dt *DoSTester) Close() {
	if dt.httpClient != nil {
		dt.httpClient.Close()
	}
}
