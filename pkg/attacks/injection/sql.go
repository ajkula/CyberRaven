package injection

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// InjectionTestResult represents the result of injection testing
type InjectionTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                      `json:"tests_executed"`
	VulnerabilitiesFound []InjectionVulnerability `json:"vulnerabilities_found"`
	TestedParameters     []ParameterTest          `json:"tested_parameters"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`
}

// InjectionVulnerability represents an injection-specific vulnerability
type InjectionVulnerability struct {
	Type        string `json:"type"`     // sql, nosql, json, path
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Parameter   string `json:"parameter"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// Injection-specific fields
	PayloadUsed     string `json:"payload_used"`
	ResponseSnippet string `json:"response_snippet"`
	AttackVector    string `json:"attack_vector"`
	DatabaseType    string `json:"database_type,omitempty"`
}

// ParameterTest represents a tested parameter
type ParameterTest struct {
	Endpoint     string        `json:"endpoint"`
	Method       string        `json:"method"`
	Parameter    string        `json:"parameter"`
	PayloadType  string        `json:"payload_type"`
	Vulnerable   bool          `json:"vulnerable"`
	ResponseTime time.Duration `json:"response_time"`
}

// InjectionTester handles injection attack testing
type InjectionTester struct {
	config     *config.InjectionAttackConfig
	target     *config.TargetConfig
	httpClient *utils.HTTPClient

	// Test parameters
	testEndpoints []string
	sqlPayloads   []string
	nosqlPayloads []string
	jsonPayloads  []string
	pathPayloads  []string

	// Results tracking
	mu               sync.RWMutex
	testsExecuted    int
	vulnerabilities  []InjectionVulnerability
	testedParameters []ParameterTest
	successfulTests  int
	failedTests      int
}

// NewInjectionTester creates a new injection tester
func NewInjectionTester(injConfig *config.InjectionAttackConfig, targetConfig *config.TargetConfig) (*InjectionTester, error) {
	// Create default engine config for HTTP client - MUCH more conservative
	engineConfig := &config.EngineConfig{
		MaxWorkers: 2,                // Reduced from 3
		Timeout:    10 * time.Second, // Reduced from 20s
		RateLimit:  1,                // Reduced from 3 - 1 request per second MAX
		MaxRetries: 1,                // Reduced from 2
		RetryDelay: 3 * time.Second,  // Increased delay
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &InjectionTester{
		config:        injConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		testEndpoints: getDefaultInjectionEndpoints(),
		sqlPayloads:   getLimitedSQLPayloads(),   // Use limited set
		nosqlPayloads: getLimitedNoSQLPayloads(), // Use limited set
		jsonPayloads:  getLimitedJSONPayloads(),  // Use limited set
		pathPayloads:  getLimitedPathPayloads(),  // Use limited set
	}, nil
}

// Execute performs comprehensive injection testing - WITH TIMEOUT
func (it *InjectionTester) Execute(ctx context.Context) (*InjectionTestResult, error) {
	startTime := time.Now()

	// CRITICAL: Add global timeout to prevent infinite loops
	timeoutDuration := 5 * time.Minute // Maximum 5 minutes for all injection tests
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	result := &InjectionTestResult{
		StartTime: startTime,
		TestType:  "Injection Security Assessment (Limited)",
		BaseURL:   it.target.BaseURL,
	}

	// Execute different injection tests based on configuration
	if it.config.TestSQL {
		if err := it.testSQLInjection(timeoutCtx); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("SQL injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("SQL injection testing failed: %w", err)
		}
	}

	if it.config.TestNoSQL {
		if err := it.testNoSQLInjection(timeoutCtx); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("NoSQL injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("NoSQL injection testing failed: %w", err)
		}
	}

	if it.config.TestJSON {
		if err := it.testJSONInjection(timeoutCtx); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("JSON injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("JSON injection testing failed: %w", err)
		}
	}

	if it.config.TestPath {
		if err := it.testPathTraversal(timeoutCtx); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("path traversal testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("path traversal testing failed: %w", err)
		}
	}

	// Finalize results
	it.mu.RLock()
	result.TestsExecuted = it.testsExecuted
	result.VulnerabilitiesFound = make([]InjectionVulnerability, len(it.vulnerabilities))
	copy(result.VulnerabilitiesFound, it.vulnerabilities)
	result.TestedParameters = make([]ParameterTest, len(it.testedParameters))
	copy(result.TestedParameters, it.testedParameters)
	result.SuccessfulTests = it.successfulTests
	result.FailedTests = it.failedTests
	it.mu.RUnlock()

	// Calculate metrics
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Get HTTP client statistics
	_, _, requestsPerSecond := it.httpClient.GetStats()
	result.RequestsPerSecond = requestsPerSecond

	return result, nil
}

// testSQLInjection performs SQL injection testing - MUCH more limited
func (it *InjectionTester) testSQLInjection(ctx context.Context) error {
	payloads := it.config.SQLPayloads
	if len(payloads) == 0 {
		payloads = it.sqlPayloads
	}

	// CRITICAL: Limit to max 3 endpoints and 3 parameters to prevent DoS
	maxEndpoints := 3
	maxParameters := 3
	maxPayloads := 5

	endpoints := it.testEndpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		for _, method := range []string{"GET"} { // Only test GET to reduce load
			// Test only limited SQL injection parameters
			parameters := []string{"id", "search", "q"} // Reduced from 8 to 3

			for j, param := range parameters {
				if j >= maxParameters {
					break
				}

				for k, payload := range payloads {
					if k >= maxPayloads {
						break
					}

					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}

					if err := it.testSQLPayload(ctx, endpoint, method, param, payload); err != nil {
						continue // Log error but continue testing
					}

					// Add delay between each test to prevent overwhelming target
					time.Sleep(2 * time.Second)
				}
			}
		}
	}

	return nil
}

// testSQLPayload tests a specific SQL injection payload
func (it *InjectionTester) testSQLPayload(ctx context.Context, endpoint, method, parameter, payload string) error {
	it.incrementTestCount()

	var resp *utils.HTTPResponse
	var err error

	baselineResp, err := it.sendBaselineRequest(ctx, endpoint, method, parameter)
	if err != nil {
		it.recordFailedTest()
		return err
	}

	// Send malicious payload
	startTime := time.Now()
	if method == "GET" {
		// URL parameter injection
		fullURL := fmt.Sprintf("%s%s?%s=%s", it.target.BaseURL, endpoint, parameter, url.QueryEscape(payload))
		resp, err = it.httpClient.Get(ctx, fullURL)
	} else {
		// POST body injection
		body := fmt.Sprintf("%s=%s", parameter, url.QueryEscape(payload))
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		resp, err = it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(body), headers)
	}
	responseTime := time.Since(startTime)

	if err != nil {
		it.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	it.recordSuccessfulTest()

	// Record parameter test
	paramTest := ParameterTest{
		Endpoint:     endpoint,
		Method:       method,
		Parameter:    parameter,
		PayloadType:  "sql",
		Vulnerable:   false,
		ResponseTime: responseTime,
	}

	// Analyze response for SQL injection indicators
	if it.detectSQLInjection(baselineResp, resp, payload) {
		paramTest.Vulnerable = true

		// Create vulnerability record
		vuln := InjectionVulnerability{
			Type:            "sql",
			Severity:        it.calculateSQLSeverity(resp, payload),
			Endpoint:        endpoint,
			Method:          method,
			Parameter:       parameter,
			Description:     fmt.Sprintf("SQL injection vulnerability in parameter '%s'", parameter),
			Evidence:        it.extractSQLEvidence(resp, payload),
			Remediation:     "Use parameterized queries and input validation",
			RiskScore:       it.calculateSQLRiskScore(resp, payload),
			PayloadUsed:     payload,
			ResponseSnippet: it.getResponseSnippet(resp.BodyPreview),
			AttackVector:    fmt.Sprintf("%s parameter injection", method),
			DatabaseType:    it.detectDatabaseType(resp.BodyPreview),
		}

		it.recordVulnerability(vuln)
	}

	it.recordParameterTest(paramTest)
	return nil
}

// detectSQLInjection analyzes responses to detect SQL injection vulnerabilities
func (it *InjectionTester) detectSQLInjection(baseline, response *utils.HTTPResponse, payload string) bool {
	// Check for SQL error messages
	errorPatterns := []string{
		"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
		"syntax error", "unclosed quotation", "quoted string not properly terminated",
		"microsoft ole db", "microsoft jet database", "odbc drivers error",
		"invalid column name", "table doesn't exist", "unknown column",
		"you have an error in your sql syntax", "warning: mysql_",
		"function.mysql", "mysql result", "mysqlclient version",
		"postgresql query failed", "supplied argument is not a valid postgresql",
		"ora-00933", "ora-00921", "ora-00936", "ora-01756",
		"microsoft access driver", "jdb-odbc",
	}

	responseBody := strings.ToLower(response.BodyPreview)

	for _, pattern := range errorPatterns {
		if strings.Contains(responseBody, pattern) {
			return true
		}
	}

	// Check for significant response time differences (blind SQL injection)
	if response.Duration > baseline.Duration*3 && response.Duration > 5*time.Second {
		// Potential time-based blind SQL injection
		if strings.Contains(strings.ToLower(payload), "sleep") ||
			strings.Contains(strings.ToLower(payload), "waitfor") ||
			strings.Contains(strings.ToLower(payload), "benchmark") {
			return true
		}
	}

	// Check for different response lengths (boolean-based blind SQL injection)
	if len(response.BodyPreview) != len(baseline.BodyPreview) {
		sizeDiff := abs(len(response.BodyPreview) - len(baseline.BodyPreview))
		if sizeDiff > 100 { // Significant difference
			return true
		}
	}

	// Check for different status codes
	if response.StatusCode != baseline.StatusCode {
		// 500 errors often indicate injection success
		if response.StatusCode == 500 {
			return true
		}
	}

	return false
}

// testNoSQLInjection performs NoSQL injection testing - LIMITED
func (it *InjectionTester) testNoSQLInjection(ctx context.Context) error {
	payloads := it.config.NoSQLPayloads
	if len(payloads) == 0 {
		payloads = it.nosqlPayloads
	}

	// Limit to 2 endpoints and 3 payloads max
	maxEndpoints := 2
	maxPayloads := 3

	endpoints := it.testEndpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		for j, payload := range payloads {
			if j >= maxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err := it.testNoSQLPayload(ctx, endpoint, payload); err != nil {
				continue
			}

			// Add delay between tests
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

// testNoSQLPayload tests NoSQL injection payloads
func (it *InjectionTester) testNoSQLPayload(ctx context.Context, endpoint, payload string) error {
	it.incrementTestCount()

	// Test JSON-based NoSQL injection
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	resp, err := it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(payload), headers)
	if err != nil {
		it.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	it.recordSuccessfulTest()

	// Check for NoSQL injection indicators
	if it.detectNoSQLInjection(resp, payload) {
		vuln := InjectionVulnerability{
			Type:            "nosql",
			Severity:        "high",
			Endpoint:        endpoint,
			Method:          "POST",
			Parameter:       "request_body",
			Description:     "NoSQL injection vulnerability detected",
			Evidence:        it.extractNoSQLEvidence(resp, payload),
			Remediation:     "Validate and sanitize NoSQL queries, use proper schema validation",
			RiskScore:       80,
			PayloadUsed:     payload,
			ResponseSnippet: it.getResponseSnippet(resp.BodyPreview),
			AttackVector:    "JSON NoSQL injection",
		}

		it.recordVulnerability(vuln)
	}

	return nil
}

// testJSONInjection performs JSON injection testing - LIMITED
func (it *InjectionTester) testJSONInjection(ctx context.Context) error {
	payloads := it.config.JSONPayloads
	if len(payloads) == 0 {
		payloads = it.jsonPayloads
	}

	// Limit to 2 endpoints and 2 payloads max
	maxEndpoints := 2
	maxPayloads := 2

	endpoints := it.testEndpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		for j, payload := range payloads {
			if j >= maxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err := it.testJSONPayload(ctx, endpoint, payload); err != nil {
				continue
			}

			// Add delay between tests
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

// testJSONPayload tests JSON injection payloads
func (it *InjectionTester) testJSONPayload(ctx context.Context, endpoint, payload string) error {
	it.incrementTestCount()

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	resp, err := it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(payload), headers)
	if err != nil {
		it.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	it.recordSuccessfulTest()

	// Check for JSON injection indicators
	if it.detectJSONInjection(resp, payload) {
		vuln := InjectionVulnerability{
			Type:            "json",
			Severity:        "medium",
			Endpoint:        endpoint,
			Method:          "POST",
			Parameter:       "json_body",
			Description:     "JSON injection vulnerability detected",
			Evidence:        it.extractJSONEvidence(resp, payload),
			Remediation:     "Implement proper JSON schema validation and input sanitization",
			RiskScore:       60,
			PayloadUsed:     payload,
			ResponseSnippet: it.getResponseSnippet(resp.BodyPreview),
			AttackVector:    "JSON structure injection",
		}

		it.recordVulnerability(vuln)
	}

	return nil
}

// testPathTraversal performs path traversal testing - LIMITED
func (it *InjectionTester) testPathTraversal(ctx context.Context) error {
	payloads := it.config.PathPayloads
	if len(payloads) == 0 {
		payloads = it.pathPayloads
	}

	// Limit to 2 endpoints and 3 payloads max
	maxEndpoints := 2
	maxPayloads := 3

	endpoints := it.testEndpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		for j, payload := range payloads {
			if j >= maxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err := it.testPathPayload(ctx, endpoint, payload); err != nil {
				continue
			}

			// Add delay between tests
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

// testPathPayload tests path traversal payloads
func (it *InjectionTester) testPathPayload(ctx context.Context, endpoint, payload string) error {
	it.incrementTestCount()

	// Test path parameter injection
	testURL := fmt.Sprintf("%s%s?file=%s", it.target.BaseURL, endpoint, url.QueryEscape(payload))

	resp, err := it.httpClient.Get(ctx, testURL)
	if err != nil {
		it.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	it.recordSuccessfulTest()

	// Check for path traversal indicators
	if it.detectPathTraversal(resp, payload) {
		vuln := InjectionVulnerability{
			Type:            "path",
			Severity:        it.calculatePathSeverity(resp, payload),
			Endpoint:        endpoint,
			Method:          "GET",
			Parameter:       "file",
			Description:     "Path traversal vulnerability detected",
			Evidence:        it.extractPathEvidence(resp, payload),
			Remediation:     "Implement proper input validation and use whitelist for allowed files",
			RiskScore:       it.calculatePathRiskScore(resp, payload),
			PayloadUsed:     payload,
			ResponseSnippet: it.getResponseSnippet(resp.BodyPreview),
			AttackVector:    "File path traversal",
		}

		it.recordVulnerability(vuln)
	}

	return nil
}

// Helper methods for detection and analysis

func (it *InjectionTester) sendBaselineRequest(ctx context.Context, endpoint, method, parameter string) (*utils.HTTPResponse, error) {
	if method == "GET" {
		fullURL := fmt.Sprintf("%s%s?%s=test", it.target.BaseURL, endpoint, parameter)
		return it.httpClient.Get(ctx, fullURL)
	} else {
		body := fmt.Sprintf("%s=test", parameter)
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		return it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(body), headers)
	}
}

func (it *InjectionTester) detectNoSQLInjection(resp *utils.HTTPResponse, payload string) bool {
	responseBody := strings.ToLower(resp.BodyPreview)

	// NoSQL error patterns
	patterns := []string{
		"mongodb", "mongoose", "couchdb", "redis",
		"$where", "$regex", "$ne", "$gt", "$lt",
		"bson", "objectid", "aggregation",
	}

	for _, pattern := range patterns {
		if strings.Contains(responseBody, pattern) {
			return true
		}
	}

	return resp.StatusCode == 500 && strings.Contains(responseBody, "error")
}

func (it *InjectionTester) detectJSONInjection(resp *utils.HTTPResponse, payload string) bool {
	// Check for JSON parsing errors or structure modification
	responseBody := strings.ToLower(resp.BodyPreview)

	patterns := []string{
		"json parse error", "invalid json", "syntax error",
		"unexpected token", "malformed json",
	}

	for _, pattern := range patterns {
		if strings.Contains(responseBody, pattern) {
			return true
		}
	}

	return false
}

func (it *InjectionTester) detectPathTraversal(resp *utils.HTTPResponse, payload string) bool {
	responseBody := strings.ToLower(resp.BodyPreview)

	// Look for system file contents
	patterns := []string{
		"root:x:", "[boot loader]", "windows registry",
		"etc/passwd", "windows\\system32", "/etc/",
		"program files", "documents and settings",
	}

	for _, pattern := range patterns {
		if strings.Contains(responseBody, pattern) {
			return true
		}
	}

	return false
}

// Default payloads and endpoints

func getDefaultInjectionEndpoints() []string {
	return []string{
		"/login", "/search", "/user", // Reduced from 8 to 3 endpoints
	}
}

// LIMITED payload functions to prevent DoS

func getLimitedSQLPayloads() []string {
	return []string{
		"'",
		"' OR '1'='1",
		"' OR 1=1--",
		"admin'--",
		"1'; waitfor delay '0:0:1'--", // Reduced delay for testing
	}
}

func getLimitedNoSQLPayloads() []string {
	return []string{
		`{"$where": "1==1"}`,
		`{"$ne": null}`,
		`{"$regex": ".*"}`,
	}
}

func getLimitedJSONPayloads() []string {
	return []string{
		`{"test": "value", "injected": true}`,
		`{test: "no_quotes"}`,
	}
}

func getLimitedPathPayloads() []string {
	return []string{
		"../",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	}
}

// Note: The original getDefault*Payloads() functions contained too many payloads
// and caused DoS-like behavior. They have been replaced with limited versions.

// Utility methods

func (it *InjectionTester) calculateSQLSeverity(resp *utils.HTTPResponse, payload string) string {
	if strings.Contains(strings.ToLower(resp.BodyPreview), "root:x:") {
		return "critical"
	}
	if resp.StatusCode == 500 {
		return "high"
	}
	return "medium"
}

func (it *InjectionTester) calculateSQLRiskScore(resp *utils.HTTPResponse, payload string) int {
	score := 50
	if strings.Contains(strings.ToLower(resp.BodyPreview), "root:x:") {
		score = 95
	} else if resp.StatusCode == 500 {
		score = 80
	}
	return score
}

func (it *InjectionTester) calculatePathSeverity(resp *utils.HTTPResponse, payload string) string {
	if strings.Contains(strings.ToLower(resp.BodyPreview), "root:x:") ||
		strings.Contains(strings.ToLower(resp.BodyPreview), "windows registry") {
		return "critical"
	}
	return "high"
}

func (it *InjectionTester) calculatePathRiskScore(resp *utils.HTTPResponse, payload string) int {
	if strings.Contains(strings.ToLower(resp.BodyPreview), "root:x:") {
		return 95
	}
	return 75
}

func (it *InjectionTester) extractSQLEvidence(resp *utils.HTTPResponse, payload string) string {
	if strings.Contains(strings.ToLower(resp.BodyPreview), "sql syntax") {
		return "SQL syntax error detected in response"
	}
	if resp.StatusCode == 500 {
		return "Internal server error triggered by SQL payload"
	}
	return "SQL injection indicators detected"
}

func (it *InjectionTester) extractNoSQLEvidence(resp *utils.HTTPResponse, payload string) string {
	return "NoSQL database response pattern detected"
}

func (it *InjectionTester) extractJSONEvidence(resp *utils.HTTPResponse, payload string) string {
	return "JSON structure injection successful"
}

func (it *InjectionTester) extractPathEvidence(resp *utils.HTTPResponse, payload string) string {
	if strings.Contains(strings.ToLower(resp.BodyPreview), "root:x:") {
		return "System file /etc/passwd exposed"
	}
	return "Path traversal successful"
}

func (it *InjectionTester) detectDatabaseType(responseBody string) string {
	responseBody = strings.ToLower(responseBody)
	if strings.Contains(responseBody, "mysql") {
		return "MySQL"
	}
	if strings.Contains(responseBody, "postgresql") {
		return "PostgreSQL"
	}
	if strings.Contains(responseBody, "oracle") {
		return "Oracle"
	}
	if strings.Contains(responseBody, "sqlite") {
		return "SQLite"
	}
	return "Unknown"
}

func (it *InjectionTester) getResponseSnippet(body string) string {
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Thread-safe methods

func (it *InjectionTester) incrementTestCount() {
	it.mu.Lock()
	it.testsExecuted++
	it.mu.Unlock()
}

func (it *InjectionTester) recordSuccessfulTest() {
	it.mu.Lock()
	it.successfulTests++
	it.mu.Unlock()
}

func (it *InjectionTester) recordFailedTest() {
	it.mu.Lock()
	it.failedTests++
	it.mu.Unlock()
}

func (it *InjectionTester) recordVulnerability(vuln InjectionVulnerability) {
	it.mu.Lock()
	it.vulnerabilities = append(it.vulnerabilities, vuln)
	it.mu.Unlock()
}

func (it *InjectionTester) recordParameterTest(test ParameterTest) {
	it.mu.Lock()
	it.testedParameters = append(it.testedParameters, test)
	it.mu.Unlock()
}

// Close cleans up resources used by the tester
func (it *InjectionTester) Close() {
	if it.httpClient != nil {
		it.httpClient.Close()
	}
}
