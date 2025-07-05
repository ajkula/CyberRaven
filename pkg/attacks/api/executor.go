package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// TestExecutor handles the execution of endpoint tests
type TestExecutor struct {
	httpClient *utils.HTTPClient
	analyzer   *ResponseAnalyzer
}

// NewTestExecutor creates a new test executor
func NewTestExecutor(httpClient *utils.HTTPClient) *TestExecutor {
	return &TestExecutor{
		httpClient: httpClient,
		analyzer:   NewResponseAnalyzer(),
	}
}

// ExecuteTests performs endpoint enumeration tests with smart method selection
func (te *TestExecutor) ExecuteTests(ctx context.Context, baseURL *url.URL, endpoints []string, resultCollector *ResultCollector, config *config.APIAttackConfig) error {
	var wg sync.WaitGroup

	for _, endpoint := range endpoints {
		// Get relevant methods for this endpoint
		methods := te.getMethodsForEndpoint(endpoint, config)

		for _, method := range methods {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			wg.Add(1)
			go func(path, httpMethod string) {
				defer wg.Done()
				te.testEndpoint(ctx, baseURL, path, httpMethod, resultCollector, config)
			}(endpoint, method)
		}
	}

	wg.Wait()
	return nil
}

// getMethodsForEndpoint returns appropriate HTTP methods for a given endpoint
func (te *TestExecutor) getMethodsForEndpoint(endpoint string, config *config.APIAttackConfig) []string {
	methods := []string{"GET"} // Always test GET first

	// Smart method selection based on endpoint type
	switch {
	case te.isAuthEndpoint(endpoint):
		methods = append(methods, "POST")
		if config.TestMethodTampering {
			methods = append(methods, "PUT", "PATCH") // Test unusual auth methods
		}

	case te.isResourceEndpoint(endpoint):
		methods = append(methods, "POST", "PUT", "DELETE")
		if config.TestMethodTampering {
			methods = append(methods, "PATCH", "HEAD", "OPTIONS")
		}

	case te.isConfigEndpoint(endpoint):
		methods = append(methods, "POST", "PUT")
		if config.TestMethodTampering {
			methods = append(methods, "DELETE") // Dangerous on config endpoints
		}

	case te.isFileEndpoint(endpoint):
		methods = append(methods, "POST", "PUT")
		if config.TestMethodTampering {
			methods = append(methods, "DELETE", "PATCH")
		}

	case te.isStatusEndpoint(endpoint):
		// Status endpoints typically only support GET
		if config.TestMethodTampering {
			methods = append(methods, "POST", "PUT", "DELETE") // Test for vulnerabilities
		}

	default:
		// Generic endpoints
		if config.TestMethodTampering {
			methods = append(methods, "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
		} else {
			methods = append(methods, "POST") // Conservative approach
		}
	}

	return methods
}

// isAuthEndpoint checks if endpoint is authentication-related
func (te *TestExecutor) isAuthEndpoint(endpoint string) bool {
	authPatterns := []string{"auth", "login", "logout", "signin", "signup", "register", "token", "session"}
	return te.containsAnyPattern(endpoint, authPatterns)
}

// isResourceEndpoint checks if endpoint represents a REST resource
func (te *TestExecutor) isResourceEndpoint(endpoint string) bool {
	resourcePatterns := []string{"users", "accounts", "messages", "files", "reports", "events"}
	return te.containsAnyPattern(endpoint, resourcePatterns)
}

// isConfigEndpoint checks if endpoint is configuration-related
func (te *TestExecutor) isConfigEndpoint(endpoint string) bool {
	configPatterns := []string{"config", "settings", "admin", "management", "control"}
	return te.containsAnyPattern(endpoint, configPatterns)
}

// isFileEndpoint checks if endpoint is file-related
func (te *TestExecutor) isFileEndpoint(endpoint string) bool {
	filePatterns := []string{"files", "upload", "download", "media", "attachments"}
	return te.containsAnyPattern(endpoint, filePatterns)
}

// isStatusEndpoint checks if endpoint is status/health-related
func (te *TestExecutor) isStatusEndpoint(endpoint string) bool {
	statusPatterns := []string{"status", "health", "info", "version", "metrics", "stats"}
	return te.containsAnyPattern(endpoint, statusPatterns)
}

// containsAnyPattern checks if endpoint contains any of the given patterns
func (te *TestExecutor) containsAnyPattern(endpoint string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(endpoint), pattern) {
			return true
		}
	}
	return false
}

// testEndpoint tests a specific endpoint with a specific HTTP method
func (te *TestExecutor) testEndpoint(ctx context.Context, baseURL *url.URL, path, method string, resultCollector *ResultCollector, config *config.APIAttackConfig) {
	// Test base endpoint
	te.executeEndpointTest(ctx, baseURL, path, method, "", resultCollector)

	// Test with parameter pollution if enabled
	if config.TestParameterPollution && te.shouldTestParameterPollution(path, method) {
		pollutionTests := te.generateParameterPollutionTests(path)
		for _, queryParams := range pollutionTests {
			te.executeEndpointTest(ctx, baseURL, path, method, queryParams, resultCollector)
		}
	}
}

// executeEndpointTest executes a single endpoint test with optional query parameters
func (te *TestExecutor) executeEndpointTest(ctx context.Context, baseURL *url.URL, path, method, queryParams string, resultCollector *ResultCollector) {
	// Build full URL
	fullURL := baseURL.ResolveReference(&url.URL{Path: path})
	if queryParams != "" {
		fullURL.RawQuery = queryParams
	}

	// DEBUG
	fmt.Printf("[DEBUG] Testing URL: %s\n", fullURL.String())

	// Record that we tested this endpoint
	resultCollector.IncrementTestedCount()

	// Execute request
	resp, err := te.executeHTTPRequest(ctx, fullURL.String(), method)
	if err != nil {
		if httpErr, ok := err.(*utils.HTTPError); ok {
			resultCollector.RecordError(path, method, httpErr.ErrorType, httpErr.Message)
		} else {
			resultCollector.RecordError(path, method, "unknown", err.Error())
		}
		return
	}
	defer resp.Body.Close()

	// Analyze response
	endpointResult, vulnerabilities := te.analyzer.AnalyzeResponse(path, method, resp)

	// Record results
	if endpointResult != nil {
		resultCollector.RecordEndpoint(*endpointResult)
	}

	for _, vuln := range vulnerabilities {
		resultCollector.RecordVulnerability(vuln)
	}
}

// shouldTestParameterPollution determines if an endpoint should be tested for parameter pollution
func (te *TestExecutor) shouldTestParameterPollution(path, method string) bool {
	// Only test GET/POST methods for parameter pollution
	if method != "GET" && method != "POST" {
		return false
	}

	// Test endpoints likely to accept parameters
	return te.isResourceEndpoint(path) || te.isAuthEndpoint(path) || te.isConfigEndpoint(path)
}

// generateParameterPollutionTests generates parameter pollution test cases based on endpoint type
func (te *TestExecutor) generateParameterPollutionTests(path string) []string {
	var tests []string

	// Base tests for all endpoints
	tests = append(tests, "id=1&id=2")

	// Endpoint-specific tests
	switch {
	case te.isAuthEndpoint(path):
		// Authentication endpoints
		tests = append(tests,
			"admin=false&admin=true",
			"role=user&role=admin",
			"access=false&access=true")

	case te.isResourceEndpoint(path):
		// Resource endpoints (users, accounts, etc.)
		tests = append(tests,
			"user=1&user=2",
			"account=1&account=2",
			"page=1&page=999",
			"limit=10&limit=999999")

	case te.isFileEndpoint(path):
		// File endpoints
		tests = append(tests,
			"file=safe.txt&file=../../../etc/passwd",
			"path=public&path=../admin")

	case te.isConfigEndpoint(path):
		// Configuration endpoints
		tests = append(tests,
			"admin=false&admin=true",
			"debug=false&debug=true")

	default:
		// Generic endpoints - basic tests
		tests = append(tests,
			"search=safe&search=<script>",
			"filter=normal&filter=*",
			"query=test&query=1'or'1'='1")
	}

	return tests
}

// executeHTTPRequest executes an HTTP request with the specified method
func (te *TestExecutor) executeHTTPRequest(ctx context.Context, url, method string) (*utils.HTTPResponse, error) {
	switch method {
	case "GET":
		return te.httpClient.Get(ctx, url)
	case "POST":
		return te.httpClient.Post(ctx, url, nil, nil)
	case "PUT":
		return te.httpClient.Put(ctx, url, nil, nil)
	case "DELETE":
		return te.httpClient.Delete(ctx, url)
	case "HEAD":
		return te.httpClient.Head(ctx, url)
	case "OPTIONS":
		return te.httpClient.Options(ctx, url)
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", method)
	}
}
