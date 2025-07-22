package injection

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// InjectionTester handles injection attack testing
type InjectionTester struct {
	config       *config.InjectionAttackConfig
	target       *config.TargetConfig
	httpClient   *utils.HTTPClient
	discoveryCtx *discovery.AttackContext // Intelligence discovery

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
func NewInjectionTester(injConfig *config.InjectionAttackConfig, targetConfig *config.TargetConfig, attackContext *discovery.AttackContext) (*InjectionTester, error) {
	// Create default engine config for HTTP client - MUCH more conservative
	engineConfig := &config.EngineConfig{
		MaxWorkers: 2,               // Reduced from 3
		Timeout:    2 * time.Second, // Reduced from 20s
		RateLimit:  1,               // Reduced from 3 - 1 request per second MAX
		MaxRetries: 1,               // Reduced from 2
		RetryDelay: 1 * time.Second, // Increased delay
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	if attackContext != nil && attackContext.IsIntelligenceAvailable() {
		// Count relevant discoveries for injection
		paramEndpoints := 0
		totalParams := 0
		for _, endpoint := range attackContext.Endpoints {
			if len(endpoint.Parameters) > 0 {
				paramEndpoints++
				totalParams += len(endpoint.Parameters)
			}
		}
		fmt.Printf("[SUCCESS] Loaded discovery intelligence - found %d parameterized endpoints with %d parameters\n",
			paramEndpoints, totalParams)

		discoveryLoader := discovery.NewDiscoveryLoader()
		age, _ := discoveryLoader.GetDiscoveryAge()
		fmt.Printf("[INFO] Discovery age: %v\n", age.Round(time.Second))
	} else {
		fmt.Printf("[INFO] No discovery file found - using standard testing\n")
		fmt.Printf("[INFO] Run 'cyberraven sniff' first for intelligent targeting\n")
	}

	return &InjectionTester{
		config:        injConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		discoveryCtx:  attackContext,
		testEndpoints: getDefaultInjectionEndpoints(),
		sqlPayloads:   getLimitedSQLPayloads(),   // Use limited set
		nosqlPayloads: getLimitedNoSQLPayloads(), // Use limited set
		jsonPayloads:  getLimitedJSONPayloads(),  // Use limited set
		pathPayloads:  getLimitedPathPayloads(),  // Use limited set
	}, nil
}

// Execute performs comprehensive injection testing WITH TIMEOUT
func (it *InjectionTester) Execute(ctx context.Context) (*InjectionTestResult, error) {
	startTime := time.Now()

	// CRITICAL: Add global timeout to prevent infinite loops
	timeoutDuration := 1 * time.Minute // Maximum 1 min for all injection tests
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	result := &InjectionTestResult{
		StartTime: startTime,
		TestType:  "Injection Security Assessment (Intelligent)",
		BaseURL:   it.target.BaseURL,
	}

	if it.config.TestSQL {
		fallbackPayloads := it.sqlPayloads
		if len(it.config.SQLPayloads) > 0 {
			fallbackPayloads = it.config.SQLPayloads
		}

		if err := it.executeTestByType(timeoutCtx, "sql", fallbackPayloads); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("SQL injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("SQL injection testing failed: %w", err)
		}
	}

	if it.config.TestNoSQL {
		fallbackPayloads := it.nosqlPayloads
		if len(it.config.NoSQLPayloads) > 0 {
			fallbackPayloads = it.config.NoSQLPayloads
		}

		if err := it.executeTestByType(timeoutCtx, "nosql", fallbackPayloads); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("NoSQL injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("NoSQL injection testing failed: %w", err)
		}
	}

	if it.config.TestJSON {
		fallbackPayloads := it.jsonPayloads
		if len(it.config.JSONPayloads) > 0 {
			fallbackPayloads = it.config.JSONPayloads
		}

		if err := it.executeTestByType(timeoutCtx, "json", fallbackPayloads); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("JSON injection testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("JSON injection testing failed: %w", err)
		}
	}

	if it.config.TestPath {
		fallbackPayloads := it.pathPayloads
		if len(it.config.PathPayloads) > 0 {
			fallbackPayloads = it.config.PathPayloads
		}

		if err := it.executeTestByType(timeoutCtx, "path", fallbackPayloads); err != nil {
			if err == context.DeadlineExceeded {
				return nil, fmt.Errorf("path traversal testing timed out after %v", timeoutDuration)
			}
			return nil, fmt.Errorf("path traversal testing failed: %w", err)
		}
	}

	it.ExploitTLSIntelligence()

	// Finalize results (unchanged)
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

	// Log intelligence usage for reporting
	if it.discoveryCtx != nil && it.discoveryCtx.IsIntelligenceAvailable() {
		fmt.Printf("[SUCCESS] Injection testing completed using discovery intelligence\n")
		fmt.Printf("[INFO] Targeted %d parameterized endpoints with contextual payloads\n",
			len(it.discoveryCtx.GetParameterizedEndpoints()))
	} else {
		fmt.Printf("[INFO] Injection testing completed in standard mode\n")
	}

	return result, nil
}

// getIntelligentParameters returns unique parameters discovered across all endpoints
func (it *InjectionTester) getIntelligentParameters() []string {
	if it.discoveryCtx == nil {
		return []string{}
	}

	// Collect unique parameters from all endpoints
	paramMap := make(map[string]bool)
	for _, endpoint := range it.discoveryCtx.Endpoints {
		for _, param := range endpoint.Parameters {
			paramMap[param] = true
		}
	}

	// Convert to slice
	var params []string
	for param := range paramMap {
		params = append(params, param)
	}

	return params
}

// Close cleans up resources used by the tester
func (it *InjectionTester) Close() {
	if it.httpClient != nil {
		it.httpClient.Close()
	}
}
