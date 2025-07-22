package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// Enumerator handles API endpoint enumeration attacks
type Enumerator struct {
	config       *config.APIAttackConfig
	target       *config.TargetConfig
	httpClient   *utils.HTTPClient
	strategy     *EndpointStrategy
	executor     *TestExecutor
	discoveryCtx *discovery.AttackContext
}

// NewEnumerator creates a new API enumerator instance
func NewEnumerator(apiConfig *config.APIAttackConfig, targetConfig *config.TargetConfig) (*Enumerator, error) {
	return NewEnumeratorWithDiscovery(apiConfig, targetConfig)
}

// API enumerator with auto-discovery
func NewEnumeratorWithDiscovery(apiConfig *config.APIAttackConfig, targetConfig *config.TargetConfig) (*Enumerator, error) {
	engineConfig := &config.EngineConfig{
		MaxWorkers: 10,
		Timeout:    10 * time.Second,
		RateLimit:  10,
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
	}

	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Load discovery intelligence
	discoveryLoader := discovery.NewDiscoveryLoader()
	var attackContext *discovery.AttackContext

	if discoveryLoader.HasDiscoveries() {
		attackContext, err = discoveryLoader.LoadAttackContext()
		if err != nil {
			printWarning(fmt.Sprintf("Failed to load discovery intelligence: %v", err), false)
			printInfo("Falling back to standard enumeration mode", false)
		} else {
			printSuccess("Loaded discovery intelligence - targeting discovered endpoints", false)
			age, _ := discoveryLoader.GetDiscoveryAge()
			printInfo(fmt.Sprintf("Discovery age: %v", age.Round(time.Second)), false)
		}
	} else {
		printInfo("No discovery file found - using standard enumeration", false)
		printInfo("Run 'cyberraven sniff' first for intelligent targeting", false)
	}

	// Create components with discovery context
	strategy := NewEndpointStrategyWithDiscovery(apiConfig, targetConfig, attackContext)
	executor := NewTestExecutor(httpClient, strategy.discoveryCtx)

	enumerator := &Enumerator{
		config:       apiConfig,
		target:       targetConfig,
		httpClient:   httpClient,
		strategy:     strategy,
		executor:     executor,
		discoveryCtx: attackContext,
	}

	if apiConfig.EnableAutoDiscovery {
		ctx := context.Background()
		discoveredURL, err := enumerator.AutoDiscoverTarget(ctx, targetConfig.BaseURL)
		if err != nil {
			printWarning(fmt.Sprintf("Auto-discovery failed: %v", err), false)
		} else if discoveredURL != targetConfig.BaseURL {
			printInfo(fmt.Sprintf("Target updated: %s → %s", targetConfig.BaseURL, discoveredURL), false)
			targetConfig.BaseURL = discoveredURL
		}
	}

	return enumerator, nil
}

// Execute performs API endpoint enumeration attack
func (e *Enumerator) Execute(ctx context.Context) (*EnumerationResult, error) {
	startTime := time.Now()

	baseURL, err := url.Parse(e.target.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Initialize result with intelligence info
	result := &EnumerationResult{
		StartTime:          startTime,
		TestType:           "API Endpoint Enumeration",
		BaseURL:            e.target.BaseURL,
		UserAgent:          "CyberRaven/1.0 Security Scanner",
		IntelligenceUsed:   e.discoveryCtx != nil,
		DiscoveredTargets:  e.getTargetedEndpointsCount(),
		RecommendedModules: e.getRecommendedModules(),
	}

	endpoints := e.strategy.GetEndpointsToTest()

	// Intelligence-aware logging
	if e.discoveryCtx != nil {
		printInfo(fmt.Sprintf("Using discovery intelligence: %d targeted endpoints", len(endpoints)), false)
	} else {
		printInfo(fmt.Sprintf("Standard enumeration mode: %d common endpoints", len(endpoints)), false)
	}

	resultCollector := NewResultCollector()

	err = e.executor.ExecuteTests(ctx, baseURL, endpoints, resultCollector, e.config)
	if err != nil {
		return nil, fmt.Errorf("enumeration failed: %w", err)
	}

	e.ExploitTLSIntelligence(resultCollector)

	testedCount, foundEndpoints, erroredEndpoints, vulnerabilities := resultCollector.GetResults()
	result.TestedEndpoints = testedCount
	result.FoundEndpoints = foundEndpoints
	result.ErroredEndpoints = erroredEndpoints
	result.Vulnerabilities = vulnerabilities

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	_, _, requestsPerSecond := e.httpClient.GetStats()
	result.RequestsPerSecond = requestsPerSecond
	if result.TestedEndpoints > 0 {
		result.SuccessRate = float64(len(result.FoundEndpoints)) / float64(result.TestedEndpoints) * 100
	}

	return result, nil
}

// unused yet
func (e *Enumerator) getTargetedEndpoints() []string {
	if e.discoveryCtx == nil {
		return []string{} // No discovery context
	}

	// Get endpoints targeted for API module
	targetEndpoints := e.discoveryCtx.GetTargetedEndpoints("api")

	endpoints := make([]string, 0, len(targetEndpoints))
	for _, endpoint := range targetEndpoints {
		endpoints = append(endpoints, endpoint.Path)
	}

	return endpoints
}

// Close cleans up resources used by the enumerator
func (e *Enumerator) Close() {
	if e.httpClient != nil {
		e.httpClient.Close()
	}
}

// AutoDiscoverTarget performs intelligent protocol discovery
func (e *Enumerator) AutoDiscoverTarget(ctx context.Context, targetURL string) (string, error) {
	// Parse the URL to check if protocol is specified
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		// No protocol specified - try auto-discovery
		return e.discoverProtocol(ctx, targetURL)
	}

	// Protocol specified - test connectivity and suggest fallback if needed
	if strings.HasPrefix(targetURL, "https://") {
		if err := e.testConnectivity(ctx, targetURL); err != nil {
			// HTTPS failed - suggest HTTP fallback
			httpURL := strings.Replace(targetURL, "https://", "http://", 1)
			if e.testConnectivity(ctx, httpURL) == nil {
				printWarning(fmt.Sprintf("HTTPS failed (%v), falling back to HTTP", err), false)
				return httpURL, nil
			}
			return targetURL, fmt.Errorf("both HTTPS and HTTP failed for target")
		}
	}

	return targetURL, nil
}

// discoverProtocol attempts to discover the correct protocol for a target
func (e *Enumerator) discoverProtocol(ctx context.Context, host string) (string, error) {
	// Try HTTPS first (security best practice)
	httpsURL := "https://" + host
	if err := e.testConnectivity(ctx, httpsURL); err == nil {
		printInfo(fmt.Sprintf("Auto-discovered: %s (HTTPS)", httpsURL), false)
		return httpsURL, nil
	}

	// Fallback to HTTP
	httpURL := "http://" + host
	if err := e.testConnectivity(ctx, httpURL); err == nil {
		printWarning(fmt.Sprintf("Auto-discovered: %s (HTTP - unencrypted)", httpURL), false)
		return httpURL, nil
	}

	return "", fmt.Errorf("unable to connect to %s via HTTPS or HTTP", host)
}

// testConnectivity performs a quick connectivity test
func (e *Enumerator) testConnectivity(ctx context.Context, testURL string) error {
	// Create a quick timeout context for connectivity test
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Parse URL for basic validation
	_, err := url.Parse(testURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Try a simple HEAD request to test connectivity
	resp, err := e.httpClient.Head(connectCtx, testURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Any response (even 404) indicates successful connectivity
	return nil
}

func (e *Enumerator) getTargetedEndpointsCount() int {
	if e.discoveryCtx == nil {
		return 0
	}
	return len(e.discoveryCtx.GetTargetedEndpoints("api"))
}

func (e *Enumerator) getRecommendedModules() []string {
	if e.discoveryCtx == nil {
		return []string{}
	}
	return e.discoveryCtx.GetRecommendedModules()
}
