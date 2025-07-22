package jwt

import (
	"context"
	"fmt"
	"time"
)

// Execute performs comprehensive JWT security testing
func (jf *JWTFuzzer) Execute(ctx context.Context) (*JWTTestResult, error) {
	startTime := time.Now()

	result := &JWTTestResult{
		StartTime:          startTime,
		TestType:           "JWT Security Assessment",
		BaseURL:            jf.target.BaseURL,
		IntelligenceUsed:   jf.discoveryCtx != nil && jf.discoveryCtx.IsIntelligenceAvailable(),
		DiscoveredTokens:   jf.getDiscoveredTokensCount(),
		RecommendedModules: jf.getRecommendedModules(),
	}

	if jf.attackContext != nil {
		jf.ExploitTLSIntelligence(jf.attackContext)
	}

	var tokens []string
	var testEndpoints []string

	if jf.discoveryCtx != nil && jf.discoveryCtx.IsIntelligenceAvailable() {
		testEndpoints = jf.getIntelligentEndpoints()
		printInfo(fmt.Sprintf("Using discovery intelligence: %d targeted endpoints, %d discovered tokens",
			len(testEndpoints), len(tokens)), false)
	} else {
		testEndpoints = jf.getStandardEndpoints()
		printInfo(fmt.Sprintf("Standard JWT testing mode: %d common endpoints", len(testEndpoints)), false)
	}

	discoveredTokens, err := jf.discoverJWTTokensFromEndpoints(ctx, testEndpoints)
	if err == nil {
		tokens = append(tokens, discoveredTokens...)
	}

	if len(tokens) == 0 {
		tokens = jf.getStandardTokens()
	}

	// Analyze discovered tokens
	for _, token := range tokens {
		analysis := jf.analyzeToken(token)
		jf.recordTokenAnalysis(analysis)

		// Use first valid token as test token
		if analysis.IsValid && result.TestToken == "" {
			result.TestToken = token
		}
	}

	// Execute JWT-specific attacks
	if err := jf.executeJWTAttacks(ctx, tokens); err != nil {
		return nil, fmt.Errorf("failed to execute JWT attacks: %w", err)
	}

	// Finalize results
	jf.mu.RLock()
	result.TestsExecuted = jf.testsExecuted
	result.VulnerabilitiesFound = make([]JWTVulnerability, len(jf.vulnerabilities))
	copy(result.VulnerabilitiesFound, jf.vulnerabilities)
	result.TokensAnalyzed = make([]TokenAnalysis, len(jf.tokensAnalyzed))
	copy(result.TokensAnalyzed, jf.tokensAnalyzed)
	result.SuccessfulTests = jf.successfulTests
	result.FailedTests = jf.failedTests
	jf.mu.RUnlock()

	// Calculate metrics
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Get HTTP client statistics
	_, _, requestsPerSecond := jf.httpClient.GetStats()
	result.RequestsPerSecond = requestsPerSecond

	return result, nil
}
