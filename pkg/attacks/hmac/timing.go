package hmac

import (
	"context"
	"fmt"
	"time"
)

// TimingTester handles HMAC timing attack testing
type TimingTester struct {
	hmacTester *HMACTester
}

// NewTimingTester creates a new timing attack tester
func NewTimingTester(hmacTester *HMACTester) *TimingTester {
	return &TimingTester{
		hmacTester: hmacTester,
	}
}

// Execute performs comprehensive timing attack testing
func (tt *TimingTester) Execute(ctx context.Context) error {
	config := tt.hmacTester.GetConfig()
	if config.TimingRequests < 10 {
		config.TimingRequests = 50 // Default to 50 requests for statistical significance
	}

	var endpoints []string

	if tt.hmacTester.HasIntelligence() {
		endpoints = tt.hmacTester.GetIntelligentEndpoints()
		printInfo(fmt.Sprintf("Using discovery intelligence: %d targeted endpoints for timing analysis", len(endpoints)), false)

		// Focus on high-priority endpoints for timing attacks
		endpoints = tt.getHighPriorityEndpoints(endpoints)
	} else {
		endpoints = tt.hmacTester.GetTestEndpoints()
		printInfo(fmt.Sprintf("Standard timing testing mode: %d generic endpoints", len(endpoints)), false)
	}

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := tt.performTimingAnalysis(ctx, endpoint); err != nil {
			continue // Continue with other endpoints
		}
	}

	return nil
}

// getHighPriorityEndpoints filters endpoints to focus on high-priority ones for timing attacks
func (tt *TimingTester) getHighPriorityEndpoints(endpoints []string) []string {
	discoveryCtx := tt.hmacTester.GetDiscoveryContext()
	if discoveryCtx == nil {
		return endpoints
	}

	highPriorityEndpoints := discoveryCtx.GetHighPriorityEndpoints()
	if len(highPriorityEndpoints) == 0 {
		return endpoints
	}

	// Convert to string slice and prioritize auth-required endpoints
	prioritized := make([]string, 0)
	for _, ep := range highPriorityEndpoints {
		if ep.AuthRequired || ep.Priority == "high" {
			prioritized = append(prioritized, ep.Path)
		}
	}

	if len(prioritized) == 0 {
		return endpoints
	}

	printInfo(fmt.Sprintf("Focusing timing analysis on %d high-priority endpoints", len(prioritized)), false)
	return prioritized
}

// performTimingAnalysis performs statistical timing analysis on an endpoint
func (tt *TimingTester) performTimingAnalysis(ctx context.Context, endpoint string) error {
	config := tt.hmacTester.GetConfig()
	var validTimes, invalidTimes []time.Duration

	// Test with valid signatures
	for i := 0; i < config.TimingRequests/2; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		responseTime, err := tt.testSignatureValidation(ctx, endpoint, true)
		if err == nil {
			validTimes = append(validTimes, responseTime)
		}
	}

	// Test with invalid signatures
	for i := 0; i < config.TimingRequests/2; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		responseTime, err := tt.testSignatureValidation(ctx, endpoint, false)
		if err == nil {
			invalidTimes = append(invalidTimes, responseTime)
		}
	}

	// Analyze timing differences
	if timeDiff, isVulnerable := analyzeTimingDifference(validTimes, invalidTimes); isVulnerable {
		tt.recordTimingVulnerability(endpoint, timeDiff)
	}

	return nil
}

// testSignatureValidation tests a signature and returns response time
func (tt *TimingTester) testSignatureValidation(ctx context.Context, endpoint string, useValidSignature bool) (time.Duration, error) {
	target := tt.hmacTester.GetTarget()
	timestamp := time.Now()

	var signature string
	var testType string

	if useValidSignature && target.Auth.Type == "hmac" {
		signature = generateHMAC(endpoint, "GET", timestamp, target)
		testType = "timing_valid"
	} else {
		signature = generateInvalidHMAC(tt.hmacTester.GetTestsExecuted())
		testType = "timing_invalid"
	}

	response, _ := tt.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", signature, timestamp, testType)

	if response.Error != nil {
		return 0, response.Error
	}

	return response.ResponseTime, nil
}

// recordTimingVulnerability records a timing attack vulnerability
func (tt *TimingTester) recordTimingVulnerability(endpoint string, timeDiff time.Duration) {
	target := tt.hmacTester.GetTarget()

	vuln := HMACVulnerability{
		Type:         "timing",
		Severity:     "medium",
		Endpoint:     endpoint,
		Method:       "GET",
		Description:  "HMAC timing attack vulnerability detected",
		Evidence:     fmt.Sprintf("Timing difference between valid and invalid signatures: %v", timeDiff),
		Remediation:  "Implement constant-time HMAC verification to prevent timing attacks",
		RiskScore:    65,
		Algorithm:    target.Auth.HMAC.Algorithm,
		ResponseTime: timeDiff,
		AttackVector: "Timing analysis attack",
	}

	tt.hmacTester.RecordVulnerability(vuln)
	tt.hmacTester.RecordTimingAnomaly()
}
