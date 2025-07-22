package hmac

import (
	"context"
	"fmt"
	"time"
)

// ReplayTester handles HMAC replay attack testing
type ReplayTester struct {
	hmacTester *HMACTester
}

// NewReplayTester creates a new replay attack tester
func NewReplayTester(hmacTester *HMACTester) *ReplayTester {
	return &ReplayTester{
		hmacTester: hmacTester,
	}
}

// Execute performs comprehensive replay attack testing
func (rt *ReplayTester) Execute(ctx context.Context) error {
	var endpoints []string

	if rt.hmacTester.HasIntelligence() {
		endpoints = rt.hmacTester.GetIntelligentEndpoints()
		printInfo(fmt.Sprintf("Using discovery intelligence: %d targeted endpoints", len(endpoints)), false)
	} else {
		endpoints = rt.hmacTester.GetTestEndpoints()
		printInfo(fmt.Sprintf("Standard testing mode: %d generic endpoints", len(endpoints)), false)
	}

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := rt.testEndpointReplay(ctx, endpoint); err != nil {
			continue // Continue with other endpoints
		}
	}

	return nil
}

// testEndpointReplay tests replay attacks on a specific endpoint
func (rt *ReplayTester) testEndpointReplay(ctx context.Context, endpoint string) error {
	// Step 1: Capture a valid signature
	originalSig, originalTimestamp, err := rt.captureValidSignature(ctx, endpoint)
	if err != nil {
		return err
	}

	// Step 2: Wait for replay window to potentially expire
	time.Sleep(200 * time.Millisecond)

	// Step 3: Attempt to replay the request with the same signature
	return rt.attemptReplayAttack(ctx, endpoint, originalSig, originalTimestamp)
}

// captureValidSignature captures a valid HMAC signature from the target
func (rt *ReplayTester) captureValidSignature(ctx context.Context, endpoint string) (string, time.Time, error) {
	target := rt.hmacTester.GetTarget()
	timestamp := time.Now()

	var signature string
	if target.Auth.Type == "hmac" && target.Auth.HMAC.Secret != "" {
		signature = generateHMAC(endpoint, "GET", timestamp, target)
	}

	response, _ := rt.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", signature, timestamp, "capture")

	if response.Error != nil {
		return "", timestamp, fmt.Errorf("failed to capture signature: %w", response.Error)
	}

	if response.StatusCode >= 400 {
		return "", timestamp, fmt.Errorf("authentication failed during capture (status: %d)", response.StatusCode)
	}

	return signature, timestamp, nil
}

// attemptReplayAttack attempts to replay a captured signature
func (rt *ReplayTester) attemptReplayAttack(ctx context.Context, endpoint, signature string, timestamp time.Time) error {
	response, _ := rt.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", signature, timestamp, "replay")

	if response.Error != nil {
		return fmt.Errorf("replay request failed: %w", response.Error)
	}

	// Check if replay was successful (vulnerability detected)
	if response.StatusCode < 400 {
		rt.recordReplayVulnerability(endpoint, signature, timestamp, response.ResponseTime)
	}

	return nil
}

// recordReplayVulnerability records a successful replay attack as a vulnerability
func (rt *ReplayTester) recordReplayVulnerability(endpoint, signature string, timestamp time.Time, responseTime time.Duration) {
	target := rt.hmacTester.GetTarget()

	vuln := HMACVulnerability{
		Type:              "replay",
		Severity:          "high",
		Endpoint:          endpoint,
		Method:            "GET",
		Description:       "HMAC signature replay attack successful",
		Evidence:          fmt.Sprintf("Replayed signature accepted after %v delay", time.Since(timestamp)),
		Remediation:       "Implement timestamp validation and nonce tracking to prevent replay attacks",
		RiskScore:         85,
		Algorithm:         target.Auth.HMAC.Algorithm,
		TimestampUsed:     &timestamp,
		ResponseTime:      responseTime,
		AttackVector:      "Signature replay attack",
		OriginalSignature: signature,
	}

	rt.hmacTester.RecordVulnerability(vuln)
	rt.hmacTester.RecordReplaySuccess()
}

// testReplayWithModifiedTimestamp tests replay with modified timestamps
func (rt *ReplayTester) testReplayWithModifiedTimestamp(ctx context.Context, endpoint string) error {
	// Capture original signature
	originalSig, originalTimestamp, err := rt.captureValidSignature(ctx, endpoint)
	if err != nil {
		return err
	}

	// Test with various timestamp modifications
	modifications := []time.Duration{
		-1 * time.Hour,   // 1 hour ago
		-1 * time.Minute, // 1 minute ago
		1 * time.Minute,  // 1 minute future
		1 * time.Hour,    // 1 hour future
	}

	for _, modification := range modifications {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		modifiedTimestamp := originalTimestamp.Add(modification)

		response, _ := rt.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", originalSig, modifiedTimestamp, "replay_modified_timestamp")

		// If successful with modified timestamp, it's a vulnerability
		if response.Error == nil && response.StatusCode < 400 {
			rt.recordTimestampBypassVulnerability(endpoint, originalSig, originalTimestamp, modifiedTimestamp, response.ResponseTime)
		}
	}

	return nil
}

// recordTimestampBypassVulnerability records a timestamp validation bypass
func (rt *ReplayTester) recordTimestampBypassVulnerability(endpoint, signature string, originalTimestamp, modifiedTimestamp time.Time, responseTime time.Duration) {
	target := rt.hmacTester.GetTarget()
	timeDiff := modifiedTimestamp.Sub(originalTimestamp)

	vuln := HMACVulnerability{
		Type:              "timestamp_bypass",
		Severity:          "high",
		Endpoint:          endpoint,
		Method:            "GET",
		Description:       "HMAC timestamp validation bypass detected",
		Evidence:          fmt.Sprintf("Signature accepted with %v timestamp difference", timeDiff),
		Remediation:       "Implement strict timestamp validation with reasonable time windows",
		RiskScore:         80,
		Algorithm:         target.Auth.HMAC.Algorithm,
		TimestampUsed:     &modifiedTimestamp,
		ResponseTime:      responseTime,
		AttackVector:      "Timestamp validation bypass",
		OriginalSignature: signature,
	}

	rt.hmacTester.RecordVulnerability(vuln)
}

// ExecuteAdvanced performs advanced replay testing with various techniques
func (rt *ReplayTester) ExecuteAdvanced(ctx context.Context) error {
	var endpoints []string

	if rt.hmacTester.HasIntelligence() {
		endpoints = rt.hmacTester.GetIntelligentEndpoints()
		printInfo(fmt.Sprintf("Advanced replay testing with discovery intelligence: %d endpoints", len(endpoints)), false)

		// Test with discovered HMAC signatures if available
		rt.testDiscoveredSignatures(ctx)
	} else {
		endpoints = rt.hmacTester.GetTestEndpoints()
		printInfo(fmt.Sprintf("Advanced replay testing in standard mode: %d endpoints", len(endpoints)), false)
	}

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Test standard replay
		rt.testEndpointReplay(ctx, endpoint)

		// Test timestamp modification attacks
		rt.testReplayWithModifiedTimestamp(ctx, endpoint)
	}

	return nil
}

// testDiscoveredSignatures tests replay attacks using discovered HMAC signatures
func (rt *ReplayTester) testDiscoveredSignatures(ctx context.Context) error {
	discoveryCtx := rt.hmacTester.GetDiscoveryContext()
	if discoveryCtx == nil {
		return nil
	}

	hmacSignatures := discoveryCtx.GetHMACSignatures()
	if len(hmacSignatures) == 0 {
		return nil
	}

	printInfo(fmt.Sprintf("Testing %d discovered HMAC signatures for replay vulnerabilities", len(hmacSignatures)), false)

	for _, sig := range hmacSignatures {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Find corresponding endpoint for this signature
		endpoint := "/api/authenticate" // Default if not found
		for _, ep := range discoveryCtx.Endpoints {
			if ep.AuthRequired {
				endpoint = ep.Path
				break
			}
		}

		// Wait before replay to test time-based validation
		time.Sleep(300 * time.Millisecond)

		// Attempt to replay the discovered signature
		rt.testDiscoveredSignatureReplay(ctx, endpoint, sig.SignatureValue)
	}

	return nil
}

// testDiscoveredSignatureReplay tests replay with a specific discovered signature
func (rt *ReplayTester) testDiscoveredSignatureReplay(ctx context.Context, endpoint, signature string) {
	timestamp := time.Now()

	response, _ := rt.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", signature, timestamp, "discovered_signature_replay")

	// Check if replay was successful (vulnerability detected)
	if response.Error == nil && response.StatusCode < 400 {
		rt.recordDiscoveredSignatureReplayVulnerability(endpoint, signature, response.ResponseTime)
	}
}

// recordDiscoveredSignatureReplayVulnerability records a vulnerability when discovered signature is replayed successfully
func (rt *ReplayTester) recordDiscoveredSignatureReplayVulnerability(endpoint, signature string, responseTime time.Duration) {
	target := rt.hmacTester.GetTarget()

	vuln := HMACVulnerability{
		Type:              "discovered_signature_replay",
		Severity:          "critical",
		Endpoint:          endpoint,
		Method:            "GET",
		Description:       "Discovered HMAC signature successfully replayed",
		Evidence:          "Previously captured HMAC signature accepted without timestamp validation",
		Remediation:       "Implement strict timestamp validation and nonce tracking for HMAC signatures",
		RiskScore:         90,
		Algorithm:         target.Auth.HMAC.Algorithm,
		ResponseTime:      responseTime,
		AttackVector:      "Discovered signature replay attack",
		OriginalSignature: signature,
	}

	rt.hmacTester.RecordVulnerability(vuln)
	rt.hmacTester.RecordReplaySuccess()
}
