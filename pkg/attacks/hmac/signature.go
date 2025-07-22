package hmac

import (
	"context"
	"fmt"
	"time"
)

// SignatureTester handles HMAC signature bypass testing
type SignatureTester struct {
	hmacTester *HMACTester
}

// NewSignatureTester creates a new signature bypass tester
func NewSignatureTester(hmacTester *HMACTester) *SignatureTester {
	return &SignatureTester{
		hmacTester: hmacTester,
	}
}

// Execute performs comprehensive signature bypass testing
func (st *SignatureTester) Execute(ctx context.Context) error {
	endpoints := st.hmacTester.GetTestEndpoints()

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Test different bypass techniques
		st.testEmptySignature(ctx, endpoint)
		st.testNullSignature(ctx, endpoint)
		st.testMalformedSignatures(ctx, endpoint)
		st.testSignatureRemoval(ctx, endpoint)
	}

	return nil
}

// testEmptySignature tests bypass with empty signature
func (st *SignatureTester) testEmptySignature(ctx context.Context, endpoint string) {
	st.testBypassTechnique(ctx, endpoint, "", "empty_signature", "critical")
}

// testNullSignature tests bypass with null signature
func (st *SignatureTester) testNullSignature(ctx context.Context, endpoint string) {
	st.testBypassTechnique(ctx, endpoint, "null", "null_signature", "high")
}

// testMalformedSignatures tests bypass with various malformed signatures
func (st *SignatureTester) testMalformedSignatures(ctx context.Context, endpoint string) {
	malformed := []struct {
		signature string
		name      string
	}{
		{"invalid_base64!@#", "malformed_base64"},
		{"000000000000000000000000000000000000000000000000000000000000000", "zero_signature"},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "padding_signature"},
	}

	for _, test := range malformed {
		select {
		case <-ctx.Done():
			return
		default:
		}
		st.testBypassTechnique(ctx, endpoint, test.signature, test.name, "medium")
	}
}

// testSignatureRemoval tests request without signature header
func (st *SignatureTester) testSignatureRemoval(ctx context.Context, endpoint string) {
	target := st.hmacTester.GetTarget()
	timestamp := time.Now()

	// Create headers without signature header
	headers := map[string]string{}
	if target.Auth.HMAC.TimestampHeader != "" {
		headers[target.Auth.HMAC.TimestampHeader] = fmt.Sprintf("%d", timestamp.Unix())
	}

	st.hmacTester.IncrementTestCount()

	startTime := time.Now()
	resp, err := st.hmacTester.GetHTTPClient().Do(ctx, "GET", target.BaseURL+endpoint, nil, headers)
	responseTime := time.Since(startTime)

	if err != nil {
		st.hmacTester.RecordFailedTest()
		return
	}
	defer resp.Body.Close()

	st.hmacTester.RecordSuccessfulTest()
	st.hmacTester.RecordResponseTime(responseTime)

	// Record signature test
	sigTest := SignatureTest{
		Endpoint:     endpoint,
		Method:       "GET",
		Algorithm:    target.Auth.HMAC.Algorithm,
		Timestamp:    timestamp,
		Signature:    "", // No signature
		Valid:        resp.StatusCode < 400,
		ResponseTime: responseTime,
		ResponseCode: resp.StatusCode,
		TestType:     "signature_removal",
	}
	st.hmacTester.RecordSignatureTest(sigTest)

	// Check if request was accepted without signature
	if resp.StatusCode < 400 {
		st.recordSignatureRemovalVulnerability(endpoint, responseTime)
	}
}

// testBypassTechnique tests a specific signature bypass technique
func (st *SignatureTester) testBypassTechnique(ctx context.Context, endpoint, signature, technique, severity string) {
	timestamp := time.Now()

	response, _ := st.hmacTester.ExecuteHTTPTest(ctx, endpoint, "GET", signature, timestamp, technique)

	// Check if bypass was successful
	if response.Error == nil && response.StatusCode < 400 {
		st.recordBypassVulnerability(endpoint, technique, signature, response.ResponseTime, severity)
	}
}

// recordBypassVulnerability records a signature bypass vulnerability
func (st *SignatureTester) recordBypassVulnerability(endpoint, technique, signature string, responseTime time.Duration, severity string) {
	var riskScore int
	switch severity {
	case "critical":
		riskScore = 95
	case "high":
		riskScore = 80
	case "medium":
		riskScore = 65
	default:
		riskScore = 50
	}

	vuln := HMACVulnerability{
		Type:            "bypass",
		Severity:        severity,
		Endpoint:        endpoint,
		Method:          "GET",
		Description:     fmt.Sprintf("HMAC signature bypass using %s", technique),
		Evidence:        fmt.Sprintf("Request accepted with %s signature", technique),
		Remediation:     "Implement proper HMAC signature validation and reject malformed signatures",
		RiskScore:       riskScore,
		ResponseTime:    responseTime,
		AttackVector:    fmt.Sprintf("Signature bypass (%s)", technique),
		ForgedSignature: signature,
	}

	st.hmacTester.RecordVulnerability(vuln)
}

// recordSignatureRemovalVulnerability records a signature removal vulnerability
func (st *SignatureTester) recordSignatureRemovalVulnerability(endpoint string, responseTime time.Duration) {
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

	st.hmacTester.RecordVulnerability(vuln)
}
