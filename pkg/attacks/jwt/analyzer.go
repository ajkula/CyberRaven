package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

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

func (jf *JWTFuzzer) getStandardTokens() []string {
	return jf.generateTestTokens()
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

func (jf *JWTFuzzer) generateTestTokens() []string {
	// Generate sample JWT tokens for testing
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`))

	return []string{
		header + "." + payload + ".fake_signature",
	}
}
