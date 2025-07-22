package jwt

import (
	"context"
	"encoding/json"
	"strings"
)

func (jf *JWTFuzzer) discoverJWTTokensFromEndpoints(ctx context.Context, endpoints []string) ([]string, error) {
	var tokens []string

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return tokens, ctx.Err()
		default:
		}

		token, err := jf.extractJWTFromEndpoint(ctx, endpoint)
		if err != nil {
			continue
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

func (jf *JWTFuzzer) isValidJWTStructure(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

func (jf *JWTFuzzer) hasIntelligentTokenInfo() bool {
	if jf.discoveryCtx == nil {
		return false
	}
	return len(jf.discoveryCtx.GetJWTTokens()) > 0
}

func (jf *JWTFuzzer) getIntelligentEndpoints() []string {
	if jf.discoveryCtx == nil {
		return []string{}
	}

	targetEndpoints := jf.discoveryCtx.GetTargetedEndpoints("jwt")
	endpoints := make([]string, 0, len(targetEndpoints))

	for _, endpoint := range targetEndpoints {
		endpoints = append(endpoints, endpoint.Path)
	}

	return endpoints
}

func (jf *JWTFuzzer) getStandardEndpoints() []string {
	return jf.testEndpoints
}

func (jf *JWTFuzzer) getDiscoveredTokensCount() int {
	if jf.discoveryCtx == nil {
		return 0
	}
	return len(jf.discoveryCtx.GetJWTTokens())
}

func (jf *JWTFuzzer) getRecommendedModules() []string {
	if jf.discoveryCtx == nil {
		return []string{}
	}
	return jf.discoveryCtx.GetRecommendedModules()
}
