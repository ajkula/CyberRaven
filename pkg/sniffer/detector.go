// Package sniffer implements network traffic sniffing and analysis for CyberRaven
// File: pkg/sniffer/detector.go
package sniffer

import (
	"fmt"

	"github.com/ajkula/cyberraven/pkg/config"
)

// NewDetector creates a new security pattern detector
func NewDetector(config *config.SnifferConfig) *Detector {
	return &Detector{
		config: config,
		detectionResults: &DetectionResults{
			Tokens:        make([]DiscoveredToken, 0),
			Signatures:    make([]DiscoveredSignature, 0),
			Endpoints:     make([]DiscoveredEndpoint, 0),
			SensitiveData: make([]SensitiveDataLeak, 0),
		},
	}
}

// ProcessConversation analyzes an HTTP conversation for security patterns
func (d *Detector) ProcessConversation(conversation *HTTPConversation) (*DetectionResults, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	results := &DetectionResults{
		Tokens:        make([]DiscoveredToken, 0),
		Signatures:    make([]DiscoveredSignature, 0),
		Endpoints:     make([]DiscoveredEndpoint, 0),
		SensitiveData: make([]SensitiveDataLeak, 0),
	}

	if conversation.Request != nil {
		// Detect tokens in request
		tokens := d.detectTokensInRequest(conversation.Request)
		results.Tokens = append(results.Tokens, tokens...)
		d.detectionResults.Tokens = append(d.detectionResults.Tokens, tokens...)

		// Detect signatures in request
		signatures := d.detectSignaturesInRequest(conversation.Request)
		results.Signatures = append(results.Signatures, signatures...)
		d.detectionResults.Signatures = append(d.detectionResults.Signatures, signatures...)

		// Detect endpoint characteristics with deduplication
		newEndpoint := d.detectEndpointFromRequest(conversation.Request, conversation.Response)
		if newEndpoint != nil {
			// Check if this endpoint already exists (same method + path)
			existingIndex := d.findExistingEndpoint(newEndpoint.Method, newEndpoint.Path)

			if existingIndex != -1 {
				// Endpoint exists - update it instead of adding duplicate
				existing := &d.detectionResults.Endpoints[existingIndex]
				existing.RequestCount++
				existing.LastSeen = newEndpoint.LastSeen

				// Merge status codes if present
				if len(newEndpoint.StatusCodes) > 0 && len(existing.StatusCodes) > 0 {
					// Add new status code if not already present
					statusExists := false
					for _, existingStatus := range existing.StatusCodes {
						if existingStatus == newEndpoint.StatusCodes[0] {
							statusExists = true
							break
						}
					}
					if !statusExists {
						existing.StatusCodes = append(existing.StatusCodes, newEndpoint.StatusCodes[0])
					}
				} else if len(newEndpoint.StatusCodes) > 0 {
					existing.StatusCodes = newEndpoint.StatusCodes
				}

				// Update authentication requirement (once detected, stays true)
				if newEndpoint.AuthRequired {
					existing.AuthRequired = true
				}

				// Update CSRF protection (once detected, stays true)
				if newEndpoint.CSRFProtected {
					existing.CSRFProtected = true
				}

				// Merge parameters
				existing.Parameters = d.mergeParameters(existing.Parameters, newEndpoint.Parameters)

				// Return the updated endpoint in results
				results.Endpoints = append(results.Endpoints, *existing)
			} else {
				// New endpoint - add it
				results.Endpoints = append(results.Endpoints, *newEndpoint)
				d.detectionResults.Endpoints = append(d.detectionResults.Endpoints, *newEndpoint)
			}
		}

		// Detect sensitive data leaks
		leaks := d.detectSensitiveDataInConversation(conversation)
		results.SensitiveData = append(results.SensitiveData, leaks...)
		d.detectionResults.SensitiveData = append(d.detectionResults.SensitiveData, leaks...)
	}

	return results, nil
}

// findExistingEndpoint finds an endpoint with matching method and path
func (d *Detector) findExistingEndpoint(method, path string) int {
	for i, endpoint := range d.detectionResults.Endpoints {
		if endpoint.Method == method && endpoint.Path == path {
			return i
		}
	}
	return -1 // Not found
}

// mergeParameters merges parameter lists, avoiding duplicates
func (d *Detector) mergeParameters(existing, new []Parameter) []Parameter {
	// Create a map for fast lookup
	paramMap := make(map[string]Parameter)

	// Add existing parameters
	for _, param := range existing {
		key := param.Name + "_" + param.Type
		paramMap[key] = param
	}

	// Add new parameters, updating existing ones
	for _, newParam := range new {
		key := newParam.Name + "_" + newParam.Type
		if existingParam, exists := paramMap[key]; exists {
			// Merge values
			for _, value := range newParam.Values {
				valueExists := false
				for _, existingValue := range existingParam.Values {
					if existingValue == value {
						valueExists = true
						break
					}
				}
				if !valueExists {
					existingParam.Values = append(existingParam.Values, value)
				}
			}
			// Update injection risk to highest level
			if newParam.InjectionRisk == "high" || existingParam.InjectionRisk == "high" {
				existingParam.InjectionRisk = "high"
			} else if newParam.InjectionRisk == "medium" || existingParam.InjectionRisk == "medium" {
				existingParam.InjectionRisk = "medium"
			}
			paramMap[key] = existingParam
		} else {
			paramMap[key] = newParam
		}
	}

	// Convert back to slice
	result := make([]Parameter, 0, len(paramMap))
	for _, param := range paramMap {
		result = append(result, param)
	}

	return result
}

// GetDiscoveredEndpoints returns all discovered endpoints
func (d *Detector) GetDiscoveredEndpoints() []DiscoveredEndpoint {
	d.mu.RLock()
	defer d.mu.RUnlock()

	endpoints := make([]DiscoveredEndpoint, len(d.detectionResults.Endpoints))
	copy(endpoints, d.detectionResults.Endpoints)
	return endpoints
}

// GetDiscoveredTokens returns all discovered tokens
func (d *Detector) GetDiscoveredTokens() []DiscoveredToken {
	d.mu.RLock()
	defer d.mu.RUnlock()

	tokens := make([]DiscoveredToken, len(d.detectionResults.Tokens))
	copy(tokens, d.detectionResults.Tokens)
	return tokens
}

// GetDiscoveredSignatures returns all discovered signatures
func (d *Detector) GetDiscoveredSignatures() []DiscoveredSignature {
	d.mu.RLock()
	defer d.mu.RUnlock()

	signatures := make([]DiscoveredSignature, len(d.detectionResults.Signatures))
	copy(signatures, d.detectionResults.Signatures)
	return signatures
}

// GetSensitiveDataLeaks returns all discovered sensitive data leaks
func (d *Detector) GetSensitiveDataLeaks() []SensitiveDataLeak {
	d.mu.RLock()
	defer d.mu.RUnlock()

	leaks := make([]SensitiveDataLeak, len(d.detectionResults.SensitiveData))
	copy(leaks, d.detectionResults.SensitiveData)
	return leaks
}

// Private detection methods

func (d *Detector) detectTokensInRequest(request *HTTPRequest) []DiscoveredToken {
	tokens := make([]DiscoveredToken, 0)

	// Check Authorization header
	if auth := request.Authorization; auth != "" {
		if token := d.analyzeAuthorizationHeader(auth); token != nil {
			tokens = append(tokens, *token)
		}
	}

	// Check cookies for session tokens
	for name, value := range request.Cookies {
		if token := d.analyzeCookie(name, value); token != nil {
			tokens = append(tokens, *token)
		}
	}

	// Check custom headers for API keys
	for name, value := range request.Headers {
		if token := d.analyzeCustomHeader(name, value); token != nil {
			tokens = append(tokens, *token)
		}
	}

	// Check query parameters for tokens
	for name, value := range request.QueryParams {
		if token := d.analyzeQueryParameter(name, value); token != nil {
			tokens = append(tokens, *token)
		}
	}

	return tokens
}

func (d *Detector) detectSignaturesInRequest(request *HTTPRequest) []DiscoveredSignature {
	signatures := make([]DiscoveredSignature, 0)

	// Check for HMAC signatures in headers
	for name, value := range request.Headers {
		if signature := d.analyzeSignatureHeader(name, value); signature != nil {
			signatures = append(signatures, *signature)
		}
	}

	return signatures
}

func (d *Detector) detectEndpointFromRequest(request *HTTPRequest, response *HTTPResponse) *DiscoveredEndpoint {
	// Debug: Log what we receive
	fmt.Printf("DEBUG detectEndpoint: Request=%t, Response=%t\n", request != nil, response != nil)
	if request != nil {
		fmt.Printf("DEBUG detectEndpoint: Method=%s, Path=%s\n", request.Method, request.Path)
	}
	if response != nil {
		fmt.Printf("DEBUG detectEndpoint: StatusCode=%d\n", response.StatusCode)
	}

	endpoint := &DiscoveredEndpoint{
		Method:       request.Method,
		Path:         request.Path,
		FullURL:      request.URL,
		Headers:      request.Headers,
		ContentType:  request.ContentType,
		Parameters:   d.extractParameters(request),
		RequestCount: 1,
		LastSeen:     request.Timestamp,
	}

	if response != nil {
		endpoint.StatusCodes = []int{response.StatusCode}
		endpoint.AuthRequired = d.detectAuthRequirement(request, response)
		endpoint.CSRFProtected = d.detectCSRFProtection(request, response)

		// Debug: Confirm status codes are set
		fmt.Printf("DEBUG detectEndpoint: Set StatusCodes=%v\n", endpoint.StatusCodes)
	} else {
		fmt.Printf("DEBUG detectEndpoint: No response - StatusCodes will be null\n")
	}

	return endpoint
}

func (d *Detector) detectSensitiveDataInConversation(conversation *HTTPConversation) []SensitiveDataLeak {
	leaks := make([]SensitiveDataLeak, 0)

	// Check request body for sensitive data
	if conversation.Request != nil && conversation.Request.Body != "" {
		requestLeaks := d.scanForSensitiveData(conversation.Request.Body, "request_body")
		leaks = append(leaks, requestLeaks...)
	}

	// Check response body for sensitive data
	if conversation.Response != nil && conversation.Response.Body != "" {
		responseLeaks := d.scanForSensitiveData(conversation.Response.Body, "response_body")
		leaks = append(leaks, responseLeaks...)
	}

	return leaks
}

// Analysis helper methods

func (d *Detector) analyzeAuthorizationHeader(auth string) *DiscoveredToken {
	if len(auth) < 7 {
		return nil
	}

	// Check for Bearer token
	if auth[:7] == "Bearer " {
		token := auth[7:]
		return &DiscoveredToken{
			Type:        "bearer",
			Value:       d.maskToken(token),
			Location:    "header",
			LocationKey: "Authorization",
			Format:      d.detectTokenFormat(token),
			UsageCount:  1,
			IsValid:     true,
		}
	}

	// Check for JWT (starts with eyJ)
	if len(auth) > 10 && auth[:3] == "eyJ" {
		return &DiscoveredToken{
			Type:        "jwt",
			Value:       d.maskToken(auth),
			Location:    "header",
			LocationKey: "Authorization",
			Format:      "jwt",
			UsageCount:  1,
			IsValid:     d.validateJWT(auth),
		}
	}

	return nil
}

func (d *Detector) analyzeCookie(name, value string) *DiscoveredToken {
	// Common session cookie names
	sessionNames := []string{"sessionid", "session", "jsessionid", "phpsessid", "aspsessionid"}

	for _, sessionName := range sessionNames {
		if name == sessionName {
			return &DiscoveredToken{
				Type:        "session",
				Value:       d.maskToken(value),
				Location:    "cookie",
				LocationKey: name,
				Format:      d.detectTokenFormat(value),
				UsageCount:  1,
				IsValid:     len(value) > 8,
			}
		}
	}

	return nil
}

func (d *Detector) analyzeCustomHeader(name, value string) *DiscoveredToken {
	// Common API key header patterns
	apiKeyHeaders := []string{"x-api-key", "api-key", "x-auth-token", "x-access-token"}

	for _, apiHeader := range apiKeyHeaders {
		if name == apiHeader {
			return &DiscoveredToken{
				Type:        "api_key",
				Value:       d.maskToken(value),
				Location:    "header",
				LocationKey: name,
				Format:      d.detectTokenFormat(value),
				UsageCount:  1,
				IsValid:     len(value) > 16,
			}
		}
	}

	return nil
}

func (d *Detector) analyzeQueryParameter(name, value string) *DiscoveredToken {
	// Common token parameter names
	tokenParams := []string{"token", "access_token", "api_key", "key"}

	for _, tokenParam := range tokenParams {
		if name == tokenParam {
			return &DiscoveredToken{
				Type:        "api_key",
				Value:       d.maskToken(value),
				Location:    "query",
				LocationKey: name,
				Format:      d.detectTokenFormat(value),
				UsageCount:  1,
				IsValid:     len(value) > 12,
			}
		}
	}

	return nil
}

func (d *Detector) analyzeSignatureHeader(name, value string) *DiscoveredSignature {
	// Common signature header patterns
	sigHeaders := []string{"x-signature", "x-hub-signature", "signature", "authorization"}

	for _, sigHeader := range sigHeaders {
		if name == sigHeader && len(value) > 32 {
			return &DiscoveredSignature{
				Type:            "hmac",
				Algorithm:       d.detectSignatureAlgorithm(value),
				Location:        "header",
				HeaderName:      name,
				SignatureValue:  d.maskToken(value),
				RequestsCount:   1,
				ValidSignatures: 1,
			}
		}
	}

	return nil
}

func (d *Detector) extractParameters(request *HTTPRequest) []Parameter {
	params := make([]Parameter, 0)

	// Extract query parameters
	for name, value := range request.QueryParams {
		param := Parameter{
			Name:          name,
			Type:          "query",
			DataType:      d.detectDataType(value),
			Values:        []string{value},
			InjectionRisk: d.assessInjectionRisk(value),
		}
		params = append(params, param)
	}

	// Extract form parameters
	for name, value := range request.FormParams {
		param := Parameter{
			Name:          name,
			Type:          "form",
			DataType:      d.detectDataType(value),
			Values:        []string{value},
			InjectionRisk: d.assessInjectionRisk(value),
		}
		params = append(params, param)
	}

	return params
}

func (d *Detector) detectAuthRequirement(request *HTTPRequest, response *HTTPResponse) bool {
	// Check for 401 Unauthorized
	if response.StatusCode == 401 {
		return true
	}

	// Check for auth headers in request
	if request.Authorization != "" {
		return true
	}

	return false
}

func (d *Detector) detectCSRFProtection(request *HTTPRequest, response *HTTPResponse) bool {
	// Check for CSRF tokens in headers
	csrfHeaders := []string{"x-csrf-token", "x-xsrf-token", "csrf-token"}

	for _, header := range csrfHeaders {
		if _, exists := request.Headers[header]; exists {
			return true
		}
	}

	return false
}

func (d *Detector) scanForSensitiveData(data, location string) []SensitiveDataLeak {
	leaks := make([]SensitiveDataLeak, 0)

	// Simple patterns for sensitive data (basic implementation)
	patterns := map[string]string{
		"email":       `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
		"credit_card": `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
		"ssn":         `\b\d{3}-\d{2}-\d{4}\b`,
		"password":    `(?i)password["\s:=]+[^"\s,}]{8,}`,
	}

	for dataType, pattern := range patterns {
		if matches := d.findMatches(data, pattern); len(matches) > 0 {
			for _, match := range matches {
				leak := SensitiveDataLeak{
					DataType:    dataType,
					Pattern:     pattern,
					Location:    location,
					MaskedValue: d.maskSensitiveData(match),
					Severity:    d.getSeverityForDataType(dataType),
					Occurrences: 1,
					Encrypted:   false,
				}
				leaks = append(leaks, leak)
			}
		}
	}

	return leaks
}

// Utility methods

func (d *Detector) maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "***" + token[len(token)-4:]
}

func (d *Detector) detectTokenFormat(token string) string {
	if len(token) > 10 && token[:3] == "eyJ" {
		return "jwt"
	}
	if len(token) == 32 {
		return "hex"
	}
	if len(token)%4 == 0 {
		return "base64"
	}
	return "custom"
}

func (d *Detector) validateJWT(token string) bool {
	parts := len(token) > 0 && len(splitString(token, ".")) == 3
	return parts
}

func (d *Detector) detectSignatureAlgorithm(signature string) string {
	if len(signature) == 64 {
		return "sha256"
	}
	if len(signature) == 128 {
		return "sha512"
	}
	return "unknown"
}

func (d *Detector) detectDataType(value string) string {
	if value == "true" || value == "false" {
		return "bool"
	}
	if isNumeric(value) {
		return "int"
	}
	if isEmail(value) {
		return "email"
	}
	return "string"
}

func (d *Detector) assessInjectionRisk(value string) string {
	dangerous := []string{"'", "\"", "<", ">", ";", "--", "union", "select", "drop"}

	for _, pattern := range dangerous {
		if containsString(value, pattern) {
			return "high"
		}
	}

	if len(value) > 100 {
		return "medium"
	}

	return "low"
}

func (d *Detector) maskSensitiveData(data string) string {
	if len(data) <= 4 {
		return "***"
	}
	return data[:2] + "***" + data[len(data)-2:]
}

func (d *Detector) getSeverityForDataType(dataType string) string {
	severities := map[string]string{
		"credit_card": "critical",
		"ssn":         "critical",
		"password":    "high",
		"email":       "medium",
	}

	if severity, exists := severities[dataType]; exists {
		return severity
	}
	return "low"
}

func (d *Detector) findMatches(text, pattern string) []string {
	// Simplified pattern matching - in real implementation would use regexp
	matches := make([]string, 0)
	// Basic implementation - would need proper regex
	return matches
}

// Simple utility functions
func splitString(s, sep string) []string {
	// Simplified split - would use strings.Split in real implementation
	return []string{s} // Placeholder
}

func isNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isEmail(s string) bool {
	return len(s) > 5 && containsString(s, "@") && containsString(s, ".")
}

func containsString(s, substr string) bool {
	// Simplified contains - would use strings.Contains in real implementation
	return len(s) >= len(substr) // Placeholder
}
