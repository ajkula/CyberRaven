package api

import (
	"github.com/ajkula/cyberraven/pkg/utils"
)

// ResponseAnalyzer handles analysis of HTTP responses
type ResponseAnalyzer struct {
	detector *VulnerabilityDetector
}

// NewResponseAnalyzer creates a new response analyzer
func NewResponseAnalyzer() *ResponseAnalyzer {
	return &ResponseAnalyzer{
		detector: NewVulnerabilityDetector(),
	}
}

// AnalyzeResponse analyzes an HTTP response and returns results
func (ra *ResponseAnalyzer) AnalyzeResponse(path, method string, resp *utils.HTTPResponse) (*EndpointResult, []VulnerabilityFinding) {
	// Check if response is interesting
	if !ra.isInterestingResponse(resp.StatusCode, method) {
		return nil, nil
	}

	// Create endpoint result
	result := &EndpointResult{
		Path:          path,
		Method:        method,
		StatusCode:    resp.StatusCode,
		ResponseSize:  resp.BodySize,
		ResponseTime:  resp.Duration,
		Headers:       make(map[string]string),
		ContentType:   resp.Header.Get("Content-Type"),
		ServerHeader:  resp.Header.Get("Server"),
		SecurityScore: resp.SecurityScore,
	}

	// Copy important headers
	for _, header := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Frame-Options", "X-XSS-Protection"} {
		if value := resp.Header.Get(header); value != "" {
			result.Headers[header] = value
		}
	}

	// Analyze for vulnerabilities
	vulnerabilities := ra.detector.AnalyzeResponse(path, method, resp)

	return result, vulnerabilities
}

// isInterestingResponse determines if a response is worth recording
func (ra *ResponseAnalyzer) isInterestingResponse(statusCode int, method string) bool {
	switch statusCode {
	case 200, 201, 202, 204: // Success responses
		return true
	case 301, 302, 303, 307, 308: // Redirects
		return true
	case 401, 403: // Authentication/authorization errors
		return true
	case 405: // Method not allowed (indicates endpoint exists)
		return method == "GET" // Only record for GET requests
	case 500, 502, 503, 504: // Server errors (might indicate vulnerabilities)
		return true
	default:
		return false
	}
}
