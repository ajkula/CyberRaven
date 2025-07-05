package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// HTTPClient represents an enhanced HTTP client for penetration testing
type HTTPClient struct {
	client    *http.Client
	config    *config.TargetConfig
	userAgent string

	// Rate limiting
	rateLimiter chan struct{}

	// Request tracking
	requestCount int64
	totalTime    time.Duration
}

// HTTPResponse represents an enhanced HTTP response with additional metadata
type HTTPResponse struct {
	*http.Response

	// Timing information
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Request information
	RequestURL     string            `json:"request_url"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`

	// Response analysis
	SecurityScore int      `json:"security_score"`
	Fingerprints  []string `json:"fingerprints"`

	// Body content (limited for security)
	BodyPreview string `json:"body_preview"` // First 1024 chars
	BodySize    int64  `json:"body_size"`
}

// HTTPError represents an enhanced HTTP error with additional context
type HTTPError struct {
	URL        string        `json:"url"`
	Method     string        `json:"method"`
	StatusCode int           `json:"status_code,omitempty"`
	Duration   time.Duration `json:"duration"`
	Message    string        `json:"message"`    // Renamed from Error to avoid conflict
	ErrorType  string        `json:"error_type"` // timeout, connection, dns, tls, etc.
	Retries    int           `json:"retries"`
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %s %s failed: %s (type: %s, retries: %d)",
		e.Method, e.URL, e.Message, e.ErrorType, e.Retries)
}

// NewHTTPClient creates a new enhanced HTTP client for penetration testing
func NewHTTPClient(targetConfig *config.TargetConfig, engineConfig *config.EngineConfig) (*HTTPClient, error) {
	// Create base transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false, // Enable compression analysis
	}

	// Configure TLS
	tlsConfig, err := createTLSConfig(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}
	transport.TLSClientConfig = tlsConfig

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   engineConfig.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow limited redirects for analysis
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Create rate limiter
	rateLimiter := make(chan struct{}, engineConfig.MaxWorkers)

	return &HTTPClient{
		client:      client,
		config:      targetConfig,
		userAgent:   "CyberRaven/1.0 Security Scanner",
		rateLimiter: rateLimiter,
	}, nil
}

// Get performs an enhanced HTTP GET request
func (hc *HTTPClient) Get(ctx context.Context, url string) (*HTTPResponse, error) {
	return hc.Do(ctx, "GET", url, nil, nil)
}

// Post performs an enhanced HTTP POST request
func (hc *HTTPClient) Post(ctx context.Context, url string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	return hc.Do(ctx, "POST", url, body, headers)
}

// Put performs an enhanced HTTP PUT request
func (hc *HTTPClient) Put(ctx context.Context, url string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	return hc.Do(ctx, "PUT", url, body, headers)
}

// Delete performs an enhanced HTTP DELETE request
func (hc *HTTPClient) Delete(ctx context.Context, url string) (*HTTPResponse, error) {
	return hc.Do(ctx, "DELETE", url, nil, nil)
}

// Head performs an enhanced HTTP HEAD request
func (hc *HTTPClient) Head(ctx context.Context, url string) (*HTTPResponse, error) {
	return hc.Do(ctx, "HEAD", url, nil, nil)
}

// Options performs an enhanced HTTP OPTIONS request
func (hc *HTTPClient) Options(ctx context.Context, url string) (*HTTPResponse, error) {
	return hc.Do(ctx, "OPTIONS", url, nil, nil)
}

// Do performs an enhanced HTTP request with retry logic and analysis
func (hc *HTTPClient) Do(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	// Acquire rate limit slot
	select {
	case hc.rateLimiter <- struct{}{}:
		defer func() { <-hc.rateLimiter }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var lastErr error
	maxRetries := 3

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return nil, &HTTPError{
				URL:       url,
				Method:    method,
				Message:   err.Error(),
				ErrorType: "request_creation",
				Retries:   attempt,
			}
		}

		// Set headers
		hc.setRequestHeaders(req, headers)

		// Execute request with timing
		startTime := time.Now()
		resp, err := hc.client.Do(req)
		endTime := time.Now()
		duration := endTime.Sub(startTime)

		// Update metrics
		hc.requestCount++
		hc.totalTime += duration

		if err != nil {
			errorType := classifyHTTPError(err)
			lastErr = &HTTPError{
				URL:       url,
				Method:    method,
				Duration:  duration,
				Message:   err.Error(),
				ErrorType: errorType,
				Retries:   attempt,
			}

			// Retry on certain error types
			if shouldRetry(errorType) && attempt < maxRetries {
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
				continue
			}

			return nil, lastErr
		}

		// Create enhanced response
		enhancedResp, err := hc.createEnhancedResponse(resp, req, startTime, endTime)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to create enhanced response: %w", err)
		}

		return enhancedResp, nil
	}

	return nil, lastErr
}

// setRequestHeaders sets appropriate headers for penetration testing
func (hc *HTTPClient) setRequestHeaders(req *http.Request, additionalHeaders map[string]string) {
	// Set User-Agent
	req.Header.Set("User-Agent", hc.userAgent)

	// Set target-specific headers
	for key, value := range hc.config.Headers {
		req.Header.Set(key, value)
	}

	// Set additional headers
	for key, value := range additionalHeaders {
		req.Header.Set(key, value)
	}

	// Add authentication
	hc.addAuthentication(req)

	// Set common penetration testing headers
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}
}

// addAuthentication adds authentication headers based on configuration
func (hc *HTTPClient) addAuthentication(req *http.Request) {
	switch hc.config.Auth.Type {
	case "basic":
		if hc.config.Auth.Username != "" && hc.config.Auth.Password != "" {
			req.SetBasicAuth(hc.config.Auth.Username, hc.config.Auth.Password)
		}
	case "bearer", "jwt":
		if hc.config.Auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+hc.config.Auth.Token)
		}
	case "hmac":
		// TODO: Implement HMAC authentication
		// This would require calculating HMAC signature based on request
	case "custom":
		for key, value := range hc.config.Auth.CustomHeaders {
			req.Header.Set(key, value)
		}
	}
}

// createEnhancedResponse creates an enhanced response with security analysis
func (hc *HTTPClient) createEnhancedResponse(resp *http.Response, req *http.Request, startTime, endTime time.Time) (*HTTPResponse, error) {
	enhanced := &HTTPResponse{
		Response:       resp,
		StartTime:      startTime,
		EndTime:        endTime,
		Duration:       endTime.Sub(startTime),
		RequestURL:     req.URL.String(),
		RequestMethod:  req.Method,
		RequestHeaders: make(map[string]string),
	}

	// Copy request headers for analysis
	for key, values := range req.Header {
		if len(values) > 0 {
			enhanced.RequestHeaders[key] = values[0]
		}
	}

	// Read and analyze response body
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		resp.Body.Close()

		// Store body information
		enhanced.BodySize = int64(len(bodyBytes))
		if len(bodyBytes) > 1024 {
			enhanced.BodyPreview = string(bodyBytes[:1024]) + "..."
		} else {
			enhanced.BodyPreview = string(bodyBytes)
		}

		// Recreate body reader for caller
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	// Perform security analysis
	enhanced.SecurityScore = hc.calculateSecurityScore(resp)
	enhanced.Fingerprints = hc.extractFingerprints(resp)

	return enhanced, nil
}

// calculateSecurityScore calculates a security score based on response headers and content
func (hc *HTTPClient) calculateSecurityScore(resp *http.Response) int {
	score := 100

	// Security headers analysis
	securityHeaders := map[string]int{
		"X-Frame-Options":                   10,
		"X-XSS-Protection":                  10,
		"X-Content-Type-Options":            10,
		"Strict-Transport-Security":         15,
		"Content-Security-Policy":           15,
		"Referrer-Policy":                   5,
		"X-Permitted-Cross-Domain-Policies": 5,
	}

	for header, penalty := range securityHeaders {
		if resp.Header.Get(header) == "" {
			score -= penalty
		}
	}

	// Information disclosure penalties
	disclosureHeaders := map[string]int{
		"Server":           5,
		"X-Powered-By":     5,
		"X-AspNet-Version": 10,
		"X-Generator":      5,
	}

	for header, penalty := range disclosureHeaders {
		if resp.Header.Get(header) != "" {
			score -= penalty
		}
	}

	// Status code analysis
	if resp.StatusCode >= 500 {
		score -= 20 // Server errors indicate potential issues
	} else if resp.StatusCode == 403 {
		score += 5 // Access controls in place
	}

	// Content-Type validation
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		score -= 5
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// extractFingerprints extracts technology fingerprints from the response
func (hc *HTTPClient) extractFingerprints(resp *http.Response) []string {
	var fingerprints []string

	// Server header analysis
	if server := resp.Header.Get("Server"); server != "" {
		fingerprints = append(fingerprints, "Server: "+server)
	}

	// Technology-specific headers
	techHeaders := map[string]string{
		"X-Powered-By":     "PoweredBy",
		"X-AspNet-Version": "ASP.NET",
		"X-Generator":      "Generator",
		"X-Runtime":        "Runtime",
	}

	for header, tech := range techHeaders {
		if value := resp.Header.Get(header); value != "" {
			fingerprints = append(fingerprints, tech+": "+value)
		}
	}

	// Framework detection from headers
	if resp.Header.Get("X-Frame-Options") != "" {
		fingerprints = append(fingerprints, "Framework: Modern web framework")
	}

	return fingerprints
}

// GetStats returns client statistics
func (hc *HTTPClient) GetStats() (int64, time.Duration, float64) {
	if hc.requestCount == 0 {
		return 0, 0, 0
	}

	avgTime := hc.totalTime / time.Duration(hc.requestCount)
	requestsPerSecond := float64(hc.requestCount) / hc.totalTime.Seconds()

	return hc.requestCount, avgTime, requestsPerSecond
}

// Close closes the HTTP client and cleans up resources
func (hc *HTTPClient) Close() {
	// Close rate limiter channel
	close(hc.rateLimiter)

	// Close idle connections
	hc.client.CloseIdleConnections()
}

// Utility functions

// createTLSConfig creates TLS configuration based on target settings
func createTLSConfig(target *config.TargetConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: target.TLS.InsecureSkipVerify,
	}

	// Set TLS version constraints
	if target.TLS.MinVersion != "" {
		minVersion, err := parseTLSVersion(target.TLS.MinVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid min TLS version: %w", err)
		}
		tlsConfig.MinVersion = minVersion
	}

	if target.TLS.MaxVersion != "" {
		maxVersion, err := parseTLSVersion(target.TLS.MaxVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid max TLS version: %w", err)
		}
		tlsConfig.MaxVersion = maxVersion
	}

	// Load custom CA certificate
	if target.TLS.CACertPath != "" {
		caCert, err := os.ReadFile(target.TLS.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate for mutual TLS
	if target.TLS.ClientCertPath != "" && target.TLS.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(target.TLS.ClientCertPath, target.TLS.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// parseTLSVersion parses TLS version string to constant
func parseTLSVersion(version string) (uint16, error) {
	switch strings.ToUpper(version) {
	case "1.0", "TLS1.0":
		return tls.VersionTLS10, nil
	case "1.1", "TLS1.1":
		return tls.VersionTLS11, nil
	case "1.2", "TLS1.2":
		return tls.VersionTLS12, nil
	case "1.3", "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// classifyHTTPError classifies HTTP errors for retry logic
func classifyHTTPError(err error) string {
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "connection refused"):
		return "connection_refused"
	case strings.Contains(errStr, "no such host"):
		return "dns"
	case strings.Contains(errStr, "tls"):
		return "tls"
	case strings.Contains(errStr, "certificate"):
		return "certificate"
	case strings.Contains(errStr, "context canceled"):
		return "canceled"
	default:
		return "unknown"
	}
}

// shouldRetry determines if an error type should trigger a retry
func shouldRetry(errorType string) bool {
	retryableErrors := []string{
		"timeout",
		"connection_refused",
		"unknown",
	}

	for _, retryable := range retryableErrors {
		if errorType == retryable {
			return true
		}
	}
	return false
}
