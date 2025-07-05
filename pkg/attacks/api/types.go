package api

import (
	"time"
)

// EnumerationResult represents the result of an API endpoint enumeration test
type EnumerationResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL   string `json:"base_url"`
	UserAgent string `json:"user_agent"`

	// Enumeration results
	TestedEndpoints  int              `json:"tested_endpoints"`
	FoundEndpoints   []EndpointResult `json:"found_endpoints"`
	ErroredEndpoints []EndpointError  `json:"errored_endpoints"`

	// Security findings
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessRate       float64 `json:"success_rate"`
}

// EndpointResult represents information about a discovered endpoint
type EndpointResult struct {
	Path          string            `json:"path"`
	Method        string            `json:"method"`
	StatusCode    int               `json:"status_code"`
	ResponseSize  int64             `json:"response_size"`
	ResponseTime  time.Duration     `json:"response_time"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"content_type"`
	ServerHeader  string            `json:"server_header"`
	SecurityScore int               `json:"security_score"` // 0-100
}

// EndpointError represents an error encountered during enumeration
type EndpointError struct {
	Path      string `json:"path"`
	Method    string `json:"method"`
	Error     string `json:"error"`
	ErrorType string `json:"error_type"` // timeout, connection, dns, etc.
}

// VulnerabilityFinding represents a security vulnerability discovered
type VulnerabilityFinding struct {
	Type        string `json:"type"`     // directory_listing, debug_endpoint, etc.
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}
