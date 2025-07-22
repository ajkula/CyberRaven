package injection

import (
	"time"
)

// InjectionTestResult represents the result of injection testing
type InjectionTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                      `json:"tests_executed"`
	VulnerabilitiesFound []InjectionVulnerability `json:"vulnerabilities_found"`
	TestedParameters     []ParameterTest          `json:"tested_parameters"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`
}

// InjectionVulnerability represents an injection-specific vulnerability
type InjectionVulnerability struct {
	Type        string `json:"type"`     // sql, nosql, json, path
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Parameter   string `json:"parameter"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// Injection-specific fields
	PayloadUsed     string `json:"payload_used"`
	ResponseSnippet string `json:"response_snippet"`
	AttackVector    string `json:"attack_vector"`
	DatabaseType    string `json:"database_type,omitempty"`
}

// ParameterTest represents a tested parameter
type ParameterTest struct {
	Endpoint     string        `json:"endpoint"`
	Method       string        `json:"method"`
	Parameter    string        `json:"parameter"`
	PayloadType  string        `json:"payload_type"`
	Vulnerable   bool          `json:"vulnerable"`
	ResponseTime time.Duration `json:"response_time"`
}
