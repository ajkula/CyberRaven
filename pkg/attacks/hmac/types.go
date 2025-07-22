package hmac

import (
	"hash"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// HMACTestResult represents the result of HMAC security testing
type HMACTestResult struct {
	// Test metadata
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	TestType  string        `json:"test_type"`

	// Target information
	BaseURL string `json:"base_url"`

	// Test results
	TestsExecuted        int                 `json:"tests_executed"`
	VulnerabilitiesFound []HMACVulnerability `json:"vulnerabilities_found"`
	SignatureTests       []SignatureTest     `json:"signature_tests"`

	// Performance metrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessfulTests   int     `json:"successful_tests"`
	FailedTests       int     `json:"failed_tests"`

	// HMAC-specific metrics
	ReplayAttemptsSuccessful int           `json:"replay_attempts_successful"`
	TimingAnomaliesDetected  int           `json:"timing_anomalies_detected"`
	AverageResponseTime      time.Duration `json:"average_response_time"`
}

// HMACVulnerability represents an HMAC-specific security vulnerability
type HMACVulnerability struct {
	Type        string `json:"type"`     // replay, timing, weak_secret, bypass
	Severity    string `json:"severity"` // low, medium, high, critical
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"` // 0-100

	// HMAC-specific fields
	Algorithm         string        `json:"algorithm"`
	TimestampUsed     *time.Time    `json:"timestamp_used,omitempty"`
	ResponseTime      time.Duration `json:"response_time"`
	AttackVector      string        `json:"attack_vector"`
	OriginalSignature string        `json:"original_signature,omitempty"`
	ForgedSignature   string        `json:"forged_signature,omitempty"`
}

// SignatureTest represents a tested HMAC signature
type SignatureTest struct {
	Endpoint     string        `json:"endpoint"`
	Method       string        `json:"method"`
	Algorithm    string        `json:"algorithm"`
	Timestamp    time.Time     `json:"timestamp"`
	Signature    string        `json:"signature"`
	Valid        bool          `json:"valid"`
	ResponseTime time.Duration `json:"response_time"`
	ResponseCode int           `json:"response_code"`
	TestType     string        `json:"test_type"` // normal, replay, timing, forged
}

// HMACTester handles HMAC security testing
type HMACTester struct {
	config       *config.HMACAttackConfig
	target       *config.TargetConfig
	httpClient   *utils.HTTPClient
	discoveryCtx *discovery.AttackContext

	// Test parameters
	testEndpoints []string
	algorithms    map[string]func() hash.Hash
	commonSecrets []string

	// Results tracking (thread-safe)
	mu                       sync.RWMutex
	testsExecuted            int
	vulnerabilities          []HMACVulnerability
	signatureTests           []SignatureTest
	successfulTests          int
	failedTests              int
	replayAttemptsSuccessful int
	timingAnomalies          int
	responseTimes            []time.Duration
}

// TestRequest represents a standardized HMAC test request
type TestRequest struct {
	Endpoint  string
	Method    string
	Signature string
	Timestamp time.Time
	TestType  string
	IsValid   bool
	Headers   map[string]string
}

// TestResponse represents the response from an HMAC test
type TestResponse struct {
	StatusCode   int
	ResponseTime time.Duration
	Success      bool
	Error        error
}

// TimingTestData holds timing analysis data
type TimingTestData struct {
	ValidTimes   []time.Duration
	InvalidTimes []time.Duration
	Endpoint     string
	SampleSize   int
}

// BypassTechnique represents a signature bypass testing technique
type BypassTechnique struct {
	Name        string
	Signature   string
	Description string
	RiskLevel   string
}
