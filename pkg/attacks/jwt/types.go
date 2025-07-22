package jwt

import (
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
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

	IntelligenceUsed   bool     `json:"intelligence_used"`
	DiscoveredTokens   int      `json:"discovered_tokens"`
	RecommendedModules []string `json:"recommended_modules"`

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
	config        *config.JWTAttackConfig
	target        *config.TargetConfig
	attackContext *discovery.AttackContext
	httpClient    *utils.HTTPClient

	// JWT testing parameters
	testEndpoints []string
	weakSecrets   []string
	discoveryCtx  *discovery.AttackContext

	// Results tracking
	mu              sync.RWMutex
	testsExecuted   int
	vulnerabilities []JWTVulnerability
	tokensAnalyzed  []TokenAnalysis
	successfulTests int
	failedTests     int
}
