// Package sniffer implements network traffic sniffing and analysis for CyberRaven
package sniffer

import (
	"encoding/json"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// SnifferResult represents the complete result of network sniffing session
type SnifferResult struct {
	// Session metadata
	SessionID string        `json:"session_id"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Capture statistics
	PacketsCaptured    int   `json:"packets_captured"`
	BytesCaptured      int64 `json:"bytes_captured"`
	HTTPConversations  int   `json:"http_conversations"`
	HTTPSConversations int   `json:"https_conversations"`

	// Discovery results
	DiscoveredEndpoints  []DiscoveredEndpoint  `json:"discovered_endpoints"`
	DiscoveredTokens     []DiscoveredToken     `json:"discovered_tokens"`
	DiscoveredSignatures []DiscoveredSignature `json:"discovered_signatures"`
	TechnologyProfile    TechnologyProfile     `json:"technology_profile"`

	// Security findings
	SecurityFindings   []SecurityFinding   `json:"security_findings"`
	SensitiveDataLeaks []SensitiveDataLeak `json:"sensitive_data_leaks"`
	TLSIntelligence    TLSIntelligence     `json:"tls_intelligence"`

	// Configuration updates
	ConfigUpdates         ConfigurationUpdates   `json:"config_updates"`
	AttackRecommendations []AttackRecommendation `json:"attack_recommendations"`
}

// DiscoveredEndpoint represents an endpoint discovered through traffic analysis
type DiscoveredEndpoint struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	FullURL     string            `json:"full_url"`
	Parameters  []Parameter       `json:"parameters"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	StatusCodes []int             `json:"status_codes"`

	// Analysis data
	RequestCount  int             `json:"request_count"`
	LastSeen      time.Time       `json:"last_seen"`
	ResponseTimes []time.Duration `json:"response_times"`
	AuthRequired  bool            `json:"auth_required"`
	CSRFProtected bool            `json:"csrf_protected"`

	// Security relevance
	SecurityLevel string   `json:"security_level"` // low, medium, high, critical
	AttackSurface []string `json:"attack_surface"` // injection, auth_bypass, etc.
}

// Parameter represents a discovered request parameter
type Parameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`      // query, form, json, header, cookie
	DataType    string   `json:"data_type"` // string, int, bool, email, etc.
	Values      []string `json:"values"`    // observed values
	IsRequired  bool     `json:"is_required"`
	IsSensitive bool     `json:"is_sensitive"`

	// Injection potential
	InjectionRisk string   `json:"injection_risk"` // none, low, medium, high
	TestPayloads  []string `json:"test_payloads"`  // suggested payloads for testing
}

// DiscoveredToken represents authentication tokens found in traffic
type DiscoveredToken struct {
	Type        string `json:"type"`         // jwt, session, api_key, bearer, custom
	Value       string `json:"value"`        // actual token value (masked in logs)
	Location    string `json:"location"`     // header, cookie, query, body
	LocationKey string `json:"location_key"` // Authorization, session_id, etc.
	Format      string `json:"format"`       // jwt, uuid, hex, base64, custom

	// JWT specific
	JWTHeader    map[string]interface{} `json:"jwt_header,omitempty"`
	JWTPayload   map[string]interface{} `json:"jwt_payload,omitempty"`
	JWTAlgorithm string                 `json:"jwt_algorithm,omitempty"`

	// Analysis
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	UsageCount int        `json:"usage_count"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsValid    bool       `json:"is_valid"`

	// Security assessment
	SecurityIssues []string `json:"security_issues"`
	AttackVectors  []string `json:"attack_vectors"`
}

// DiscoveredSignature represents cryptographic signatures found
type DiscoveredSignature struct {
	Type           string `json:"type"`      // hmac, rsa, ecdsa, custom
	Algorithm      string `json:"algorithm"` // sha256, sha512, etc.
	Location       string `json:"location"`  // header, query, body
	HeaderName     string `json:"header_name,omitempty"`
	SignatureValue string `json:"signature_value"` // masked

	// HMAC specific
	TimestampHeader string `json:"timestamp_header,omitempty"`
	NonceHeader     string `json:"nonce_header,omitempty"`
	PayloadHash     string `json:"payload_hash,omitempty"`

	// Analysis
	RequestsCount   int       `json:"requests_count"`
	ValidSignatures int       `json:"valid_signatures"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`

	// Timing analysis
	ResponseTimes  []time.Duration `json:"response_times"`
	TimingVariance time.Duration   `json:"timing_variance"`

	// Security assessment
	WeakAlgorithm    bool   `json:"weak_algorithm"`
	ReplayRisk       string `json:"replay_risk"` // none, low, medium, high
	TimingAttackRisk string `json:"timing_attack_risk"`
}

// TechnologyProfile represents identified technologies and frameworks
type TechnologyProfile struct {
	// Server information
	WebServer string `json:"web_server"` // nginx, apache, iis, etc.
	Framework string `json:"framework"`  // express, django, spring, etc.
	Language  string `json:"language"`   // node.js, python, java, etc.
	Database  string `json:"database"`   // mysql, postgres, mongodb, etc.

	// Frontend technologies
	Frontend       []string `json:"frontend"`     // react, vue, angular, etc.
	JavaScriptLibs []string `json:"js_libraries"` // jquery, bootstrap, etc.

	// Security technologies
	WAF          string `json:"waf"`           // cloudflare, aws_waf, etc.
	CDN          string `json:"cdn"`           // cloudflare, fastly, etc.
	LoadBalancer string `json:"load_balancer"` // nginx, haproxy, etc.

	// Authentication systems
	AuthSystem  string `json:"auth_system"`  // oauth, saml, custom, etc.
	SessionMgmt string `json:"session_mgmt"` // jwt, sessions, etc.

	// Version information
	Versions map[string]string `json:"versions"` // component -> version

	// Fingerprints
	ServerHeaders    map[string]string `json:"server_headers"`
	SecurityHeaders  map[string]string `json:"security_headers"`
	CookieAttributes map[string]string `json:"cookie_attributes"`
}

// SecurityFinding represents a security issue discovered during sniffing
type SecurityFinding struct {
	Type        string    `json:"type"`     // unencrypted_data, weak_auth, etc.
	Severity    string    `json:"severity"` // low, medium, high, critical
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Location    string    `json:"location"` // URL, header name, etc.
	Remediation string    `json:"remediation"`
	FirstSeen   time.Time `json:"first_seen"`
	Occurrences int       `json:"occurrences"`
}

// SensitiveDataLeak represents detected sensitive information
type SensitiveDataLeak struct {
	DataType    string    `json:"data_type"`    // credit_card, ssn, email, password, etc.
	Pattern     string    `json:"pattern"`      // regex pattern that matched
	Location    string    `json:"location"`     // header, body, query, etc.
	Context     string    `json:"context"`      // surrounding context
	MaskedValue string    `json:"masked_value"` // partially masked for logging
	Severity    string    `json:"severity"`     // low, medium, high, critical
	FirstSeen   time.Time `json:"first_seen"`
	Occurrences int       `json:"occurrences"`
	Encrypted   bool      `json:"encrypted"` // was the data encrypted in transit
}

// ConfigurationUpdates represents suggested configuration updates
type ConfigurationUpdates struct {
	TargetUpdates    TargetConfigUpdates    `json:"target_updates"`
	APIUpdates       APIConfigUpdates       `json:"api_updates"`
	JWTUpdates       JWTConfigUpdates       `json:"jwt_updates"`
	HMACUpdates      HMACConfigUpdates      `json:"hmac_updates"`
	InjectionUpdates InjectionConfigUpdates `json:"injection_updates"`
	DoSUpdates       DoSConfigUpdates       `json:"dos_updates"`
	TLSUpdates       TLSConfigUpdates       `json:"tls_updates"`
}

// TargetConfigUpdates represents updates to target configuration
type TargetConfigUpdates struct {
	BaseURL        string            `json:"base_url,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	AuthType       string            `json:"auth_type,omitempty"`
	AuthToken      string            `json:"auth_token,omitempty"`
	CSRFToken      string            `json:"csrf_token,omitempty"`
	SessionCookies map[string]string `json:"session_cookies,omitempty"`
}

// APIConfigUpdates represents updates to API testing configuration
type APIConfigUpdates struct {
	DiscoveredEndpoints []string `json:"discovered_endpoints"`
	CommonParameters    []string `json:"common_parameters"`
	AuthenticationReq   bool     `json:"authentication_required"`
	RateLimitDetected   bool     `json:"rate_limit_detected"`
	CSRFRequired        bool     `json:"csrf_required"`
}

// JWTConfigUpdates represents updates to JWT testing configuration
type JWTConfigUpdates struct {
	TokensFound     []string `json:"tokens_found"`
	Algorithms      []string `json:"algorithms"`
	TokenLocations  []string `json:"token_locations"`
	RefreshTokens   []string `json:"refresh_tokens"`
	ExpirationTimes []string `json:"expiration_times"`
}

// HMACConfigUpdates represents updates to HMAC testing configuration
type HMACConfigUpdates struct {
	Algorithm       string `json:"algorithm"`
	SignatureHeader string `json:"signature_header"`
	TimestampHeader string `json:"timestamp_header"`
	PayloadHashing  bool   `json:"payload_hashing"`
	TimestampFormat string `json:"timestamp_format"`
	NonceUsed       bool   `json:"nonce_used"`
}

// InjectionConfigUpdates represents updates to injection testing configuration
type InjectionConfigUpdates struct {
	VulnerableParams  []string `json:"vulnerable_params"`
	InputValidation   string   `json:"input_validation"`
	OutputEncoding    bool     `json:"output_encoding"`
	DatabaseType      string   `json:"database_type"`
	FrameworkDetected string   `json:"framework_detected"`
}

// DoSConfigUpdates represents updates to DoS testing configuration
type DoSConfigUpdates struct {
	MaxConnections  int    `json:"max_connections"`
	RateLimit       int    `json:"rate_limit"`
	TimeoutDetected bool   `json:"timeout_detected"`
	LoadBalancer    bool   `json:"load_balancer"`
	CDNDetected     string `json:"cdn_detected"`
}

// TLSConfigUpdates represents updates to TLS testing configuration
type TLSConfigUpdates struct {
	TLSVersions     []string          `json:"tls_versions"`
	CipherSuites    []string          `json:"cipher_suites"`
	CertificateInfo string            `json:"certificate_info"`
	SecurityHeaders map[string]string `json:"security_headers"`
	HSTSEnabled     bool              `json:"hsts_enabled"`
}

// AttackRecommendation represents a recommended attack based on discoveries
type AttackRecommendation struct {
	Module      string   `json:"module"`     // api, jwt, injection, etc.
	Priority    string   `json:"priority"`   // low, medium, high, critical
	Confidence  float64  `json:"confidence"` // 0.0 to 1.0
	Description string   `json:"description"`
	Reasoning   string   `json:"reasoning"`
	Targets     []string `json:"targets"`  // specific endpoints/parameters
	Payloads    []string `json:"payloads"` // suggested test payloads
}

// Detector specializes in finding specific security-relevant patterns
type Detector struct {
	config *config.SnifferConfig

	// Detection engines
	tokenDetector     *TokenDetector
	signatureDetector *SignatureDetector
	endpointDetector  *EndpointDetector
	leakDetector      *SensitiveDataDetector

	// Detection state
	mu               sync.RWMutex
	detectionResults *DetectionResults
}

// Formatter handles output formatting and display
type Formatter struct {
	config   *config.SnifferConfig
	noColor  bool
	verbose  bool
	realTime bool

	// Output state
	mu           sync.RWMutex
	outputBuffer []string
	stats        *DisplayStats
}

// HTTPConversation represents a complete HTTP request/response pair
type HTTPConversation struct {
	ID         string        `json:"id"`
	ClientIP   net.IP        `json:"client_ip"`
	ServerIP   net.IP        `json:"server_ip"`
	ClientPort int           `json:"client_port"`
	ServerPort int           `json:"server_port"`
	Protocol   string        `json:"protocol"` // http, https
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`

	// Request
	Request *HTTPRequest `json:"request"`

	// Response
	Response *HTTPResponse `json:"response"`

	// Analysis
	IsCompleted bool     `json:"is_completed"`
	HasErrors   bool     `json:"has_errors"`
	Errors      []string `json:"errors"`
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method        string                 `json:"method"`
	URL           string                 `json:"url"`
	Path          string                 `json:"path"`
	Protocol      string                 `json:"protocol"`
	Headers       map[string]string      `json:"headers"`
	Body          string                 `json:"body"`
	Cookies       map[string]string      `json:"cookies"`
	QueryParams   map[string]string      `json:"query_params"`
	FormParams    map[string]string      `json:"form_params"`
	JSONParams    map[string]interface{} `json:"json_params"`
	ContentLength int64                  `json:"content_length"`
	ContentType   string                 `json:"content_type"`
	UserAgent     string                 `json:"user_agent"`
	Referer       string                 `json:"referer"`
	Authorization string                 `json:"authorization"`

	// Network metadata
	ClientIP   net.IP    `json:"client_ip"`
	ServerIP   net.IP    `json:"server_ip"`
	ClientPort int       `json:"client_port"`
	ServerPort int       `json:"server_port"`
	Timestamp  time.Time `json:"timestamp"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode    int               `json:"status_code"`
	StatusText    string            `json:"status_text"`
	Protocol      string            `json:"protocol"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	Cookies       map[string]string `json:"cookies"`
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type"`
	ServerHeader  string            `json:"server_header"`

	// Network metadata
	ClientIP   net.IP    `json:"client_ip"`
	ServerIP   net.IP    `json:"server_ip"`
	ClientPort int       `json:"client_port"`
	ServerPort int       `json:"server_port"`
	Timestamp  time.Time `json:"timestamp"`
}

// Supporting types for specialized components

// AnalysisResults holds results from traffic analysis
type AnalysisResults struct {
	Patterns     []Pattern         `json:"patterns"`
	Technologies TechnologyProfile `json:"technologies"`
	Statistics   TrafficStats      `json:"statistics"`
	Anomalies    []*Anomaly        `json:"anomalies"`
}

// DetectionResults holds results from pattern detection
type DetectionResults struct {
	Tokens        []DiscoveredToken     `json:"tokens"`
	Signatures    []DiscoveredSignature `json:"signatures"`
	Endpoints     []DiscoveredEndpoint  `json:"endpoints"`
	SensitiveData []SensitiveDataLeak   `json:"sensitive_data"`
}

// Pattern represents a detected pattern in traffic
type Pattern struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Regex       string    `json:"regex"`
	Matches     []string  `json:"matches"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int       `json:"occurrences"`
}

// TrafficStats holds statistical analysis of traffic
type TrafficStats struct {
	TotalRequests   int            `json:"total_requests"`
	UniqueEndpoints int            `json:"unique_endpoints"`
	AverageRespTime time.Duration  `json:"average_response_time"`
	ErrorRate       float64        `json:"error_rate"`
	MethodDistrib   map[string]int `json:"method_distribution"`
	StatusDistrib   map[int]int    `json:"status_distribution"`
	ContentTypes    map[string]int `json:"content_types"`
	UserAgents      map[string]int `json:"user_agents"`
	RequestSizes    []int64        `json:"request_sizes"`
	ResponseSizes   []int64        `json:"response_sizes"`
}

// Anomaly represents detected anomalous behavior
type Anomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Evidence    string    `json:"evidence"`
	FirstSeen   time.Time `json:"first_seen"`
	Occurrences int       `json:"occurrences"`
	Score       float64   `json:"score"` // anomaly score 0.0-1.0
}

// DisplayStats holds statistics for real-time display
type DisplayStats struct {
	PacketsProcessed   int       `json:"packets_processed"`
	ConversationsFound int       `json:"conversations_found"`
	TokensDiscovered   int       `json:"tokens_discovered"`
	EndpointsFound     int       `json:"endpoints_found"`
	SecurityFindings   int       `json:"security_findings"`
	LastUpdate         time.Time `json:"last_update"`
}

// TokenDetector specializes in finding authentication tokens in traffic
type TokenDetector struct {
	config *config.SnifferConfig

	// Token patterns and recognition
	jwtPattern      *regexp.Regexp
	apiKeyPatterns  []*regexp.Regexp
	sessionPatterns []*regexp.Regexp
	bearerPattern   *regexp.Regexp

	// Detection state
	mu               sync.RWMutex
	discoveredTokens map[string]*DiscoveredToken
	tokenStats       map[string]int

	// Token validation
	jwtValidator   func(string) (*DiscoveredToken, error)
	tokenExtractor func([]byte, string) []string
}

// SignatureDetector specializes in finding cryptographic signatures
type SignatureDetector struct {
	config *config.SnifferConfig

	// Signature patterns
	hmacPattern    *regexp.Regexp
	rsaPattern     *regexp.Regexp
	ecdsaPattern   *regexp.Regexp
	customPatterns []*regexp.Regexp

	// Detection state
	mu                   sync.RWMutex
	discoveredSignatures map[string]*DiscoveredSignature
	signatureStats       map[string]int
	timingData           map[string][]time.Duration

	// Signature analysis
	hmacAnalyzer     func([]byte) (*DiscoveredSignature, error)
	timingAnalyzer   func(string, []time.Duration) bool
	weaknessDetector func(string, string) bool
}

// EndpointDetector specializes in discovering API endpoints and their characteristics
type EndpointDetector struct {
	config *config.SnifferConfig

	// Endpoint discovery
	pathExtractor  func(string) string
	paramExtractor func([]byte) []Parameter
	methodAnalyzer func(string) []string
	statusAnalyzer func([]int) string

	// Detection state
	mu                  sync.RWMutex
	discoveredEndpoints map[string]*DiscoveredEndpoint
	endpointStats       map[string]*EndpointStats
	pathFrequency       map[string]int

	// Security analysis
	authDetector     func(*HTTPRequest, *HTTPResponse) bool
	csrfDetector     func(*HTTPRequest, *HTTPResponse) bool
	injectionScanner func([]Parameter) []Parameter
}

// SensitiveDataDetector specializes in finding sensitive information leaks
type SensitiveDataDetector struct {
	config *config.SnifferConfig

	// Sensitive data patterns
	creditCardPattern *regexp.Regexp
	ssnPattern        *regexp.Regexp
	emailPattern      *regexp.Regexp
	passwordPattern   *regexp.Regexp
	privateKeyPattern *regexp.Regexp
	tokenLeakPattern  *regexp.Regexp

	// Custom patterns
	customPatterns   map[string]*regexp.Regexp
	contextAnalyzer  func(string, string) string
	severityAnalyzer func(string, string) string

	// Detection state
	mu              sync.RWMutex
	discoveredLeaks map[string]*SensitiveDataLeak
	leakStats       map[string]int
	falsePositives  map[string]bool

	// Privacy protection
	dataMasker       func(string, string) string
	contextExtractor func([]byte, int) string
}

// EndpointStats holds statistical data about discovered endpoints
type EndpointStats struct {
	RequestCount   int             `json:"request_count"`
	ResponseTimes  []time.Duration `json:"response_times"`
	StatusCodes    map[int]int     `json:"status_codes"`
	ErrorRate      float64         `json:"error_rate"`
	LastAccessed   time.Time       `json:"last_accessed"`
	ParameterCount int             `json:"parameter_count"`
	AuthRequired   bool            `json:"auth_required"`
	CSRFProtected  bool            `json:"csrf_protected"`
}

// NewTokenDetector creates a new token detector with default patterns
func NewTokenDetector(config *config.SnifferConfig) *TokenDetector {
	detector := &TokenDetector{
		config:           config,
		discoveredTokens: make(map[string]*DiscoveredToken),
		tokenStats:       make(map[string]int),
	}

	// Initialize regex patterns
	detector.jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*`)
	detector.bearerPattern = regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9+/=]+)`)

	// Initialize API key patterns
	detector.apiKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[Aa]pi[_-]?[Kk]ey[:\s=]+"?([A-Za-z0-9+/=]{20,})"?`),
		regexp.MustCompile(`[Aa]ccess[_-]?[Tt]oken[:\s=]+"?([A-Za-z0-9+/=]{20,})"?`),
		regexp.MustCompile(`[Aa]uth[_-]?[Tt]oken[:\s=]+"?([A-Za-z0-9+/=]{20,})"?`),
	}

	// Initialize session patterns
	detector.sessionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[Ss]ession[_-]?[Ii]d[:\s=]+"?([A-Za-z0-9+/=]{16,})"?`),
		regexp.MustCompile(`JSESSIONID=([A-Za-z0-9+/=]+)`),
		regexp.MustCompile(`PHPSESSID=([A-Za-z0-9+/=]+)`),
	}

	return detector
}

// NewSignatureDetector creates a new signature detector
func NewSignatureDetector(config *config.SnifferConfig) *SignatureDetector {
	detector := &SignatureDetector{
		config:               config,
		discoveredSignatures: make(map[string]*DiscoveredSignature),
		signatureStats:       make(map[string]int),
		timingData:           make(map[string][]time.Duration),
	}

	// Initialize patterns
	detector.hmacPattern = regexp.MustCompile(`(?i)x-signature[:\s]+"?([A-Za-z0-9+/=]+)"?`)
	detector.rsaPattern = regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`)
	detector.ecdsaPattern = regexp.MustCompile(`-----BEGIN\s+EC\s+PRIVATE\s+KEY-----`)

	return detector
}

// NewEndpointDetector creates a new endpoint detector
func NewEndpointDetector(config *config.SnifferConfig) *EndpointDetector {
	detector := &EndpointDetector{
		config:              config,
		discoveredEndpoints: make(map[string]*DiscoveredEndpoint),
		endpointStats:       make(map[string]*EndpointStats),
		pathFrequency:       make(map[string]int),
	}

	return detector
}

// NewSensitiveDataDetector creates a new sensitive data detector
func NewSensitiveDataDetector(config *config.SnifferConfig) *SensitiveDataDetector {
	detector := &SensitiveDataDetector{
		config:          config,
		discoveredLeaks: make(map[string]*SensitiveDataLeak),
		leakStats:       make(map[string]int),
		falsePositives:  make(map[string]bool),
		customPatterns:  make(map[string]*regexp.Regexp),
	}

	// Initialize sensitive data patterns
	detector.creditCardPattern = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)
	detector.ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	detector.emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	detector.passwordPattern = regexp.MustCompile(`(?i)password[:\s=]+"?([^"\s]{8,})"?`)
	detector.privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`)
	detector.tokenLeakPattern = regexp.MustCompile(`(?i)(?:token|key|secret)[:\s=]+"?([A-Za-z0-9+/=]{20,})"?`)

	return detector
}

// ToJSON converts SnifferResult to JSON format
func (sr *SnifferResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(sr, "", "  ")
}
