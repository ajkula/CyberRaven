// Package sniffer implements network traffic sniffing and analysis for CyberRaven
// File: pkg/sniffer/analyzer.go
package sniffer

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// Analyzer performs intelligent analysis of HTTP conversations
type Analyzer struct {
	config *config.SnifferConfig

	// Analysis engines
	patternAnalyzer   *PatternAnalyzer
	fingerprinter     *TechnologyFingerprinter
	statisticalEngine *StatisticalEngine
	anomalyDetector   *AnomalyDetector

	// Accumulated data
	mu              sync.RWMutex
	conversations   []*HTTPConversation
	analysisResults *AnalysisResults

	// Analysis state
	lastAnalysisTime time.Time
	analysisInterval time.Duration

	// Callbacks
	analysisCallback func(*AnalysisResults)
	anomalyCallback  func(*Anomaly)
}

// PatternAnalyzer detects patterns in HTTP traffic
type PatternAnalyzer struct {
	// Pattern definitions
	patterns   map[string]*Pattern
	regexCache map[string]*regexp.Regexp
	mu         sync.RWMutex

	// Analysis state
	patternMatches      map[string][]PatternMatch
	confidenceThreshold float64
}

// PatternMatch represents a specific pattern match
type PatternMatch struct {
	Pattern    *Pattern
	Location   string  // header, body, url, etc.
	Value      string  // matched value
	Context    string  // surrounding context
	Confidence float64 // match confidence 0.0-1.0
	Timestamp  time.Time
	LastSeen   time.Time
	ConvID     string // conversation ID
}

// TechnologyFingerprinter identifies technologies and frameworks
type TechnologyFingerprinter struct {
	// Technology signatures
	webServers map[string]*TechSignature
	frameworks map[string]*TechSignature
	languages  map[string]*TechSignature
	databases  map[string]*TechSignature
	security   map[string]*TechSignature

	// Analysis results
	mu               sync.RWMutex
	detectedTech     map[string]*TechDetection
	confidenceScores map[string]float64
}

// TechSignature defines how to detect a specific technology
type TechSignature struct {
	Name       string
	Category   string         // web_server, framework, language, database, security
	Patterns   []string       // regex patterns to match
	Headers    []string       // specific headers to look for
	Cookies    []string       // cookie patterns
	Content    []string       // content patterns
	Confidence float64        // base confidence score
	Version    *regexp.Regexp // version extraction regex
}

// TechDetection represents a detected technology
type TechDetection struct {
	Technology  *TechSignature
	Version     string
	Confidence  float64
	Evidence    []string
	FirstSeen   time.Time
	LastSeen    time.Time
	Occurrences int
}

// StatisticalEngine performs statistical analysis of traffic patterns
type StatisticalEngine struct {
	// Traffic statistics
	mu             sync.RWMutex
	stats          *TrafficStats
	timeSeriesData map[string][]TimePoint

	// Analysis windows
	shortWindow  time.Duration // 1 minute
	mediumWindow time.Duration // 5 minutes
	longWindow   time.Duration // 15 minutes

	// Thresholds
	anomalyThreshold float64
}

// TimePoint represents a data point in time series
type TimePoint struct {
	Timestamp time.Time
	Value     float64
	Metadata  map[string]interface{}
}

// AnomalyDetector identifies unusual patterns in traffic
type AnomalyDetector struct {
	// Detection algorithms
	mu        sync.RWMutex
	baseline  *TrafficBaseline
	anomalies []*Anomaly

	// Detection parameters
	sensitivityLevel float64
	learningPeriod   time.Duration
	minObservations  int

	// Algorithm state
	movingAverages  map[string]float64
	standardDevs    map[string]float64
	zScoreThreshold float64
}

// TrafficBaseline represents normal traffic patterns
type TrafficBaseline struct {
	RequestRate        float64
	ResponseTime       time.Duration
	ErrorRate          float64
	MethodDistrib      map[string]float64
	StatusDistrib      map[int]float64
	UserAgentDistrib   map[string]float64
	EndpointPopularity map[string]float64
	RequestSizes       []int64
	ResponseSizes      []int64
	UpdatedAt          time.Time
}

// NewAnalyzer creates a new traffic analyzer
func NewAnalyzer(config *config.SnifferConfig) *Analyzer {
	analyzer := &Analyzer{
		config:           config,
		conversations:    make([]*HTTPConversation, 0),
		analysisInterval: 30 * time.Second, // Analyze every 30 seconds
		analysisResults: &AnalysisResults{
			Patterns:     make([]Pattern, 0),
			Technologies: TechnologyProfile{},
			Statistics:   TrafficStats{},
			Anomalies:    make([]*Anomaly, 0),
		},
	}

	// Initialize analysis engines
	analyzer.patternAnalyzer = NewPatternAnalyzer()
	analyzer.fingerprinter = NewTechnologyFingerprinter()
	analyzer.statisticalEngine = NewStatisticalEngine()
	analyzer.anomalyDetector = NewAnomalyDetector()

	return analyzer
}

// ProcessConversation processes a new HTTP conversation
func (a *Analyzer) ProcessConversation(conversation *HTTPConversation) {
	if conversation == nil {
		return
	}

	// Store conversation
	a.mu.Lock()
	a.conversations = append(a.conversations, conversation)
	a.mu.Unlock()

	// Perform real-time analysis
	go a.analyzeConversationRealTime(conversation)

	// Trigger batch analysis if enough time has passed
	if time.Since(a.lastAnalysisTime) >= a.analysisInterval {
		go a.performBatchAnalysis()
	}
}

// analyzeConversationRealTime performs immediate analysis on new conversation
func (a *Analyzer) analyzeConversationRealTime(conv *HTTPConversation) {
	// Pattern analysis
	patterns := a.patternAnalyzer.AnalyzeConversation(conv)

	// Technology fingerprinting
	techDetections := a.fingerprinter.AnalyzeConversation(conv)

	// Update statistical data
	a.statisticalEngine.UpdateStats(conv)

	// Anomaly detection
	anomalies := a.anomalyDetector.CheckConversation(conv)

	// Process results
	a.processRealTimeResults(patterns, techDetections, anomalies)
}

// processRealTimeResults handles real-time analysis results
func (a *Analyzer) processRealTimeResults(patterns []PatternMatch, tech []*TechDetection, anomalies []*Anomaly) {
	// Call callbacks for immediate notifications
	for _, anomaly := range anomalies {
		if a.anomalyCallback != nil {
			a.anomalyCallback(anomaly)
		}
	}

	// Update accumulated results
	a.mu.Lock()
	defer a.mu.Unlock()

	// Merge patterns
	for _, match := range patterns {
		a.mergePattern(match)
	}

	// Merge technology detections
	for _, detection := range tech {
		a.mergeTechnology(detection)
	}

	// Add anomalies
	a.analysisResults.Anomalies = append(a.analysisResults.Anomalies, anomalies...)
}

// performBatchAnalysis performs comprehensive analysis on accumulated data
func (a *Analyzer) performBatchAnalysis() {
	a.mu.Lock()
	conversations := make([]*HTTPConversation, len(a.conversations))
	copy(conversations, a.conversations)
	a.lastAnalysisTime = time.Now()
	a.mu.Unlock()

	if len(conversations) == 0 {
		return
	}

	// Comprehensive statistical analysis
	stats := a.statisticalEngine.ComputeComprehensiveStats(conversations)

	// Technology profiling
	techProfile := a.fingerprinter.BuildTechnologyProfile(conversations)

	// Pattern correlation analysis
	correlatedPatterns := a.patternAnalyzer.AnalyzePatternCorrelations(conversations)

	// Anomaly baseline update
	a.anomalyDetector.UpdateBaseline(conversations)

	// Update results
	a.mu.Lock()
	a.analysisResults.Statistics = *stats
	a.analysisResults.Technologies = *techProfile
	a.analysisResults.Patterns = correlatedPatterns
	a.mu.Unlock()

	// Trigger callback
	if a.analysisCallback != nil {
		a.analysisCallback(a.analysisResults)
	}
}

// Pattern Analyzer Implementation

// NewPatternAnalyzer creates a new pattern analyzer
func NewPatternAnalyzer() *PatternAnalyzer {
	pa := &PatternAnalyzer{
		patterns:            make(map[string]*Pattern),
		regexCache:          make(map[string]*regexp.Regexp),
		patternMatches:      make(map[string][]PatternMatch),
		confidenceThreshold: 0.7,
	}

	// Initialize common patterns
	pa.initializePatterns()

	return pa
}

// initializePatterns sets up common security and application patterns
func (pa *PatternAnalyzer) initializePatterns() {
	// JWT patterns
	pa.addPattern("jwt_token", `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`, "JWT token detected")

	// API key patterns
	pa.addPattern("api_key", `[Aa][Pp][Ii]_?[Kk][Ee][Yy]\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`, "API key detected")

	// Session tokens
	pa.addPattern("session_token", `[Ss][Ee][Ss][Ss][Ii][Oo][Nn]\s*[:=]\s*['"]?([A-Za-z0-9_\-]{16,})['"]?`, "Session token detected")

	// Database connection strings
	pa.addPattern("db_connection", `(mysql|postgres|mongodb|redis)://[^\s'"]+`, "Database connection string detected")

	// Email addresses
	pa.addPattern("email", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, "Email address detected")

	// IP addresses
	pa.addPattern("ip_address", `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, "IP address detected")

	// HMAC signatures
	pa.addPattern("hmac_signature", `[Hh][Mm][Aa][Cc]\s*[:=]\s*['"]?([A-Fa-f0-9]{32,})['"]?`, "HMAC signature detected")

	// Error messages
	pa.addPattern("error_stack_trace", `(?i)(exception|error|stack\s+trace|traceback).*?at\s+.*?\(.*?:\d+\)`, "Stack trace detected")

	// SQL injection patterns
	pa.addPattern("sql_injection", `(?i)(union\s+select|order\s+by|\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1)`, "Potential SQL injection detected")

	// XSS patterns
	pa.addPattern("xss_payload", `(?i)(<script|javascript:|on\w+\s*=)`, "Potential XSS payload detected")
}

// addPattern adds a new pattern to the analyzer
func (pa *PatternAnalyzer) addPattern(name, regex, description string) {
	pattern := &Pattern{
		Type:        name,
		Description: description,
		Regex:       regex,
		Matches:     make([]string, 0),
		Confidence:  0.8,
		FirstSeen:   time.Now(),
		Occurrences: 0,
	}

	pa.mu.Lock()
	pa.patterns[name] = pattern

	// Compile and cache regex
	if compiled, err := regexp.Compile(regex); err == nil {
		pa.regexCache[name] = compiled
	}
	pa.mu.Unlock()
}

// AnalyzeConversation analyzes a conversation for patterns
func (pa *PatternAnalyzer) AnalyzeConversation(conv *HTTPConversation) []PatternMatch {
	matches := make([]PatternMatch, 0)

	pa.mu.RLock()
	defer pa.mu.RUnlock()

	// Analyze request
	if conv.Request != nil {
		matches = append(matches, pa.analyzeRequest(conv)...)
	}

	// Analyze response
	if conv.Response != nil {
		matches = append(matches, pa.analyzeResponse(conv)...)
	}

	return matches
}

// analyzeRequest analyzes HTTP request for patterns
func (pa *PatternAnalyzer) analyzeRequest(conv *HTTPConversation) []PatternMatch {
	matches := make([]PatternMatch, 0)
	req := conv.Request

	// Analyze URL
	matches = append(matches, pa.matchPatterns(req.URL, "url", conv.ID)...)

	// Analyze headers
	for name, value := range req.Headers {
		matches = append(matches, pa.matchPatterns(value, fmt.Sprintf("request_header_%s", name), conv.ID)...)
	}

	// Analyze body
	if req.Body != "" {
		matches = append(matches, pa.matchPatterns(req.Body, "request_body", conv.ID)...)
	}

	// Analyze cookies
	for name, value := range req.Cookies {
		matches = append(matches, pa.matchPatterns(value, fmt.Sprintf("request_cookie_%s", name), conv.ID)...)
	}

	return matches
}

// analyzeResponse analyzes HTTP response for patterns
func (pa *PatternAnalyzer) analyzeResponse(conv *HTTPConversation) []PatternMatch {
	matches := make([]PatternMatch, 0)
	resp := conv.Response

	// Analyze headers
	for name, value := range resp.Headers {
		matches = append(matches, pa.matchPatterns(value, fmt.Sprintf("response_header_%s", name), conv.ID)...)
	}

	// Analyze body
	if resp.Body != "" {
		matches = append(matches, pa.matchPatterns(resp.Body, "response_body", conv.ID)...)
	}

	// Analyze cookies
	for name, value := range resp.Cookies {
		matches = append(matches, pa.matchPatterns(value, fmt.Sprintf("response_cookie_%s", name), conv.ID)...)
	}

	return matches
}

// matchPatterns matches all patterns against a given text
func (pa *PatternAnalyzer) matchPatterns(text, location, convID string) []PatternMatch {
	matches := make([]PatternMatch, 0)

	for patternName, compiled := range pa.regexCache {
		pattern := pa.patterns[patternName]

		if results := compiled.FindAllString(text, -1); len(results) > 0 {
			for _, match := range results {
				patternMatch := PatternMatch{
					Pattern:    pattern,
					Location:   location,
					Value:      match,
					Context:    pa.extractContext(text, match),
					Confidence: pattern.Confidence,
					Timestamp:  time.Now(),
					ConvID:     convID,
				}

				matches = append(matches, patternMatch)

				// Update pattern statistics
				pattern.Matches = append(pattern.Matches, match)
				pattern.Occurrences++
				pattern.LastSeen = time.Now()
			}
		}
	}

	return matches
}

// extractContext extracts surrounding context for a match
func (pa *PatternAnalyzer) extractContext(text, match string) string {
	index := strings.Index(text, match)
	if index == -1 {
		return ""
	}

	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(match) + 50
	if end > len(text) {
		end = len(text)
	}

	return text[start:end]
}

// AnalyzePatternCorrelations finds correlations between patterns
func (pa *PatternAnalyzer) AnalyzePatternCorrelations(conversations []*HTTPConversation) []Pattern {
	correlations := make(map[string]*Pattern)

	// Analyze co-occurrence of patterns
	for _, conv := range conversations {
		convPatterns := pa.AnalyzeConversation(conv)

		// Group patterns by conversation
		patternTypes := make(map[string]bool)
		for _, match := range convPatterns {
			patternTypes[match.Pattern.Type] = true
		}

		// Update correlation scores
		patterns := make([]string, 0, len(patternTypes))
		for patternType := range patternTypes {
			patterns = append(patterns, patternType)
		}

		// Calculate correlations
		for i, p1 := range patterns {
			for j, p2 := range patterns {
				if i != j {
					key := fmt.Sprintf("%s_correlates_%s", p1, p2)
					if _, exists := correlations[key]; !exists {
						correlations[key] = &Pattern{
							Type:        fmt.Sprintf("correlation_%s_%s", p1, p2),
							Description: fmt.Sprintf("Correlation between %s and %s", p1, p2),
							Confidence:  0.5,
							FirstSeen:   time.Now(),
							Occurrences: 0,
						}
					}
					correlations[key].Occurrences++
				}
			}
		}
	}

	// Convert to slice and filter by confidence
	result := make([]Pattern, 0)
	for _, pattern := range correlations {
		if pattern.Occurrences >= 3 { // At least 3 occurrences
			pattern.Confidence = math.Min(1.0, float64(pattern.Occurrences)/10.0)
			result = append(result, *pattern)
		}
	}

	return result
}

// Technology Fingerprinter Implementation

// NewTechnologyFingerprinter creates a new technology fingerprinter
func NewTechnologyFingerprinter() *TechnologyFingerprinter {
	tf := &TechnologyFingerprinter{
		webServers:       make(map[string]*TechSignature),
		frameworks:       make(map[string]*TechSignature),
		languages:        make(map[string]*TechSignature),
		databases:        make(map[string]*TechSignature),
		security:         make(map[string]*TechSignature),
		detectedTech:     make(map[string]*TechDetection),
		confidenceScores: make(map[string]float64),
	}

	// Initialize technology signatures
	tf.initializeSignatures()

	return tf
}

// initializeSignatures sets up technology detection signatures
func (tf *TechnologyFingerprinter) initializeSignatures() {
	// Web servers
	tf.addWebServerSignature("nginx", []string{`nginx/(\d+\.\d+)`}, []string{"Server"}, 0.9)
	tf.addWebServerSignature("apache", []string{`Apache/(\d+\.\d+)`}, []string{"Server"}, 0.9)
	tf.addWebServerSignature("iis", []string{`Microsoft-IIS/(\d+\.\d+)`}, []string{"Server"}, 0.9)
	tf.addWebServerSignature("cloudflare", []string{`cloudflare`}, []string{"Server", "CF-RAY"}, 0.8)

	// Frameworks
	tf.addFrameworkSignature("express", []string{`X-Powered-By.*Express`}, []string{"X-Powered-By"}, 0.8)
	tf.addFrameworkSignature("django", []string{`csrftoken`, `django`}, []string{"Set-Cookie", "Server"}, 0.7)
	tf.addFrameworkSignature("rails", []string{`Ruby on Rails`, `_session`}, []string{"X-Powered-By", "Set-Cookie"}, 0.7)
	tf.addFrameworkSignature("spring", []string{`JSESSIONID`, `Spring`}, []string{"Set-Cookie", "Server"}, 0.7)

	// Languages
	tf.addLanguageSignature("php", []string{`PHPSESSID`, `PHP/(\d+\.\d+)`}, []string{"Set-Cookie", "X-Powered-By"}, 0.8)
	tf.addLanguageSignature("nodejs", []string{`Node\.js`, `connect\.sid`}, []string{"X-Powered-By", "Set-Cookie"}, 0.8)
	tf.addLanguageSignature("python", []string{`Python/(\d+\.\d+)`, `Django`, `Flask`}, []string{"Server", "X-Powered-By"}, 0.7)
	tf.addLanguageSignature("java", []string{`Java/(\d+\.\d+)`, `JSESSIONID`}, []string{"Server", "Set-Cookie"}, 0.7)

	// Security technologies
	tf.addSecuritySignature("waf", []string{`X-WAF`, `cloudflare`, `incapsula`}, []string{"X-WAF-Event", "CF-RAY"}, 0.8)
	tf.addSecuritySignature("load_balancer", []string{`X-LB`, `X-Forwarded`}, []string{"X-LB-ID", "X-Forwarded-For"}, 0.6)
}

// Helper methods for adding signatures
func (tf *TechnologyFingerprinter) addWebServerSignature(name string, patterns []string, headers []string, confidence float64) {
	tf.webServers[name] = &TechSignature{
		Name:       name,
		Category:   "web_server",
		Patterns:   patterns,
		Headers:    headers,
		Confidence: confidence,
	}
}

func (tf *TechnologyFingerprinter) addFrameworkSignature(name string, patterns []string, headers []string, confidence float64) {
	tf.frameworks[name] = &TechSignature{
		Name:       name,
		Category:   "framework",
		Patterns:   patterns,
		Headers:    headers,
		Confidence: confidence,
	}
}

func (tf *TechnologyFingerprinter) addLanguageSignature(name string, patterns []string, headers []string, confidence float64) {
	tf.languages[name] = &TechSignature{
		Name:       name,
		Category:   "language",
		Patterns:   patterns,
		Headers:    headers,
		Confidence: confidence,
	}
}

func (tf *TechnologyFingerprinter) addSecuritySignature(name string, patterns []string, headers []string, confidence float64) {
	tf.security[name] = &TechSignature{
		Name:       name,
		Category:   "security",
		Patterns:   patterns,
		Headers:    headers,
		Confidence: confidence,
	}
}

// AnalyzeConversation analyzes a conversation for technology fingerprints
func (tf *TechnologyFingerprinter) AnalyzeConversation(conv *HTTPConversation) []*TechDetection {
	detections := make([]*TechDetection, 0)

	// Analyze all signature categories
	detections = append(detections, tf.analyzeSignatures(conv, tf.webServers)...)
	detections = append(detections, tf.analyzeSignatures(conv, tf.frameworks)...)
	detections = append(detections, tf.analyzeSignatures(conv, tf.languages)...)
	detections = append(detections, tf.analyzeSignatures(conv, tf.security)...)

	return detections
}

// analyzeSignatures checks conversation against a set of signatures
func (tf *TechnologyFingerprinter) analyzeSignatures(conv *HTTPConversation, signatures map[string]*TechSignature) []*TechDetection {
	detections := make([]*TechDetection, 0)

	for _, signature := range signatures {
		if detection := tf.checkSignature(conv, signature); detection != nil {
			detections = append(detections, detection)
		}
	}

	return detections
}

// checkSignature checks if a conversation matches a specific technology signature
func (tf *TechnologyFingerprinter) checkSignature(conv *HTTPConversation, signature *TechSignature) *TechDetection {
	evidence := make([]string, 0)
	confidence := 0.0
	version := ""

	// Check response headers
	if conv.Response != nil {
		for _, headerName := range signature.Headers {
			if headerValue, exists := conv.Response.Headers[headerName]; exists {
				// Check patterns in header value
				for _, pattern := range signature.Patterns {
					if matched, _ := regexp.MatchString(pattern, headerValue); matched {
						evidence = append(evidence, fmt.Sprintf("Header %s: %s", headerName, headerValue))
						confidence += signature.Confidence

						// Extract version if pattern has capture group
						if versionRegex, err := regexp.Compile(pattern); err == nil {
							if matches := versionRegex.FindStringSubmatch(headerValue); len(matches) > 1 {
								version = matches[1]
							}
						}
					}
				}
			}
		}
	}

	// Check request/response content
	if conv.Request != nil {
		for _, pattern := range signature.Patterns {
			if matched, _ := regexp.MatchString(pattern, conv.Request.Body); matched {
				evidence = append(evidence, fmt.Sprintf("Request body contains pattern: %s", pattern))
				confidence += signature.Confidence * 0.5 // Lower confidence for body matches
			}
		}
	}

	if conv.Response != nil {
		for _, pattern := range signature.Patterns {
			if matched, _ := regexp.MatchString(pattern, conv.Response.Body); matched {
				evidence = append(evidence, fmt.Sprintf("Response body contains pattern: %s", pattern))
				confidence += signature.Confidence * 0.5
			}
		}
	}

	// Check cookies
	if conv.Response != nil {
		for cookieName := range conv.Response.Cookies {
			for _, pattern := range signature.Patterns {
				if matched, _ := regexp.MatchString(pattern, cookieName); matched {
					evidence = append(evidence, fmt.Sprintf("Cookie: %s", cookieName))
					confidence += signature.Confidence * 0.7
				}
			}
		}
	}

	// Return detection if we have evidence
	if len(evidence) > 0 && confidence > 0.3 {
		return &TechDetection{
			Technology:  signature,
			Version:     version,
			Confidence:  math.Min(confidence, 1.0),
			Evidence:    evidence,
			FirstSeen:   conv.StartTime,
			LastSeen:    conv.EndTime,
			Occurrences: 1,
		}
	}

	return nil
}

// BuildTechnologyProfile builds a comprehensive technology profile
func (tf *TechnologyFingerprinter) BuildTechnologyProfile(conversations []*HTTPConversation) *TechnologyProfile {
	profile := &TechnologyProfile{
		Frontend:         make([]string, 0),
		JavaScriptLibs:   make([]string, 0),
		Versions:         make(map[string]string),
		ServerHeaders:    make(map[string]string),
		SecurityHeaders:  make(map[string]string),
		CookieAttributes: make(map[string]string),
	}

	// Aggregate detections from all conversations
	techCounts := make(map[string]*TechDetection)

	for _, conv := range conversations {
		detections := tf.AnalyzeConversation(conv)

		for _, detection := range detections {
			key := detection.Technology.Name
			if existing, exists := techCounts[key]; exists {
				existing.Occurrences++
				existing.Confidence = math.Max(existing.Confidence, detection.Confidence)
				existing.LastSeen = detection.LastSeen
				if detection.Version != "" {
					existing.Version = detection.Version
				}
			} else {
				techCounts[key] = detection
			}
		}

		// Extract additional metadata
		if conv.Response != nil {
			// Server headers
			if server := conv.Response.Headers["Server"]; server != "" {
				profile.ServerHeaders["Server"] = server
			}

			// Security headers
			securityHeaders := []string{"X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Strict-Transport-Security"}
			for _, header := range securityHeaders {
				if value := conv.Response.Headers[header]; value != "" {
					profile.SecurityHeaders[header] = value
				}
			}
		}
	}

	// Build final profile
	for _, detection := range techCounts {
		if detection.Occurrences >= 2 && detection.Confidence > 0.5 { // Filter by confidence and occurrence
			switch detection.Technology.Category {
			case "web_server":
				profile.WebServer = detection.Technology.Name
			case "framework":
				profile.Framework = detection.Technology.Name
			case "language":
				profile.Language = detection.Technology.Name
			case "security":
				if detection.Technology.Name == "waf" {
					profile.WAF = detection.Technology.Name
				} else if detection.Technology.Name == "load_balancer" {
					profile.LoadBalancer = detection.Technology.Name
				}
			}

			if detection.Version != "" {
				profile.Versions[detection.Technology.Name] = detection.Version
			}
		}
	}

	return profile
}

// Statistical Engine Implementation

// NewStatisticalEngine creates a new statistical analysis engine
func NewStatisticalEngine() *StatisticalEngine {
	return &StatisticalEngine{
		stats:            &TrafficStats{},
		timeSeriesData:   make(map[string][]TimePoint),
		shortWindow:      1 * time.Minute,
		mediumWindow:     5 * time.Minute,
		longWindow:       15 * time.Minute,
		anomalyThreshold: 2.0, // 2 standard deviations
	}
}

// UpdateStats updates statistics with a new conversation
func (se *StatisticalEngine) UpdateStats(conv *HTTPConversation) {
	se.mu.Lock()
	defer se.mu.Unlock()

	se.stats.TotalRequests++
	se.stats.AverageRespTime = (se.stats.AverageRespTime + conv.Duration) / 2

	// Update method distribution
	if se.stats.MethodDistrib == nil {
		se.stats.MethodDistrib = make(map[string]int)
	}
	se.stats.MethodDistrib[conv.Request.Method]++

	// Update status distribution
	if se.stats.StatusDistrib == nil {
		se.stats.StatusDistrib = make(map[int]int)
	}
	se.stats.StatusDistrib[conv.Response.StatusCode]++

	// Update error rate
	if conv.Response.StatusCode >= 400 {
		se.stats.ErrorRate = float64(se.stats.ErrorRate*float64(se.stats.TotalRequests-1)+1) / float64(se.stats.TotalRequests)
	} else {
		se.stats.ErrorRate = float64(se.stats.ErrorRate*float64(se.stats.TotalRequests-1)) / float64(se.stats.TotalRequests)
	}

	// Update content types
	if se.stats.ContentTypes == nil {
		se.stats.ContentTypes = make(map[string]int)
	}
	if conv.Response.ContentType != "" {
		se.stats.ContentTypes[conv.Response.ContentType]++
	}

	// Update user agents
	if se.stats.UserAgents == nil {
		se.stats.UserAgents = make(map[string]int)
	}
	if conv.Request.UserAgent != "" {
		se.stats.UserAgents[conv.Request.UserAgent]++
	}

	// Update size distributions
	se.stats.RequestSizes = append(se.stats.RequestSizes, conv.Request.ContentLength)
	se.stats.ResponseSizes = append(se.stats.ResponseSizes, conv.Response.ContentLength)

	// Limit size arrays to prevent memory issues
	if len(se.stats.RequestSizes) > 1000 {
		se.stats.RequestSizes = se.stats.RequestSizes[len(se.stats.RequestSizes)-1000:]
	}
	if len(se.stats.ResponseSizes) > 1000 {
		se.stats.ResponseSizes = se.stats.ResponseSizes[len(se.stats.ResponseSizes)-1000:]
	}
}

// ComputeComprehensiveStats computes comprehensive statistics
func (se *StatisticalEngine) ComputeComprehensiveStats(conversations []*HTTPConversation) *TrafficStats {
	se.mu.Lock()
	defer se.mu.Unlock()

	// Reset stats
	stats := &TrafficStats{
		MethodDistrib: make(map[string]int),
		StatusDistrib: make(map[int]int),
		ContentTypes:  make(map[string]int),
		UserAgents:    make(map[string]int),
		RequestSizes:  make([]int64, 0),
		ResponseSizes: make([]int64, 0),
	}

	endpoints := make(map[string]bool)
	var totalResponseTime time.Duration
	errorCount := 0

	for _, conv := range conversations {
		stats.TotalRequests++

		// Unique endpoints
		endpoints[conv.Request.Path] = true

		// Response time
		totalResponseTime += conv.Duration

		// Error rate
		if conv.Response.StatusCode >= 400 {
			errorCount++
		}

		// Method distribution
		stats.MethodDistrib[conv.Request.Method]++

		// Status distribution
		stats.StatusDistrib[conv.Response.StatusCode]++

		// Content types
		if conv.Response.ContentType != "" {
			stats.ContentTypes[conv.Response.ContentType]++
		}

		// User agents
		if conv.Request.UserAgent != "" {
			stats.UserAgents[conv.Request.UserAgent]++
		}

		// Sizes
		stats.RequestSizes = append(stats.RequestSizes, conv.Request.ContentLength)
		stats.ResponseSizes = append(stats.ResponseSizes, conv.Response.ContentLength)
	}

	// Calculate derived metrics
	stats.UniqueEndpoints = len(endpoints)
	if stats.TotalRequests > 0 {
		stats.AverageRespTime = totalResponseTime / time.Duration(stats.TotalRequests)
		stats.ErrorRate = float64(errorCount) / float64(stats.TotalRequests) * 100.0
	}

	return stats
}

// Anomaly Detector Implementation

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		baseline:         &TrafficBaseline{},
		anomalies:        make([]*Anomaly, 0),
		sensitivityLevel: 0.8,
		learningPeriod:   15 * time.Minute,
		minObservations:  10,
		movingAverages:   make(map[string]float64),
		standardDevs:     make(map[string]float64),
		zScoreThreshold:  2.0,
	}
}

// CheckConversation checks a conversation for anomalies
func (ad *AnomalyDetector) CheckConversation(conv *HTTPConversation) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	// Check response time anomaly
	if anomaly := ad.checkResponseTimeAnomaly(conv); anomaly != nil {
		anomalies = append(anomalies, anomaly)
	}

	// Check status code anomaly
	if anomaly := ad.checkStatusCodeAnomaly(conv); anomaly != nil {
		anomalies = append(anomalies, anomaly)
	}

	// Check request size anomaly
	if anomaly := ad.checkRequestSizeAnomaly(conv); anomaly != nil {
		anomalies = append(anomalies, anomaly)
	}

	// Check unusual user agent
	if anomaly := ad.checkUserAgentAnomaly(conv); anomaly != nil {
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

// checkResponseTimeAnomaly checks for unusual response times
func (ad *AnomalyDetector) checkResponseTimeAnomaly(conv *HTTPConversation) *Anomaly {
	responseTimeMs := float64(conv.Duration.Milliseconds())

	if ad.baseline.ResponseTime.Milliseconds() == 0 {
		return nil // No baseline yet
	}

	baselineMs := float64(ad.baseline.ResponseTime.Milliseconds())

	// Check if response time is significantly higher than baseline
	if responseTimeMs > baselineMs*3 && responseTimeMs > 1000 { // 3x baseline and > 1 second
		return &Anomaly{
			Type:        "slow_response",
			Description: fmt.Sprintf("Response time %.2fms significantly higher than baseline %.2fms", responseTimeMs, baselineMs),
			Severity:    "medium",
			Evidence:    fmt.Sprintf("Endpoint: %s, Response time: %v", conv.Request.Path, conv.Duration),
			FirstSeen:   conv.StartTime,
			Occurrences: 1,
			Score:       responseTimeMs / baselineMs / 3.0, // Normalized anomaly score
		}
	}

	return nil
}

// checkStatusCodeAnomaly checks for unusual status codes
func (ad *AnomalyDetector) checkStatusCodeAnomaly(conv *HTTPConversation) *Anomaly {
	statusCode := conv.Response.StatusCode

	// Check for server errors (5xx)
	if statusCode >= 500 {
		return &Anomaly{
			Type:        "server_error",
			Description: fmt.Sprintf("Server error status code: %d", statusCode),
			Severity:    "high",
			Evidence:    fmt.Sprintf("Endpoint: %s, Status: %d", conv.Request.Path, statusCode),
			FirstSeen:   conv.StartTime,
			Occurrences: 1,
			Score:       0.8,
		}
	}

	// Check for unusual 4xx patterns
	if statusCode == 403 || statusCode == 401 {
		return &Anomaly{
			Type:        "authentication_error",
			Description: fmt.Sprintf("Authentication/authorization error: %d", statusCode),
			Severity:    "medium",
			Evidence:    fmt.Sprintf("Endpoint: %s, Status: %d", conv.Request.Path, statusCode),
			FirstSeen:   conv.StartTime,
			Occurrences: 1,
			Score:       0.6,
		}
	}

	return nil
}

// checkRequestSizeAnomaly checks for unusually large requests
func (ad *AnomalyDetector) checkRequestSizeAnomaly(conv *HTTPConversation) *Anomaly {
	requestSize := conv.Request.ContentLength

	// Check for very large requests (> 10MB)
	if requestSize > 10*1024*1024 {
		return &Anomaly{
			Type:        "large_request",
			Description: fmt.Sprintf("Unusually large request: %d bytes", requestSize),
			Severity:    "medium",
			Evidence:    fmt.Sprintf("Endpoint: %s, Size: %d bytes", conv.Request.Path, requestSize),
			FirstSeen:   conv.StartTime,
			Occurrences: 1,
			Score:       float64(requestSize) / (10 * 1024 * 1024),
		}
	}

	return nil
}

// checkUserAgentAnomaly checks for suspicious user agents
func (ad *AnomalyDetector) checkUserAgentAnomaly(conv *HTTPConversation) *Anomaly {
	userAgent := conv.Request.UserAgent

	// Check for suspicious patterns
	suspiciousPatterns := []string{"sqlmap", "nikto", "nmap", "burp", "owasp", "scanner", "bot"}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(userAgent), pattern) {
			return &Anomaly{
				Type:        "suspicious_user_agent",
				Description: fmt.Sprintf("Suspicious user agent detected: %s", pattern),
				Severity:    "high",
				Evidence:    fmt.Sprintf("User-Agent: %s", userAgent),
				FirstSeen:   conv.StartTime,
				Occurrences: 1,
				Score:       0.9,
			}
		}
	}

	return nil
}

// UpdateBaseline updates the traffic baseline
func (ad *AnomalyDetector) UpdateBaseline(conversations []*HTTPConversation) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if len(conversations) < ad.minObservations {
		return
	}

	// Calculate new baseline metrics
	var totalResponseTime time.Duration
	errorCount := 0
	methodCounts := make(map[string]int)
	statusCounts := make(map[int]int)

	for _, conv := range conversations {
		totalResponseTime += conv.Duration

		if conv.Response.StatusCode >= 400 {
			errorCount++
		}

		methodCounts[conv.Request.Method]++
		statusCounts[conv.Response.StatusCode]++
	}

	// Update baseline
	ad.baseline.RequestRate = float64(len(conversations)) / ad.learningPeriod.Seconds()
	ad.baseline.ResponseTime = totalResponseTime / time.Duration(len(conversations))
	ad.baseline.ErrorRate = float64(errorCount) / float64(len(conversations)) * 100.0
	ad.baseline.UpdatedAt = time.Now()

	// Update distributions
	ad.baseline.MethodDistrib = make(map[string]float64)
	for method, count := range methodCounts {
		ad.baseline.MethodDistrib[method] = float64(count) / float64(len(conversations))
	}

	ad.baseline.StatusDistrib = make(map[int]float64)
	for status, count := range statusCounts {
		ad.baseline.StatusDistrib[status] = float64(count) / float64(len(conversations))
	}
}

// Public interface methods

// SetAnalysisCallback sets callback for analysis results
func (a *Analyzer) SetAnalysisCallback(callback func(*AnalysisResults)) {
	a.analysisCallback = callback
}

// SetAnomalyCallback sets callback for anomaly detection
func (a *Analyzer) SetAnomalyCallback(callback func(*Anomaly)) {
	a.anomalyCallback = callback
}

// GetResults returns current analysis results
func (a *Analyzer) GetResults() *AnalysisResults {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Return copy to prevent race conditions
	return &AnalysisResults{
		Patterns:     a.analysisResults.Patterns,
		Technologies: a.analysisResults.Technologies,
		Statistics:   a.analysisResults.Statistics,
		Anomalies:    a.analysisResults.Anomalies,
	}
}

// GetStats returns analyzer statistics
func (a *Analyzer) GetStats() (conversations int, patterns int, technologies int, anomalies int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return len(a.conversations),
		len(a.analysisResults.Patterns),
		len(a.fingerprinter.detectedTech),
		len(a.analysisResults.Anomalies)
}

// Helper methods

func (a *Analyzer) mergePattern(match PatternMatch) {
	// Implementation for merging patterns
	for i, pattern := range a.analysisResults.Patterns {
		if pattern.Type == match.Pattern.Type {
			a.analysisResults.Patterns[i].Occurrences++
			a.analysisResults.Patterns[i].LastSeen = match.Timestamp
			a.analysisResults.Patterns[i].Matches = append(a.analysisResults.Patterns[i].Matches, match.Value)
			return
		}
	}

	// New pattern
	newPattern := *match.Pattern
	newPattern.LastSeen = match.Timestamp
	a.analysisResults.Patterns = append(a.analysisResults.Patterns, newPattern)
}

func (a *Analyzer) mergeTechnology(detection *TechDetection) {
	a.fingerprinter.mu.Lock()
	defer a.fingerprinter.mu.Unlock()

	if existing, exists := a.fingerprinter.detectedTech[detection.Technology.Name]; exists {
		existing.Occurrences++
		existing.LastSeen = detection.LastSeen
		existing.Confidence = math.Max(existing.Confidence, detection.Confidence)
		if detection.Version != "" {
			existing.Version = detection.Version
		}
	} else {
		a.fingerprinter.detectedTech[detection.Technology.Name] = detection
	}
}

// AnalyzeConversation performs comprehensive analysis of an HTTP conversation
func (a *Analyzer) AnalyzeConversation(conversation *HTTPConversation) (*AnalysisResults, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Initialize maps if needed
	if a.analysisResults.Statistics.MethodDistrib == nil {
		a.analysisResults.Statistics.MethodDistrib = make(map[string]int)
	}
	if a.analysisResults.Statistics.StatusDistrib == nil {
		a.analysisResults.Statistics.StatusDistrib = make(map[int]int)
	}

	// Basic technology detection from headers - ACCUMULATION instead of overwriting
	if conversation.Response != nil && len(conversation.Response.Headers) > 0 {
		// Only set if not already detected (accumulate, don't overwrite)
		if server, exists := conversation.Response.Headers["server"]; exists && server != "" {
			if a.analysisResults.Technologies.WebServer == "" {
				a.analysisResults.Technologies.WebServer = server
			}
		}

		// Check alternative server header cases
		if server, exists := conversation.Response.Headers["Server"]; exists && server != "" {
			if a.analysisResults.Technologies.WebServer == "" {
				a.analysisResults.Technologies.WebServer = server
			}
		}

		// X-Powered-By header for framework detection
		if powered, exists := conversation.Response.Headers["x-powered-by"]; exists && powered != "" {
			if a.analysisResults.Technologies.Framework == "" {
				a.analysisResults.Technologies.Framework = powered
			}
		}

		if powered, exists := conversation.Response.Headers["X-Powered-By"]; exists && powered != "" {
			if a.analysisResults.Technologies.Framework == "" {
				a.analysisResults.Technologies.Framework = powered
			}
		}

		// Additional technology detection
		for headerName, headerValue := range conversation.Response.Headers {
			headerLower := strings.ToLower(headerName)

			// Framework detection from various headers
			if headerLower == "x-framework" && a.analysisResults.Technologies.Framework == "" {
				a.analysisResults.Technologies.Framework = headerValue
			}

			// Language detection
			if strings.Contains(headerLower, "php") && a.analysisResults.Technologies.Language == "" {
				a.analysisResults.Technologies.Language = "PHP"
			}
			if strings.Contains(headerLower, "python") && a.analysisResults.Technologies.Language == "" {
				a.analysisResults.Technologies.Language = "Python"
			}
			if strings.Contains(headerLower, "java") && a.analysisResults.Technologies.Language == "" {
				a.analysisResults.Technologies.Language = "Java"
			}
			if strings.Contains(headerLower, "node") && a.analysisResults.Technologies.Language == "" {
				a.analysisResults.Technologies.Language = "Node.js"
			}

			// WAF detection
			if strings.Contains(headerLower, "waf") || strings.Contains(headerLower, "cloudflare") {
				if a.analysisResults.Technologies.WAF == "" {
					a.analysisResults.Technologies.WAF = headerValue
				}
			}

			// CDN detection
			if strings.Contains(headerLower, "cdn") || strings.Contains(headerLower, "cloudfront") {
				if a.analysisResults.Technologies.CDN == "" {
					a.analysisResults.Technologies.CDN = headerValue
				}
			}
		}

		// Server technology inference from server header
		if a.analysisResults.Technologies.WebServer != "" {
			serverLower := strings.ToLower(a.analysisResults.Technologies.WebServer)

			// Infer language from web server
			if strings.Contains(serverLower, "gunicorn") || strings.Contains(serverLower, "uwsgi") {
				if a.analysisResults.Technologies.Language == "" {
					a.analysisResults.Technologies.Language = "Python"
				}
			}
			if strings.Contains(serverLower, "apache") && strings.Contains(serverLower, "php") {
				if a.analysisResults.Technologies.Language == "" {
					a.analysisResults.Technologies.Language = "PHP"
				}
			}
			if strings.Contains(serverLower, "iis") {
				if a.analysisResults.Technologies.Language == "" {
					a.analysisResults.Technologies.Language = ".NET"
				}
			}
		}

		// Content-Type analysis for additional technology detection
		if contentType, exists := conversation.Response.Headers["content-type"]; exists {
			contentTypeLower := strings.ToLower(contentType)
			if strings.Contains(contentTypeLower, "application/json") {
				// Likely API endpoint - could indicate modern framework
			}
		}
	}

	// Basic traffic stats
	a.analysisResults.Statistics.TotalRequests++
	if conversation.Request != nil {
		a.analysisResults.Statistics.MethodDistrib[conversation.Request.Method]++
	}
	if conversation.Response != nil {
		a.analysisResults.Statistics.StatusDistrib[conversation.Response.StatusCode]++
	}

	// Return copy of analysis results
	results := &AnalysisResults{
		Patterns:     make([]Pattern, 0),
		Technologies: a.analysisResults.Technologies,
		Statistics:   a.analysisResults.Statistics,
		Anomalies:    make([]*Anomaly, 0),
	}

	return results, nil
}

// GetTechnologyProfile returns the current technology profile
func (a *Analyzer) GetTechnologyProfile() TechnologyProfile {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.analysisResults.Technologies
}

// Close cleans up analyzer resources
func (a *Analyzer) Close() {
	// Cleanup resources if needed
}
