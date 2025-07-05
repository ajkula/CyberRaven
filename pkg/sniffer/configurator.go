// Package sniffer implements network traffic sniffing and analysis for CyberRaven
// File: pkg/sniffer/configurator.go
package sniffer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ajkula/cyberraven/pkg/config"
)

// Configurator automatically updates CyberRaven configuration based on discoveries
type Configurator struct {
	config        *config.SnifferConfig
	targetConfig  *config.TargetConfig
	attackConfigs *config.AttacksConfig

	// Configuration file management
	configFilePath string
	backupDir      string
	autoBackup     bool
	updateInterval time.Duration

	// Update tracking
	mu              sync.RWMutex
	pendingUpdates  *ConfigurationUpdates
	recommendations []AttackRecommendation
	lastUpdateTime  time.Time
	updateCount     int

	// Intelligence aggregation
	discoveredTokens     map[string]*DiscoveredToken
	discoveredSignatures map[string]*DiscoveredSignature
	discoveredEndpoints  map[string]*DiscoveredEndpoint
	detectedTechnologies map[string]*TechDetection
	sensitiveDataLeaks   map[string]*SensitiveDataLeak

	// Confidence tracking
	endpointConfidence  map[string]float64
	tokenConfidence     map[string]float64
	signatureConfidence map[string]float64

	// Callbacks
	configUpdateCallback   func(*ConfigurationUpdates)
	recommendationCallback func([]AttackRecommendation)
	errorCallback          func(error)
}

// ConfigurationTemplate represents a configuration template for different scenarios
type ConfigurationTemplate struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Profile     string                 `yaml:"profile"`
	Target      config.TargetConfig    `yaml:"target"`
	Attacks     config.AttacksConfig   `yaml:"attacks"`
	Metadata    map[string]interface{} `yaml:"metadata"`
}

// UpdateStrategy defines how configuration updates should be applied
type UpdateStrategy struct {
	// Update behavior
	MergeStrategy       string  // replace, merge, append
	ConfidenceThreshold float64 // Minimum confidence to apply updates
	MaxEndpoints        int     // Maximum endpoints to include
	MaxTokens           int     // Maximum tokens to include

	// Safety settings
	BackupBefore  bool // Create backup before updating
	ValidateAfter bool // Validate config after updating
	DryRun        bool // Don't actually write, just report changes

	// Filtering
	IncludeModules []string // Only update these modules
	ExcludeModules []string // Don't update these modules
	MinOccurrences int      // Minimum occurrences to include discovery
}

// NewConfigurator creates a new configuration generator
func NewConfigurator(snifferConfig *config.SnifferConfig, targetConfig *config.TargetConfig, attackConfigs *config.AttacksConfig) *Configurator {
	configurator := &Configurator{
		config:        snifferConfig,
		targetConfig:  targetConfig,
		attackConfigs: attackConfigs,

		// Default configuration file management
		configFilePath: "cyberraven.yaml",
		backupDir:      "./backups",
		autoBackup:     true,
		updateInterval: 30 * time.Second,

		// Initialize tracking maps
		pendingUpdates:       &ConfigurationUpdates{},
		recommendations:      make([]AttackRecommendation, 0),
		discoveredTokens:     make(map[string]*DiscoveredToken),
		discoveredSignatures: make(map[string]*DiscoveredSignature),
		discoveredEndpoints:  make(map[string]*DiscoveredEndpoint),
		detectedTechnologies: make(map[string]*TechDetection),
		sensitiveDataLeaks:   make(map[string]*SensitiveDataLeak),
		endpointConfidence:   make(map[string]float64),
		tokenConfidence:      make(map[string]float64),
		signatureConfidence:  make(map[string]float64),
	}

	// Create backup directory
	if configurator.autoBackup {
		os.MkdirAll(configurator.backupDir, 0755)
	}

	return configurator
}

// ProcessDiscoveries processes detection and analysis results to generate configuration updates
func (c *Configurator) ProcessDiscoveries(detectionResults *DetectionResults, analysisResults *AnalysisResults) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear previous pending updates
	c.pendingUpdates = &ConfigurationUpdates{}
	c.recommendations = make([]AttackRecommendation, 0)

	// Process each type of discovery
	if err := c.processTokenDiscoveries(detectionResults.Tokens); err != nil {
		return fmt.Errorf("failed to process token discoveries: %w", err)
	}

	if err := c.processSignatureDiscoveries(detectionResults.Signatures); err != nil {
		return fmt.Errorf("failed to process signature discoveries: %w", err)
	}

	if err := c.processEndpointDiscoveries(detectionResults.Endpoints); err != nil {
		return fmt.Errorf("failed to process endpoint discoveries: %w", err)
	}

	if err := c.processTechnologyProfile(&analysisResults.Technologies); err != nil {
		return fmt.Errorf("failed to process technology profile: %w", err)
	}

	if err := c.processSensitiveDataLeaks(detectionResults.SensitiveData); err != nil {
		return fmt.Errorf("failed to process sensitive data leaks: %w", err)
	}

	// Generate attack recommendations based on all discoveries
	c.generateAttackRecommendations(analysisResults)

	// Update timestamp
	c.lastUpdateTime = time.Now()
	c.updateCount++

	return nil
}

// processTokenDiscoveries processes discovered tokens and updates JWT/auth configurations
func (c *Configurator) processTokenDiscoveries(tokens []DiscoveredToken) error {
	authTypes := make(map[string]int)
	tokenLocations := make(map[string]int)

	for _, token := range tokens {
		// Track for confidence calculation
		key := fmt.Sprintf("%s_%s_%s", token.Type, token.Location, token.LocationKey)
		c.discoveredTokens[key] = &token
		c.tokenConfidence[key] = c.calculateTokenConfidence(&token)

		// Skip low confidence tokens
		if c.tokenConfidence[key] < 0.6 {
			continue
		}

		// Update statistics for auth configuration
		authTypes[token.Type]++
		tokenLocations[token.Location]++

		// Process by token type and update configurations directly
		switch token.Type {
		case "jwt":
			// Update JWT configuration
			c.pendingUpdates.JWTUpdates.TokensFound = appendUnique(c.pendingUpdates.JWTUpdates.TokensFound, token.Value)
			c.pendingUpdates.JWTUpdates.TokenLocations = appendUnique(c.pendingUpdates.JWTUpdates.TokenLocations, fmt.Sprintf("%s:%s", token.Location, token.LocationKey))

			if token.JWTAlgorithm != "" {
				c.pendingUpdates.JWTUpdates.Algorithms = appendUnique(c.pendingUpdates.JWTUpdates.Algorithms, token.JWTAlgorithm)
			}

			if token.ExpiresAt != nil {
				c.pendingUpdates.JWTUpdates.ExpirationTimes = appendUnique(c.pendingUpdates.JWTUpdates.ExpirationTimes, token.ExpiresAt.Format(time.RFC3339))
			}

		case "api_key":
			// Update API configuration
			if c.pendingUpdates.TargetUpdates.Headers == nil {
				c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
			}
			c.pendingUpdates.TargetUpdates.Headers[token.LocationKey] = "API_KEY_PLACEHOLDER"

		case "session":
			// Update session configuration
			if c.pendingUpdates.TargetUpdates.SessionCookies == nil {
				c.pendingUpdates.TargetUpdates.SessionCookies = make(map[string]string)
			}
			c.pendingUpdates.TargetUpdates.SessionCookies[token.LocationKey] = "SESSION_TOKEN_PLACEHOLDER"

		case "bearer":
			// Update bearer token configuration
			if c.pendingUpdates.TargetUpdates.Headers == nil {
				c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
			}
			c.pendingUpdates.TargetUpdates.Headers["Authorization"] = "Bearer BEARER_TOKEN_PLACEHOLDER"
		}
	}

	// Update target auth configuration based on most common auth type
	if primaryAuth := c.getMostCommon(authTypes); primaryAuth != "" {
		c.pendingUpdates.TargetUpdates.AuthType = primaryAuth

		// Set appropriate auth token based on type
		switch primaryAuth {
		case "jwt", "bearer":
			c.pendingUpdates.TargetUpdates.AuthToken = "JWT_TOKEN_PLACEHOLDER"
		case "api_key":
			c.pendingUpdates.TargetUpdates.AuthToken = "API_KEY_PLACEHOLDER"
		case "session":
			// Session tokens go in cookies, not auth token
		}
	}

	// Update headers based on most common token location
	if primaryLocation := c.getMostCommon(tokenLocations); primaryLocation == "header" {
		if c.pendingUpdates.TargetUpdates.Headers == nil {
			c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
		}
		// Most common header location gets the primary auth
		c.pendingUpdates.TargetUpdates.Headers["Authorization"] = "Bearer TOKEN_PLACEHOLDER"
	}

	return nil
}

// processSignatureDiscoveries processes discovered signatures and updates HMAC configuration
func (c *Configurator) processSignatureDiscoveries(signatures []DiscoveredSignature) error {
	hmacSignatures := make([]*DiscoveredSignature, 0)
	algorithms := make(map[string]int)
	signatureHeaders := make(map[string]int)
	timestampHeaders := make(map[string]int)

	for _, sig := range signatures {
		// Track for confidence calculation
		key := fmt.Sprintf("%s_%s_%s", sig.Type, sig.Algorithm, sig.HeaderName)
		c.discoveredSignatures[key] = &sig
		c.signatureConfidence[key] = c.calculateSignatureConfidence(&sig)

		// Skip low confidence signatures
		if c.signatureConfidence[key] < 0.7 {
			continue
		}

		if sig.Type == "hmac" {
			hmacSignatures = append(hmacSignatures, &sig)
			algorithms[sig.Algorithm]++

			if sig.HeaderName != "" {
				signatureHeaders[sig.HeaderName]++
			}

			if sig.TimestampHeader != "" {
				timestampHeaders[sig.TimestampHeader]++
			}
		}
	}

	// Update HMAC configuration if signatures found
	if len(hmacSignatures) > 0 {
		// Find most common algorithm
		if primaryAlgorithm := c.getMostCommon(algorithms); primaryAlgorithm != "" {
			c.pendingUpdates.HMACUpdates.Algorithm = primaryAlgorithm
		}

		// Find most common signature header
		if primarySigHeader := c.getMostCommon(signatureHeaders); primarySigHeader != "" {
			c.pendingUpdates.HMACUpdates.SignatureHeader = primarySigHeader
		}

		// Find most common timestamp header
		if primaryTsHeader := c.getMostCommon(timestampHeaders); primaryTsHeader != "" {
			c.pendingUpdates.HMACUpdates.TimestampHeader = primaryTsHeader
		}

		// Determine if nonce is used
		c.pendingUpdates.HMACUpdates.NonceUsed = c.detectNonceUsage(hmacSignatures)

		// Determine payload hashing
		c.pendingUpdates.HMACUpdates.PayloadHashing = c.detectPayloadHashing(hmacSignatures)

		// Update target auth configuration for HMAC
		c.pendingUpdates.TargetUpdates.AuthType = "hmac"
		if c.pendingUpdates.HMACUpdates.SignatureHeader != "" {
			if c.pendingUpdates.TargetUpdates.Headers == nil {
				c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
			}
			c.pendingUpdates.TargetUpdates.Headers[c.pendingUpdates.HMACUpdates.SignatureHeader] = "HMAC_SIGNATURE_PLACEHOLDER"
		}
	}

	return nil
}

// processEndpointDiscoveries processes discovered endpoints and updates API configuration
func (c *Configurator) processEndpointDiscoveries(endpoints []DiscoveredEndpoint) error {
	discoveredPaths := make([]string, 0)
	commonParameters := make(map[string]int)
	authRequired := false
	csrfRequired := false

	for _, endpoint := range endpoints {
		// Track for confidence calculation
		key := fmt.Sprintf("%s_%s", endpoint.Method, endpoint.Path)
		c.discoveredEndpoints[key] = &endpoint
		c.endpointConfidence[key] = c.calculateEndpointConfidence(&endpoint)

		// Skip low confidence endpoints
		if c.endpointConfidence[key] < 0.5 {
			continue
		}

		// Skip root/common paths that are not interesting
		if c.isIgnorableEndpoint(endpoint.Path) {
			continue
		}

		// Add to discovered endpoints
		discoveredPaths = append(discoveredPaths, endpoint.Path)

		// Track global characteristics
		if endpoint.AuthRequired {
			authRequired = true
		}

		if endpoint.CSRFProtected {
			csrfRequired = true
		}

		// Collect common parameters
		for _, param := range endpoint.Parameters {
			commonParameters[param.Name]++
		}

		// Create parameter testing recommendations
		for _, param := range endpoint.Parameters {
			if param.InjectionRisk == "high" || param.InjectionRisk == "medium" {
				c.pendingUpdates.InjectionUpdates.VulnerableParams = appendUnique(
					c.pendingUpdates.InjectionUpdates.VulnerableParams,
					fmt.Sprintf("%s.%s", endpoint.Path, param.Name),
				)
			}
		}
	}

	// Update API configuration
	if len(discoveredPaths) > 0 {
		// Sort by confidence and limit number
		c.sortEndpointsByConfidence(discoveredPaths)
		if len(discoveredPaths) > 50 { // Limit to top 50 endpoints
			discoveredPaths = discoveredPaths[:50]
		}

		c.pendingUpdates.APIUpdates.DiscoveredEndpoints = discoveredPaths
		c.pendingUpdates.APIUpdates.AuthenticationReq = authRequired
		c.pendingUpdates.APIUpdates.CSRFRequired = csrfRequired

		// Add most common parameters
		commonParamList := c.getTopParameters(commonParameters, 20)
		c.pendingUpdates.APIUpdates.CommonParameters = commonParamList
	}

	return nil
}

// processTechnologyProfile processes technology fingerprinting results
func (c *Configurator) processTechnologyProfile(techProfile *TechnologyProfile) error {
	// Update injection configuration based on detected technologies
	if techProfile.Database != "" {
		c.pendingUpdates.InjectionUpdates.DatabaseType = techProfile.Database
	}

	if techProfile.Framework != "" {
		c.pendingUpdates.InjectionUpdates.FrameworkDetected = techProfile.Framework
	}

	// Update DoS configuration based on infrastructure
	if techProfile.CDN != "" {
		c.pendingUpdates.DoSUpdates.CDNDetected = techProfile.CDN
		c.pendingUpdates.DoSUpdates.RateLimit = 5 // Lower rate for CDN-protected targets
	}

	if techProfile.LoadBalancer != "" {
		c.pendingUpdates.DoSUpdates.LoadBalancer = true
		c.pendingUpdates.DoSUpdates.MaxConnections = 20 // Higher connections for load-balanced targets
	}

	// Update TLS configuration based on server
	if techProfile.WebServer != "" {
		if versions, exists := techProfile.Versions[techProfile.WebServer]; exists {
			c.pendingUpdates.TLSUpdates.TLSVersions = []string{versions}
		}
	}

	// Update target profile based on detected stack
	c.updateTargetProfile(techProfile)

	return nil
}

// processSensitiveDataLeaks processes sensitive data leak discoveries
func (c *Configurator) processSensitiveDataLeaks(leaks []SensitiveDataLeak) error {
	for _, leak := range leaks {
		key := fmt.Sprintf("%s_%s", leak.DataType, leak.Location)
		c.sensitiveDataLeaks[key] = &leak

		// Create high-priority recommendations for critical leaks
		if leak.Severity == "critical" {
			recommendation := AttackRecommendation{
				Module:      "manual_verification",
				Priority:    "critical",
				Confidence:  0.9,
				Description: fmt.Sprintf("Critical data leak detected: %s in %s", leak.DataType, leak.Location),
				Reasoning:   "Sensitive data exposure requires immediate verification and remediation",
				Targets:     []string{leak.Location},
			}
			c.recommendations = append(c.recommendations, recommendation)
		}
	}

	return nil
}

// generateAttackRecommendations generates prioritized attack recommendations
func (c *Configurator) generateAttackRecommendations(analysisResults *AnalysisResults) {
	// JWT testing recommendations
	if len(c.pendingUpdates.JWTUpdates.TokensFound) > 0 {
		confidence := 0.8
		priority := "high"

		// Increase priority if weak algorithms detected
		for _, alg := range c.pendingUpdates.JWTUpdates.Algorithms {
			if alg == "none" || alg == "HS256" {
				priority = "critical"
				confidence = 0.95
				break
			}
		}

		recommendation := AttackRecommendation{
			Module:      "jwt",
			Priority:    priority,
			Confidence:  confidence,
			Description: fmt.Sprintf("JWT tokens detected (%d locations)", len(c.pendingUpdates.JWTUpdates.TokenLocations)),
			Reasoning:   "JWT tokens found with potential security vulnerabilities",
			Targets:     c.pendingUpdates.JWTUpdates.TokenLocations,
			Payloads:    c.generateJWTPayloads(),
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// HMAC testing recommendations
	if c.pendingUpdates.HMACUpdates.Algorithm != "" {
		confidence := 0.7
		priority := "medium"

		// Increase priority for weak algorithms
		if c.pendingUpdates.HMACUpdates.Algorithm == "md5" || c.pendingUpdates.HMACUpdates.Algorithm == "sha1" {
			priority = "high"
			confidence = 0.9
		}

		recommendation := AttackRecommendation{
			Module:      "hmac",
			Priority:    priority,
			Confidence:  confidence,
			Description: fmt.Sprintf("HMAC signatures detected (algorithm: %s)", c.pendingUpdates.HMACUpdates.Algorithm),
			Reasoning:   "HMAC authentication system identified with potential attack vectors",
			Targets:     []string{c.pendingUpdates.HMACUpdates.SignatureHeader},
			Payloads:    c.generateHMACPayloads(),
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// API testing recommendations
	if len(c.pendingUpdates.APIUpdates.DiscoveredEndpoints) > 0 {
		confidence := float64(len(c.pendingUpdates.APIUpdates.DiscoveredEndpoints)) / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}

		priority := "medium"
		if len(c.pendingUpdates.APIUpdates.DiscoveredEndpoints) > 20 {
			priority = "high"
		}

		recommendation := AttackRecommendation{
			Module:      "api",
			Priority:    priority,
			Confidence:  confidence,
			Description: fmt.Sprintf("API endpoints discovered (%d endpoints)", len(c.pendingUpdates.APIUpdates.DiscoveredEndpoints)),
			Reasoning:   "Multiple API endpoints found for enumeration and testing",
			Targets:     c.pendingUpdates.APIUpdates.DiscoveredEndpoints,
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// Injection testing recommendations
	if len(c.pendingUpdates.InjectionUpdates.VulnerableParams) > 0 {
		recommendation := AttackRecommendation{
			Module:      "injection",
			Priority:    "high",
			Confidence:  0.8,
			Description: fmt.Sprintf("Injection-vulnerable parameters detected (%d parameters)", len(c.pendingUpdates.InjectionUpdates.VulnerableParams)),
			Reasoning:   "Parameters with high injection risk identified",
			Targets:     c.pendingUpdates.InjectionUpdates.VulnerableParams,
			Payloads:    c.generateInjectionPayloads(),
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// DoS testing recommendations (only if infrastructure supports it)
	if c.pendingUpdates.DoSUpdates.CDNDetected == "" { // No CDN = potentially vulnerable
		recommendation := AttackRecommendation{
			Module:      "dos",
			Priority:    "low",
			Confidence:  0.6,
			Description: "No DDoS protection detected",
			Reasoning:   "Server appears to lack DDoS protection mechanisms",
			Targets:     []string{"/"},
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// TLS testing recommendations
	if len(c.pendingUpdates.TLSUpdates.TLSVersions) > 0 {
		recommendation := AttackRecommendation{
			Module:      "tls",
			Priority:    "medium",
			Confidence:  0.7,
			Description: "TLS configuration detected for security testing",
			Reasoning:   "TLS implementation should be tested for vulnerabilities",
			Targets:     []string{"https://" + c.targetConfig.BaseURL},
		}
		c.recommendations = append(c.recommendations, recommendation)
	}

	// Sort recommendations by priority and confidence
	c.sortRecommendations()
}

// ApplyConfigurationUpdates applies the pending configuration updates to the config file
func (c *Configurator) ApplyConfigurationUpdates(strategy *UpdateStrategy) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if strategy == nil {
		strategy = c.getDefaultUpdateStrategy()
	}

	// Create backup if enabled
	if strategy.BackupBefore && c.autoBackup {
		if err := c.createBackup(); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
	}

	// Load current configuration
	currentConfig, err := c.loadCurrentConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load current configuration: %w", err)
	}

	// Apply updates based on strategy
	updatedConfig := c.mergeConfigurations(currentConfig, strategy)

	// Validate updated configuration
	if strategy.ValidateAfter {
		if err := c.validateConfiguration(updatedConfig); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	// Write configuration (or dry run)
	if strategy.DryRun {
		return c.reportDryRun(currentConfig, updatedConfig)
	} else {
		return c.writeConfiguration(updatedConfig)
	}
}

// Helper methods for configuration processing

func (c *Configurator) calculateTokenConfidence(token *DiscoveredToken) float64 {
	confidence := 0.5 // Base confidence

	// Usage count increases confidence
	confidence += float64(token.UsageCount) * 0.1
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Valid tokens get higher confidence
	if token.IsValid {
		confidence += 0.2
	}

	// JWT tokens with proper structure get higher confidence
	if token.Type == "jwt" && token.JWTAlgorithm != "" {
		confidence += 0.3
	}

	// Security issues reduce confidence
	confidence -= float64(len(token.SecurityIssues)) * 0.1

	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (c *Configurator) calculateSignatureConfidence(sig *DiscoveredSignature) float64 {
	confidence := 0.6 // Base confidence for signatures

	// Request count increases confidence
	confidence += float64(sig.RequestsCount) * 0.05

	// Valid signatures get higher confidence
	if sig.ValidSignatures > 0 {
		validRatio := float64(sig.ValidSignatures) / float64(sig.RequestsCount)
		confidence += validRatio * 0.3
	}

	// Consistent timing increases confidence
	if len(sig.ResponseTimes) > 3 {
		confidence += 0.1
	}

	// Weak algorithms reduce confidence
	if sig.WeakAlgorithm {
		confidence -= 0.2
	}

	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (c *Configurator) calculateEndpointConfidence(endpoint *DiscoveredEndpoint) float64 {
	confidence := 0.4 // Base confidence

	// Request count increases confidence
	confidence += float64(endpoint.RequestCount) * 0.1
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Multiple status codes increase confidence
	confidence += float64(len(endpoint.StatusCodes)) * 0.05

	// Parameters increase confidence
	confidence += float64(len(endpoint.Parameters)) * 0.02

	// Security features increase confidence
	if endpoint.AuthRequired {
		confidence += 0.1
	}
	if endpoint.CSRFProtected {
		confidence += 0.1
	}

	// Attack surface increases confidence (more interesting endpoints)
	confidence += float64(len(endpoint.AttackSurface)) * 0.05

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (c *Configurator) updateAuthConfiguration(authTypes map[string]int, tokenLocations map[string]int, jwtTokens, apiKeys []string) {
	// Determine primary auth type
	primaryAuth := c.getMostCommon(authTypes)
	if primaryAuth != "" {
		c.pendingUpdates.TargetUpdates.AuthType = primaryAuth
	}

	// Set token if available
	if len(jwtTokens) > 0 {
		c.pendingUpdates.TargetUpdates.AuthToken = "JWT_TOKEN_PLACEHOLDER"
	} else if len(apiKeys) > 0 {
		c.pendingUpdates.TargetUpdates.AuthToken = "API_KEY_PLACEHOLDER"
	}

	// Set headers based on token locations
	if tokenLocations["header"] > 0 {
		if c.pendingUpdates.TargetUpdates.Headers == nil {
			c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
		}
		c.pendingUpdates.TargetUpdates.Headers["Authorization"] = "Bearer TOKEN_PLACEHOLDER"
	}
}

func (c *Configurator) updateTargetProfile(techProfile *TechnologyProfile) {
	// Update base URL if we detected a more specific one
	if c.targetConfig.BaseURL == "" && techProfile.WebServer != "" {
		// Keep existing base URL, just note the server type
	}

	// Add server information to headers
	if c.pendingUpdates.TargetUpdates.Headers == nil {
		c.pendingUpdates.TargetUpdates.Headers = make(map[string]string)
	}

	// Add user agent that matches detected technology
	if techProfile.Framework != "" {
		switch techProfile.Framework {
		case "express":
			c.pendingUpdates.TargetUpdates.Headers["User-Agent"] = "CyberRaven/1.0 (Node.js testing)"
		case "django":
			c.pendingUpdates.TargetUpdates.Headers["User-Agent"] = "CyberRaven/1.0 (Python testing)"
		case "spring":
			c.pendingUpdates.TargetUpdates.Headers["User-Agent"] = "CyberRaven/1.0 (Java testing)"
		}
	}
}

func (c *Configurator) isIgnorableEndpoint(path string) bool {
	ignorePaths := []string{
		"/", "/index", "/home", "/favicon.ico", "/robots.txt",
		"/sitemap.xml", "/ping", "/health", "/status",
	}

	for _, ignore := range ignorePaths {
		if path == ignore {
			return true
		}
	}

	// Ignore static file paths
	if strings.Contains(path, ".css") || strings.Contains(path, ".js") ||
		strings.Contains(path, ".png") || strings.Contains(path, ".jpg") ||
		strings.Contains(path, ".gif") || strings.Contains(path, ".ico") {
		return true
	}

	return false
}

func (c *Configurator) getMostCommon(counts map[string]int) string {
	maxCount := 0
	mostCommon := ""

	for item, count := range counts {
		if count > maxCount {
			maxCount = count
			mostCommon = item
		}
	}

	return mostCommon
}

func (c *Configurator) getTopParameters(paramCounts map[string]int, limit int) []string {
	type paramCount struct {
		name  string
		count int
	}

	params := make([]paramCount, 0, len(paramCounts))
	for name, count := range paramCounts {
		params = append(params, paramCount{name: name, count: count})
	}

	// Sort by count descending
	sort.Slice(params, func(i, j int) bool {
		return params[i].count > params[j].count
	})

	// Return top parameters
	result := make([]string, 0, limit)
	for i, param := range params {
		if i >= limit {
			break
		}
		result = append(result, param.name)
	}

	return result
}

func (c *Configurator) sortEndpointsByConfidence(endpoints []string) {
	sort.Slice(endpoints, func(i, j int) bool {
		// Create keys for confidence lookup
		keyI := fmt.Sprintf("GET_%s", endpoints[i]) // Assume GET for sorting
		keyJ := fmt.Sprintf("GET_%s", endpoints[j])

		confI := c.endpointConfidence[keyI]
		confJ := c.endpointConfidence[keyJ]

		return confI > confJ
	})
}

func (c *Configurator) sortRecommendations() {
	sort.Slice(c.recommendations, func(i, j int) bool {
		// Priority order: critical > high > medium > low
		priorityOrder := map[string]int{
			"critical": 4,
			"high":     3,
			"medium":   2,
			"low":      1,
		}

		priI := priorityOrder[c.recommendations[i].Priority]
		priJ := priorityOrder[c.recommendations[j].Priority]

		if priI != priJ {
			return priI > priJ
		}

		// If same priority, sort by confidence
		return c.recommendations[i].Confidence > c.recommendations[j].Confidence
	})
}

func (c *Configurator) detectNonceUsage(signatures []*DiscoveredSignature) bool {
	for _, sig := range signatures {
		if strings.Contains(strings.ToLower(sig.HeaderName), "nonce") {
			return true
		}
	}
	return false
}

func (c *Configurator) detectPayloadHashing(signatures []*DiscoveredSignature) bool {
	// If we see signatures consistently, assume payload hashing
	return len(signatures) > 0
}

// Payload generation methods

func (c *Configurator) generateJWTPayloads() []string {
	payloads := []string{
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.invalid-signature",
	}

	return payloads
}

func (c *Configurator) generateHMACPayloads() []string {
	payloads := []string{
		"tampered_payload_signature",
		"old_timestamp_signature",
		"missing_signature",
	}

	return payloads
}

func (c *Configurator) generateInjectionPayloads() []string {
	payloads := []string{
		"' OR 1=1--",
		"'; DROP TABLE users--",
		"<script>alert('xss')</script>",
		"../../../etc/passwd",
	}

	return payloads
}

// Configuration file management methods

func (c *Configurator) loadCurrentConfiguration() (*config.Config, error) {
	data, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, err
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Configurator) mergeConfigurations(current *config.Config, strategy *UpdateStrategy) *config.Config {
	// Create a copy of current configuration
	updated := *current

	// Apply target updates
	if c.pendingUpdates.TargetUpdates.BaseURL != "" {
		updated.Target.BaseURL = c.pendingUpdates.TargetUpdates.BaseURL
	}
	if c.pendingUpdates.TargetUpdates.AuthType != "" {
		updated.Target.Auth.Type = c.pendingUpdates.TargetUpdates.AuthType
	}
	if c.pendingUpdates.TargetUpdates.AuthToken != "" {
		updated.Target.Auth.Token = c.pendingUpdates.TargetUpdates.AuthToken
	}

	// Merge headers
	if c.pendingUpdates.TargetUpdates.Headers != nil {
		if updated.Target.Headers == nil {
			updated.Target.Headers = make(map[string]string)
		}
		for key, value := range c.pendingUpdates.TargetUpdates.Headers {
			updated.Target.Headers[key] = value
		}
	}

	// Apply API updates
	if len(c.pendingUpdates.APIUpdates.DiscoveredEndpoints) > 0 {
		updated.Attacks.API.CommonEndpoints = c.pendingUpdates.APIUpdates.DiscoveredEndpoints
	}

	// Apply JWT updates
	// Note: We don't store actual tokens in config, just note their presence

	// Apply HMAC updates
	if c.pendingUpdates.HMACUpdates.Algorithm != "" {
		updated.Target.Auth.HMAC.Algorithm = c.pendingUpdates.HMACUpdates.Algorithm
	}
	if c.pendingUpdates.HMACUpdates.SignatureHeader != "" {
		updated.Target.Auth.HMAC.SignatureHeader = c.pendingUpdates.HMACUpdates.SignatureHeader
	}
	if c.pendingUpdates.HMACUpdates.TimestampHeader != "" {
		updated.Target.Auth.HMAC.TimestampHeader = c.pendingUpdates.HMACUpdates.TimestampHeader
	}

	// Apply injection updates
	// Note: Vulnerable parameters are noted but not directly added to config

	// Apply DoS updates
	if c.pendingUpdates.DoSUpdates.MaxConnections > 0 {
		updated.Attacks.DoS.MaxConnections = c.pendingUpdates.DoSUpdates.MaxConnections
	}
	if c.pendingUpdates.DoSUpdates.RateLimit > 0 {
		updated.Attacks.DoS.FloodingRate = c.pendingUpdates.DoSUpdates.RateLimit
	}

	return &updated
}

func (c *Configurator) writeConfiguration(cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(c.configFilePath, data, 0644)
}

func (c *Configurator) createBackup() error {
	if c.backupDir == "" {
		c.backupDir = "./backups"
	}

	if err := os.MkdirAll(c.backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	backupFile := filepath.Join(c.backupDir, fmt.Sprintf("cyberraven_%s.yaml", timestamp))

	if c.configFilePath == "" {
		c.configFilePath = "cyberraven.yaml"
	}

	data, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", c.configFilePath, err)
	}

	return os.WriteFile(backupFile, data, 0644)
}

func (c *Configurator) validateConfiguration(cfg *config.Config) error {
	// Basic validation
	if cfg.Target.BaseURL == "" {
		return fmt.Errorf("target base URL cannot be empty")
	}

	// Validate auth configuration
	if cfg.Target.Auth.Type == "hmac" && cfg.Target.Auth.HMAC.Algorithm == "" {
		return fmt.Errorf("HMAC auth type requires algorithm")
	}

	return nil
}

func (c *Configurator) reportDryRun(current, updated *config.Config) error {
	fmt.Println("=== DRY RUN: Configuration Changes ===")

	// Compare and report differences
	if current.Target.Auth.Type != updated.Target.Auth.Type {
		fmt.Printf("Auth Type: %s -> %s\n", current.Target.Auth.Type, updated.Target.Auth.Type)
	}

	if len(current.Attacks.API.CommonEndpoints) != len(updated.Attacks.API.CommonEndpoints) {
		fmt.Printf("API Endpoints: %d -> %d\n", len(current.Attacks.API.CommonEndpoints), len(updated.Attacks.API.CommonEndpoints))
	}

	fmt.Printf("Total Recommendations: %d\n", len(c.recommendations))
	for i, rec := range c.recommendations {
		if i >= 5 { // Show top 5
			break
		}
		fmt.Printf("  %d. [%s] %s (%.2f confidence)\n", i+1, rec.Priority, rec.Description, rec.Confidence)
	}

	return nil
}

func (c *Configurator) getDefaultUpdateStrategy() *UpdateStrategy {
	return &UpdateStrategy{
		MergeStrategy:       "merge",
		ConfidenceThreshold: 0.6,
		MaxEndpoints:        50,
		MaxTokens:           10,
		BackupBefore:        true,
		ValidateAfter:       true,
		DryRun:              false,
		MinOccurrences:      2,
	}
}

// Utility functions

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

// Public interface methods

// SetConfigFilePath sets the path to the configuration file
func (c *Configurator) SetConfigFilePath(path string) {
	c.configFilePath = path
}

// SetUpdateInterval sets the automatic update interval
func (c *Configurator) SetUpdateInterval(interval time.Duration) {
	c.updateInterval = interval
}

// GetPendingUpdates returns current pending configuration updates
func (c *Configurator) GetPendingUpdates() *ConfigurationUpdates {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.pendingUpdates
}

// GetRecommendations returns current attack recommendations
func (c *Configurator) GetRecommendations() []AttackRecommendation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	recommendations := make([]AttackRecommendation, len(c.recommendations))
	copy(recommendations, c.recommendations)

	return recommendations
}

// SetConfigUpdateCallback sets callback for configuration updates
func (c *Configurator) SetConfigUpdateCallback(callback func(*ConfigurationUpdates)) {
	c.configUpdateCallback = callback
}

// SetRecommendationCallback sets callback for attack recommendations
func (c *Configurator) SetRecommendationCallback(callback func([]AttackRecommendation)) {
	c.recommendationCallback = callback
}

// SetErrorCallback sets callback for errors
func (c *Configurator) SetErrorCallback(callback func(error)) {
	c.errorCallback = callback
}

// GetStats returns configurator statistics
func (c *Configurator) GetStats() (updates int, recommendations int, lastUpdate time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.updateCount, len(c.recommendations), c.lastUpdateTime
}

// Close cleans up configurator resources
func (c *Configurator) Close() {
	// Cleanup resources if needed
}
