package api

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// NewVulnerabilityDetector creates a new intelligent vulnerability detector
func NewVulnerabilityDetector(discoveryCtx *discovery.AttackContext) *VulnerabilityDetector {
	adapter := &ContextualAdapter{discoveryCtx: discoveryCtx}

	var technology discovery.TechnologyInfo
	if discoveryCtx != nil {
		technology = discoveryCtx.Technology
	}

	payloadGen := &PayloadGenerator{technology: technology}
	ruleEngine := &RuleEngine{rules: createIntelligentRules()}

	return &VulnerabilityDetector{
		discoveryCtx:      discoveryCtx,
		ruleEngine:        ruleEngine,
		contextualAdapter: adapter,
		payloadGenerator:  payloadGen,
	}
}

// AnalyzeResponse analyzes an HTTP response for security vulnerabilities using intelligence
func (vd *VulnerabilityDetector) AnalyzeResponse(path, method string, resp *utils.HTTPResponse) []VulnerabilityFinding {
	// Create detection context
	detectionCtx := vd.createDetectionContext(path, method, resp)

	// Filter rules based on context
	applicableRules := vd.ruleEngine.getApplicableRules(detectionCtx)

	var vulns []VulnerabilityFinding

	// Execute applicable rules
	for _, rule := range applicableRules {
		if detected, evidence := rule.Check(path, method, resp, detectionCtx); detected {
			vulns = append(vulns, VulnerabilityFinding{
				Type:        rule.Type,
				Severity:    rule.Severity,
				Endpoint:    path,
				Method:      method,
				Description: rule.Description,
				Evidence:    evidence,
				Remediation: rule.Remediation,
			})
		}
	}

	return vulns
}

// createDetectionContext creates context for intelligent detection
func (vd *VulnerabilityDetector) createDetectionContext(path, method string, resp *utils.HTTPResponse) *DetectionContext {
	ctx := &DetectionContext{
		DiscoveryCtx: vd.discoveryCtx,
	}

	if vd.discoveryCtx != nil {
		ctx.Technology = vd.discoveryCtx.Technology
		ctx.HasJWT = len(vd.discoveryCtx.GetJWTTokens()) > 0
		ctx.HasParameters = len(vd.discoveryCtx.GetParameterizedEndpoints()) > 0
		ctx.DatabaseType = strings.ToLower(vd.discoveryCtx.Technology.Database)
		ctx.FrameworkType = strings.ToLower(vd.discoveryCtx.Technology.Framework)
	}

	// Determine endpoint type
	ctx.EndpointType = vd.classifyEndpoint(path)

	return ctx
}

// classifyEndpoint classifies endpoint type for contextual testing
func (vd *VulnerabilityDetector) classifyEndpoint(path string) string {
	lowerPath := strings.ToLower(path)

	switch {
	case contains(lowerPath, "auth") || contains(lowerPath, "login") || contains(lowerPath, "token"):
		return "auth"
	case contains(lowerPath, "admin") || contains(lowerPath, "manage") || contains(lowerPath, "config"):
		return "admin"
	case contains(lowerPath, "api") || contains(lowerPath, "rest"):
		return "api"
	case contains(lowerPath, "file") || contains(lowerPath, "upload") || contains(lowerPath, "download"):
		return "file"
	case contains(lowerPath, "user") || contains(lowerPath, "account") || contains(lowerPath, "profile"):
		return "resource"
	default:
		return "generic"
	}
}

// getApplicableRules filters rules based on detection context
func (re *RuleEngine) getApplicableRules(ctx *DetectionContext) []DetectionRule {
	var applicable []DetectionRule

	for _, rule := range re.rules {
		// Check if rule applies to this context
		if re.isRuleApplicable(rule, ctx) {
			applicable = append(applicable, rule)
		}
	}

	return applicable
}

// isRuleApplicable checks if a rule applies to the current context
func (re *RuleEngine) isRuleApplicable(rule DetectionRule, ctx *DetectionContext) bool {
	// Check endpoint type context
	if len(rule.Context) > 0 {
		found := false
		for _, reqContext := range rule.Context {
			if reqContext == ctx.EndpointType || reqContext == "all" {
				found = true
				break
			}
			// Special contexts
			if reqContext == "jwt" && ctx.HasJWT {
				found = true
				break
			}
			if reqContext == "params" && ctx.HasParameters {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check technology requirements
	if len(rule.Technologies) > 0 && ctx.DatabaseType != "" {
		found := false
		for _, tech := range rule.Technologies {
			if strings.Contains(ctx.DatabaseType, tech) || strings.Contains(ctx.FrameworkType, tech) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// createIntelligentRules creates modern, contextual vulnerability detection rules
func createIntelligentRules() []DetectionRule {
	return []DetectionRule{
		// Modern SQL Injection Rules
		{
			ID:           "sqli_advanced_union",
			Type:         "sql_injection",
			Severity:     "critical",
			Description:  "Advanced SQL Injection via UNION-based attack",
			Remediation:  "Use parameterized queries and input validation",
			Context:      []string{"api", "resource", "params"},
			Technologies: []string{"mysql", "postgresql", "sqlite", "mssql"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				body := strings.ToLower(resp.BodyPreview)
				query := strings.ToLower(resp.RequestURL)

				// Check for SQL injection indicators in response
				sqlErrors := []string{
					"sql syntax", "mysql_fetch", "ora-", "postgresql",
					"sqlite_", "odbc driver", "microsoft ole db",
					"syntax error", "incorrect syntax near",
				}

				for _, sqlError := range sqlErrors {
					if strings.Contains(body, sqlError) {
						return true, fmt.Sprintf("SQL error detected: %s", sqlError)
					}
				}

				// Check for UNION injection patterns in query
				if strings.Contains(query, "union") && strings.Contains(query, "select") {
					if resp.StatusCode == 200 && resp.BodySize > 100 {
						return true, "UNION SELECT successful with large response"
					}
				}

				return false, ""
			},
		},
		{
			ID:              "sqli_blind_time",
			Type:            "sql_injection_blind",
			Severity:        "high",
			Description:     "Blind SQL Injection via time-based attack",
			Remediation:     "Use parameterized queries and implement rate limiting",
			Context:         []string{"api", "resource", "params"},
			Technologies:    []string{"mysql", "postgresql", "sqlite"},
			TimingSensitive: true,
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Time-based blind SQL injection detection
				if resp.Duration > 5*time.Second {
					query := strings.ToLower(resp.RequestURL)
					if strings.Contains(query, "sleep") || strings.Contains(query, "waitfor") ||
						strings.Contains(query, "pg_sleep") || strings.Contains(query, "benchmark") {
						return true, fmt.Sprintf("Time delay detected: %v with timing payload", resp.Duration)
					}
				}
				return false, ""
			},
		},

		// NoSQL Injection Rules
		{
			ID:           "nosql_injection",
			Type:         "nosql_injection",
			Severity:     "high",
			Description:  "NoSQL Injection detected",
			Remediation:  "Validate input and use proper NoSQL query sanitization",
			Context:      []string{"api", "resource"},
			Technologies: []string{"mongodb", "couchdb", "redis"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				body := strings.ToLower(resp.BodyPreview)
				query := strings.ToLower(resp.RequestURL)

				// NoSQL injection patterns
				nosqlPatterns := []string{
					"$ne", "$gt", "$where", "$regex", "$exists",
					"';return+true;var+dummy='", "';return+false;var+dummy='",
				}

				for _, pattern := range nosqlPatterns {
					if strings.Contains(query, pattern) && resp.StatusCode == 200 {
						return true, fmt.Sprintf("NoSQL injection pattern detected: %s", pattern)
					}
				}

				// MongoDB error patterns
				mongoErrors := []string{
					"mongodb", "bson", "objectid", "db.collection",
				}

				for _, mongoError := range mongoErrors {
					if strings.Contains(body, mongoError) {
						return true, fmt.Sprintf("MongoDB error disclosure: %s", mongoError)
					}
				}

				return false, ""
			},
		},

		// JWT Security Rules
		{
			ID:          "jwt_algorithm_confusion",
			Type:        "jwt_vulnerability",
			Severity:    "critical",
			Description: "JWT Algorithm Confusion attack possible",
			Remediation: "Enforce specific algorithm validation and use algorithm whitelisting",
			Context:     []string{"auth", "jwt"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Check if endpoint accepts JWT with "none" algorithm
				authHeader := resp.RequestHeaders["Authorization"]
				if strings.HasPrefix(authHeader, "Bearer ") {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					if strings.Contains(token, ".") {
						// Basic JWT structure check
						parts := strings.Split(token, ".")
						if len(parts) >= 2 {
							// Check for algorithm confusion indicators
							if resp.StatusCode == 200 && strings.Contains(strings.ToLower(resp.BodyPreview), "admin") {
								return true, "JWT accepted with potential algorithm confusion"
							}
						}
					}
				}
				return false, ""
			},
		},

		// Modern XSS Rules
		{
			ID:          "xss_dom_based",
			Type:        "cross_site_scripting",
			Severity:    "high",
			Description: "DOM-based Cross-Site Scripting vulnerability",
			Remediation: "Implement proper output encoding and Content Security Policy",
			Context:     []string{"all"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				body := resp.BodyPreview

				// Parse URL to check only parameters, not the full URL
				parsedURL, err := url.Parse(resp.RequestURL)
				if err != nil {
					return false, ""
				}

				queryParams := parsedURL.Query()

				// XSS payload patterns to check in parameters
				xssPayloads := []string{
					"<script>", "javascript:", "onerror=", "onload=",
					"eval(", "alert(", "confirm(", "prompt(",
					"<img", "<svg", "<iframe", "<object",
				}

				// Check if XSS payload from parameter is reflected in response
				for paramName, paramValues := range queryParams {
					for _, paramValue := range paramValues {
						for _, payload := range xssPayloads {
							if strings.Contains(strings.ToLower(paramValue), strings.ToLower(payload)) {
								// Check if payload is reflected in response body
								if strings.Contains(strings.ToLower(body), strings.ToLower(payload)) {
									// Additional check: ensure it's in exploitable context
									if isInDangerousContext(body, payload) {
										return true, fmt.Sprintf("XSS payload reflected from parameter %s: %s", paramName, payload)
									}
								}
							}
						}
					}
				}

				// Check for DOM XSS sinks only if we have user input parameters
				if len(queryParams) > 0 {
					domSinks := []string{
						"document.write", "innerHTML", "outerHTML",
						"insertAdjacentHTML", "eval", "setTimeout",
					}

					for _, sink := range domSinks {
						if strings.Contains(body, sink) {
							return true, fmt.Sprintf("DOM XSS sink detected: %s", sink)
						}
					}
				}

				return false, ""
			},
		},

		// Modern Authentication Bypass
		{
			ID:          "auth_bypass_header",
			Type:        "authentication_bypass",
			Severity:    "critical",
			Description: "Authentication bypass via header manipulation",
			Remediation: "Implement proper authentication validation and header security",
			Context:     []string{"auth", "admin"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Check for auth bypass via headers
				suspiciousHeaders := []string{
					"x-forwarded-for", "x-real-ip", "x-originating-ip",
					"x-remote-ip", "x-forwarded-host", "x-original-user",
					"x-user", "x-admin", "x-role",
				}

				for header, value := range resp.RequestHeaders {
					headerLower := strings.ToLower(header)
					for _, suspicious := range suspiciousHeaders {
						if headerLower == suspicious {
							if resp.StatusCode == 200 && strings.Contains(strings.ToLower(resp.BodyPreview), "admin") {
								return true, fmt.Sprintf("Auth bypass via header: %s: %s", header, value)
							}
						}
					}
				}
				return false, ""
			},
		},

		// Business Logic Flaws
		{
			ID:          "business_logic_idor",
			Type:        "insecure_direct_object_reference",
			Severity:    "high",
			Description: "Insecure Direct Object Reference in business logic",
			Remediation: "Implement proper authorization checks and object-level permissions",
			Context:     []string{"api", "resource"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Parse URL to get query parameters
				parsedURL, err := url.Parse(resp.RequestURL)
				if err != nil {
					return false, ""
				}

				queryParams := parsedURL.Query()

				// IDOR patterns - check in parameters only
				idorParams := []string{"id", "user", "userid", "user_id", "account", "profile", "order", "file"}

				for _, idorParam := range idorParams {
					if paramValues, exists := queryParams[idorParam]; exists && len(paramValues) > 0 {
						// Only flag as IDOR if we get successful access AND sensitive data is exposed
						if resp.StatusCode == 200 && resp.BodySize > 100 {
							body := strings.ToLower(resp.BodyPreview)

							// Look for sensitive data patterns that shouldn't be accessible
							sensitivePatterns := []string{
								"\"email\":", "\"phone\":", "\"address\":", "\"ssn\":",
								"\"password\":", "\"credit\":", "\"balance\":", "\"salary\":",
								"\"private\":", "\"secret\":", "\"token\":", "\"key\":",
								"\"admin\":", "\"role\":", "\"permission\":", "\"privilege\":",
								// Multiple user records (suggesting unauthorized access)
								"\"users\":[", "\"accounts\":[", "\"profiles\":[",
							}

							sensitiveCount := 0
							for _, sensitive := range sensitivePatterns {
								if strings.Contains(body, sensitive) {
									sensitiveCount++
								}
							}

							// Flag as IDOR only if multiple sensitive fields are exposed
							if sensitiveCount >= 2 {
								return true, fmt.Sprintf("IDOR accessing sensitive data via parameter %s", idorParam)
							}
						}
					}
				}
				return false, ""
			},
		},

		// Modern XXE
		{
			ID:          "xxe_external_entity",
			Type:        "xxe_injection",
			Severity:    "critical",
			Description: "XML External Entity (XXE) Injection vulnerability",
			Remediation: "Disable external entity processing and use secure XML parsers",
			Context:     []string{"api"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				contentType := resp.Header.Get("Content-Type")
				if strings.Contains(contentType, "xml") || method == "POST" {
					body := resp.BodyPreview

					// Check for XXE payload evidence
					xxeIndicators := []string{
						"file:///", "file://", "http://", "ftp://",
						"ENTITY", "DOCTYPE", "<!ENTITY",
						"/etc/passwd", "/etc/hosts", "C:\\Windows",
					}

					for _, indicator := range xxeIndicators {
						if strings.Contains(body, indicator) {
							return true, fmt.Sprintf("XXE injection evidence: %s", indicator)
						}
					}
				}
				return false, ""
			},
		},

		// SSRF Detection
		{
			ID:          "ssrf_internal_access",
			Type:        "server_side_request_forgery",
			Severity:    "high",
			Description: "Server-Side Request Forgery vulnerability",
			Remediation: "Implement URL validation and network access controls",
			Context:     []string{"api", "file"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Parse URL to extract query parameters only
				parsedURL, err := url.Parse(resp.RequestURL)
				if err != nil {
					return false, ""
				}

				// Only check SSRF in query parameters, not in host/base URL
				queryParams := parsedURL.Query()

				// SSRF payload patterns
				ssrfPatterns := []string{
					"localhost", "127.0.0.1", "::1", "0.0.0.0",
					"169.254.169.254", "metadata", "internal",
					"file://", "gopher://", "ftp://",
				}

				for paramName, paramValues := range queryParams {
					for _, paramValue := range paramValues {
						for _, pattern := range ssrfPatterns {
							if strings.Contains(strings.ToLower(paramValue), pattern) {
								// Check if response contains evidence of internal access
								body := strings.ToLower(resp.BodyPreview)
								if (resp.StatusCode == 200 && resp.BodySize > 0) &&
									(strings.Contains(body, "metadata") ||
										strings.Contains(body, "aws") ||
										strings.Contains(body, "gcp") ||
										strings.Contains(body, "azure") ||
										strings.Contains(body, "internal") ||
										len(resp.BodyPreview) > 500) { // Significant response
									return true, fmt.Sprintf("SSRF via parameter %s=%s", paramName, pattern)
								}
							}
						}
					}
				}
				return false, ""
			},
		},

		// Race Condition Detection
		{
			ID:              "race_condition_timing",
			Type:            "race_condition",
			Severity:        "medium",
			Description:     "Race condition vulnerability detected",
			Remediation:     "Implement proper locking mechanisms and atomic operations",
			Context:         []string{"auth", "api", "resource"},
			TimingSensitive: true,
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				// Check for potential race conditions in critical operations
				if method == "POST" || method == "PUT" || method == "DELETE" {
					critical_ops := []string{
						"transfer", "payment", "balance", "purchase",
						"register", "create", "delete", "update",
					}

					pathLower := strings.ToLower(path)
					for _, op := range critical_ops {
						if strings.Contains(pathLower, op) {
							// Fast response might indicate lack of proper locking
							if resp.Duration < 100*time.Millisecond && resp.StatusCode == 200 {
								return true, fmt.Sprintf("Potentially unsafe %s operation with fast response time", op)
							}
						}
					}
				}
				return false, ""
			},
		},

		// Modern Command Injection
		{
			ID:          "command_injection",
			Type:        "command_injection",
			Severity:    "critical",
			Description: "Command injection vulnerability detected",
			Remediation: "Use parameterized commands and input validation",
			Context:     []string{"api", "file", "admin"},
			Check: func(path, method string, resp *utils.HTTPResponse, ctx *DetectionContext) (bool, string) {
				body := resp.BodyPreview

				// Command injection indicators - ONLY specific command outputs, not generic words
				cmdIndicators := []string{
					"uid=", "gid=", "root:x:", "/bin/bash", "cmd.exe",
					"Microsoft Windows", "Linux version", "Darwin Kernel",
					"total ", "drwxr-xr-x", "-rw-r--r--", // ls -la output
					"PING ", "ttl=", "bytes from", // ping output
					"Active connections", "Proto ", "Local Address", // netstat output
					"inet addr:", "UP BROADCAST", "RX packets", // ifconfig output
					"PID TTY", "TIME CMD", // ps output
					"Volume Serial Number", "Directory of C:\\", // Windows dir
					"PATH=", "USER=", "HOME=", // environment variables
				}

				for _, indicator := range cmdIndicators {
					if strings.Contains(body, indicator) {
						return true, fmt.Sprintf("Command injection evidence: %s", indicator)
					}
				}

				return false, ""
			},
		},
	}
}

// isInDangerousContext checks if the payload reflection is in exploitable context
func isInDangerousContext(body, payload string) bool {
	// Check if payload appears in HTML context (not just JSON data)
	bodyLower := strings.ToLower(body)
	payloadLower := strings.ToLower(payload)

	// If it's in a script tag or HTML attribute, it's likely XSS
	dangerousContexts := []string{
		"<script", "javascript:", "onload=", "onerror=",
		"<img", "<svg", "<iframe", "onclick=", "onmouseover=",
	}

	for _, context := range dangerousContexts {
		if strings.Contains(bodyLower, context) && strings.Contains(bodyLower, payloadLower) {
			return true
		}
	}

	// If it's just in JSON data like {"search": "<script>"}, it's probably not exploitable
	if strings.Contains(bodyLower, "\""+payloadLower+"\"") ||
		strings.Contains(bodyLower, "'"+payloadLower+"'") {
		return false
	}

	return true
}

// Utility functions
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
