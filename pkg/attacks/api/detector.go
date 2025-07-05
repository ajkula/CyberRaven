package api

import (
	"fmt"
	"strings"

	"github.com/ajkula/cyberraven/pkg/utils"
)

// VulnerabilityDetector handles detection of security vulnerabilities
type VulnerabilityDetector struct{}

// NewVulnerabilityDetector creates a new vulnerability detector
func NewVulnerabilityDetector() *VulnerabilityDetector {
	return &VulnerabilityDetector{}
}

// DetectionRule represents a vulnerability detection rule
type DetectionRule struct {
	Type        string
	Severity    string
	Description string
	Remediation string
	Check       func(path, method string, resp *utils.HTTPResponse) (bool, string)
}

// AnalyzeResponse analyzes an HTTP response for security vulnerabilities
func (vd *VulnerabilityDetector) AnalyzeResponse(path, method string, resp *utils.HTTPResponse) []VulnerabilityFinding {
	var vulns []VulnerabilityFinding

	// Apply all detection rules
	for _, rule := range vd.getRules() {
		if detected, evidence := rule.Check(path, method, resp); detected {
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

// getRules returns all vulnerability detection rules
func (vd *VulnerabilityDetector) getRules() []DetectionRule {
	return []DetectionRule{
		{
			Type:        "debug_endpoint",
			Severity:    "medium",
			Description: "Debug endpoint accessible",
			Remediation: "Remove or restrict access to debug endpoints in production",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				if strings.Contains(strings.ToLower(path), "debug") && resp.StatusCode == 200 {
					return true, fmt.Sprintf("HTTP %d response on %s %s", resp.StatusCode, method, path)
				}
				return false, ""
			},
		},
		{
			Type:        "missing_security_headers",
			Severity:    "low",
			Description: "Missing X-Frame-Options header on sensitive endpoint",
			Remediation: "Add X-Frame-Options: DENY or SAMEORIGIN header",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				if vd.isSensitiveEndpoint(path) && resp.Header.Get("X-Frame-Options") == "" {
					return true, "X-Frame-Options header not found"
				}
				return false, ""
			},
		},
		{
			Type:        "idor",
			Severity:    "high",
			Description: "Insecure Direct Object Reference detected",
			Remediation: "Implement proper authorization checks and input validation",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				query := resp.Request.URL.RawQuery
				if (strings.Contains(query, "&id=") || strings.Contains(query, "&user=")) &&
					resp.StatusCode == 200 && vd.isResourceEndpoint(path) {
					return true, fmt.Sprintf("HTTP %d with duplicate ID parameters: %s", resp.StatusCode, query)
				}
				return false, ""
			},
		},
		{
			Type:        "method_override",
			Severity:    "medium",
			Description: "HTTP Method Override header accepted",
			Remediation: "Disable HTTP method override headers or implement strict validation",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				headers := []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}
				for _, header := range headers {
					if resp.Header.Get(header) != "" {
						return true, fmt.Sprintf("Server accepts %s header", header)
					}
				}
				return false, ""
			},
		},
		{
			Type:        "mass_assignment",
			Severity:    "high",
			Description: "Mass Assignment vulnerability - sensitive fields exposed",
			Remediation: "Implement field whitelisting and avoid exposing sensitive attributes",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				if method != "POST" && method != "PUT" && method != "PATCH" {
					return false, ""
				}
				if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
					return false, ""
				}

				bodyLower := strings.ToLower(resp.BodyPreview)
				sensitiveFields := []string{"admin", "role", "privilege", "permission", "password", "secret", "token"}
				for _, field := range sensitiveFields {
					if strings.Contains(bodyLower, fmt.Sprintf("\"%s\":", field)) {
						return true, fmt.Sprintf("Sensitive field '%s' found in JSON response", field)
					}
				}
				return false, ""
			},
		},
		{
			Type:        "access_control_bypass",
			Severity:    "critical",
			Description: "Access Control Bypass via parameter manipulation",
			Remediation: "Implement server-side authorization checks and validate all user inputs",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				query := resp.Request.URL.RawQuery
				if (strings.Contains(query, "admin=true") || strings.Contains(query, "role=admin")) &&
					resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return true, fmt.Sprintf("Success response with privilege escalation parameters: %s", query)
				}
				return false, ""
			},
		},
		{
			Type:        "access_control_bypass",
			Severity:    "high",
			Description: "Sensitive endpoint accessible without authentication",
			Remediation: "Implement proper authentication and authorization controls",
			Check: func(path, method string, resp *utils.HTTPResponse) (bool, string) {
				if vd.isSensitiveEndpoint(path) && resp.StatusCode == 200 {
					auth := resp.Request.Header.Get("Authorization")
					if !strings.Contains(auth, "Bearer") && !strings.Contains(auth, "Basic") {
						return true, "No Authorization header found on sensitive endpoint"
					}
				}
				return false, ""
			},
		},
	}
}

// isResourceEndpoint checks if endpoint represents a REST resource
func (vd *VulnerabilityDetector) isResourceEndpoint(path string) bool {
	resourcePatterns := []string{"users", "accounts", "messages", "files", "reports", "events"}
	lowerPath := strings.ToLower(path)
	for _, pattern := range resourcePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isSensitiveEndpoint checks if an endpoint is considered sensitive
func (vd *VulnerabilityDetector) isSensitiveEndpoint(path string) bool {
	sensitivePatterns := []string{"admin", "login", "auth", "config", "settings", "debug", "test", "management", "console"}
	lowerPath := strings.ToLower(path)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}
