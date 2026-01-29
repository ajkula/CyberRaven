// Package reporting implements report generation for CyberRaven
// File: pkg/reporting/generator.go
package reporting

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/config"
)

// ReportGenerator handles the generation of security assessment reports
type ReportGenerator struct {
	config   *config.ReportsConfig
	template *template.Template
}

// ReportData represents the data structure for report generation
type ReportData struct {
	// Meta information
	GeneratedAt       time.Time `json:"generated_at"`
	CyberRavenVersion string    `json:"cyberraven_version"`

	// Executive Summary
	ExecutiveSummary ExecutiveSummary `json:"executive_summary"`

	// Attack session data
	SessionData *attack.AttackResult `json:"session_data"`

	// Processed vulnerability data
	VulnerabilityAnalysis VulnerabilityAnalysis `json:"vulnerability_analysis"`

	// Performance metrics
	PerformanceMetrics PerformanceMetrics `json:"performance_metrics"`

	// Recommendations
	Recommendations []Recommendation `json:"recommendations"`
}

// ExecutiveSummary provides high-level assessment results
type ExecutiveSummary struct {
	OverallRiskLevel   string  `json:"overall_risk_level"`
	SecurityScore      int     `json:"security_score"`   // 0-100
	ComplianceScore    int     `json:"compliance_score"` // 0-100
	TotalIssuesFound   int     `json:"total_issues_found"`
	CriticalIssues     int     `json:"critical_issues"`
	HighRiskIssues     int     `json:"high_risk_issues"`
	TestCoverage       float64 `json:"test_coverage"` // Percentage of tests completed
	RecommendedActions int     `json:"recommended_actions"`
}

// VulnerabilityAnalysis provides detailed vulnerability breakdown
type VulnerabilityAnalysis struct {
	ByCategory     map[string]int                         `json:"by_category"`
	BySeverity     map[string]int                         `json:"by_severity"`
	TopIssues      []VulnerabilityDetail                  `json:"top_issues"`
	TrendData      []VulnerabilityTrend                   `json:"trend_data"`
	ModuleAnalysis map[string]ModuleVulnerabilityAnalysis `json:"module_analysis"`
}

type ModuleVulnerabilityAnalysis struct {
	ModuleName        string                `json:"module_name"`
	TestsExecuted     int                   `json:"tests_executed"`
	VulnCount         int                   `json:"vuln_count"`
	HighestSeverity   string                `json:"highest_severity"`
	Vulnerabilities   []VulnerabilityDetail `json:"vulnerabilities"`
	TestDuration      time.Duration         `json:"test_duration"`
	RequestsPerSecond float64               `json:"requests_per_second"`
}

// VulnerabilityDetail provides enhanced vulnerability information
type VulnerabilityDetail struct {
	api.VulnerabilityFinding
	RiskScore    int      `json:"risk_score"` // 0-100
	CVSSScore    string   `json:"cvss_score"` // If applicable
	References   []string `json:"references"` // External references
	AffectedURLs []string `json:"affected_urls"`
}

// VulnerabilityTrend represents vulnerability trends over time
type VulnerabilityTrend struct {
	Category  string    `json:"category"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// PerformanceMetrics provides testing performance data
type PerformanceMetrics struct {
	TotalRequestsSent     int64         `json:"total_requests_sent"`
	AverageResponseTime   time.Duration `json:"average_response_time"`
	RequestsPerSecond     float64       `json:"requests_per_second"`
	ErrorRate             float64       `json:"error_rate"`
	TimeoutRate           float64       `json:"timeout_rate"`
	TestDuration          time.Duration `json:"test_duration"`
	ConcurrentConnections int           `json:"concurrent_connections"`
}

// Recommendation provides actionable security recommendations
type Recommendation struct {
	Priority        string   `json:"priority"` // high, medium, low
	Category        string   `json:"category"` // security, performance, compliance
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Actions         []string `json:"actions"`
	References      []string `json:"references"`
	EstimatedEffort string   `json:"estimated_effort"`
}

// NewReportGenerator creates a new report generator instance
func NewReportGenerator(reportsConfig *config.ReportsConfig) (*ReportGenerator, error) {
	generator := &ReportGenerator{
		config: reportsConfig,
	}

	// Initialize HTML template
	if err := generator.initializeTemplate(); err != nil {
		return nil, fmt.Errorf("failed to initialize template: %w", err)
	}

	return generator, nil
}

// GenerateReport creates a comprehensive security assessment report
func (rg *ReportGenerator) GenerateReport(sessionResult *attack.AttackResult) (*ReportData, error) {
	// Create report data structure
	reportData := &ReportData{
		GeneratedAt:       time.Now(),
		CyberRavenVersion: "1.0.0",
		SessionData:       sessionResult,
	}

	// Generate executive summary
	reportData.ExecutiveSummary = rg.generateExecutiveSummary(sessionResult)

	// Analyze vulnerabilities
	reportData.VulnerabilityAnalysis = rg.analyzeVulnerabilities(sessionResult)

	// Calculate performance metrics
	reportData.PerformanceMetrics = rg.calculatePerformanceMetrics(sessionResult)

	// Generate recommendations
	reportData.Recommendations = rg.generateRecommendations(sessionResult)

	return reportData, nil
}

// ExportReport exports the report in the specified formats
func (rg *ReportGenerator) ExportReport(reportData *ReportData, outputDir string) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	sessionID := reportData.SessionData.SessionID

	// Export in configured formats
	for _, format := range rg.config.Formats {
		switch strings.ToLower(format) {
		case "json":
			if err := rg.exportJSON(reportData, outputDir, sessionID); err != nil {
				return fmt.Errorf("failed to export JSON: %w", err)
			}
		case "html":
			if err := rg.exportHTML(reportData, outputDir, sessionID); err != nil {
				return fmt.Errorf("failed to export HTML: %w", err)
			}
		case "txt":
			if err := rg.exportText(reportData, outputDir, sessionID); err != nil {
				return fmt.Errorf("failed to export text: %w", err)
			}
		default:
			return fmt.Errorf("unsupported export format: %s", format)
		}
	}

	return nil
}

// generateExecutiveSummary creates the executive summary
func (rg *ReportGenerator) generateExecutiveSummary(result *attack.AttackResult) ExecutiveSummary {
	summary := ExecutiveSummary{
		TotalIssuesFound: result.TotalVulnerabilities,
		CriticalIssues:   result.CriticalCount,
		HighRiskIssues:   result.HighCount,
	}

	// Calculate overall risk level based on actual exploitability
	if summary.SecurityScore < 30 {
		summary.OverallRiskLevel = "CRITICAL"
	} else if summary.SecurityScore < 50 {
		summary.OverallRiskLevel = "HIGH"
	} else if summary.SecurityScore < 70 {
		summary.OverallRiskLevel = "MEDIUM"
	} else if summary.SecurityScore < 90 {
		summary.OverallRiskLevel = "LOW"
	} else {
		summary.OverallRiskLevel = "MINIMAL"
	}

	// Calculate realistic security score
	summary.SecurityScore = rg.calculateModularSecurityScore(result)

	// Calculate compliance score (based on security headers and best practices)
	summary.ComplianceScore = rg.calculateComplianceScore(result)

	// Calculate test coverage
	if result.APIEnumeration != nil {
		summary.TestCoverage = (float64(len(result.APIEnumeration.FoundEndpoints)) / float64(result.APIEnumeration.TestedEndpoints)) * 100
	}

	// Count recommended actions (realistic number)
	summary.RecommendedActions = min(result.TotalVulnerabilities, 10) + 2

	return summary
}

// calculatePerformanceMetrics computes performance-related metrics
func (rg *ReportGenerator) calculatePerformanceMetrics(result *attack.AttackResult) PerformanceMetrics {
	metrics := PerformanceMetrics{
		TestDuration: result.Duration,
	}

	if result.APIEnumeration != nil {
		api := result.APIEnumeration

		metrics.TotalRequestsSent = int64(api.TestedEndpoints)
		metrics.RequestsPerSecond = api.RequestsPerSecond

		// Calculate error rate
		totalErrors := len(api.ErroredEndpoints)
		if api.TestedEndpoints > 0 {
			metrics.ErrorRate = float64(totalErrors) / float64(api.TestedEndpoints) * 100
		}

		// Calculate average response time
		if len(api.FoundEndpoints) > 0 {
			var totalTime time.Duration
			for _, endpoint := range api.FoundEndpoints {
				totalTime += endpoint.ResponseTime
			}
			metrics.AverageResponseTime = totalTime / time.Duration(len(api.FoundEndpoints))
		}

		// Calculate timeout rate
		timeoutCount := 0
		for _, error := range api.ErroredEndpoints {
			if error.ErrorType == "timeout" {
				timeoutCount++
			}
		}
		if api.TestedEndpoints > 0 {
			metrics.TimeoutRate = float64(timeoutCount) / float64(api.TestedEndpoints) * 100
		}
	}

	return metrics
}

// generateRecommendations creates actionable security recommendations
func (rg *ReportGenerator) generateRecommendations(result *attack.AttackResult) []Recommendation {
	var recommendations []Recommendation

	// Security headers recommendation
	if result.APIEnumeration != nil {
		hasSecurityHeaderIssues := false
		for _, vuln := range result.APIEnumeration.Vulnerabilities {
			if vuln.Type == "missing_security_headers" {
				hasSecurityHeaderIssues = true
				break
			}
		}

		if hasSecurityHeaderIssues {
			recommendations = append(recommendations, Recommendation{
				Priority:    "high",
				Category:    "security",
				Title:       "Implement Security Headers",
				Description: "Critical security headers are missing from HTTP responses",
				Actions: []string{
					"Add X-Frame-Options: DENY or SAMEORIGIN",
					"Implement Content-Security-Policy",
					"Add X-XSS-Protection: 1; mode=block",
					"Set X-Content-Type-Options: nosniff",
					"Configure Strict-Transport-Security",
				},
				References: []string{
					"https://owasp.org/www-project-secure-headers/",
					"https://securityheaders.com/",
				},
				EstimatedEffort: "2-4 hours",
			})
		}
	}

	// Debug endpoint recommendation
	if result.APIEnumeration != nil {
		hasDebugEndpoints := false
		for _, vuln := range result.APIEnumeration.Vulnerabilities {
			if vuln.Type == "debug_endpoint" {
				hasDebugEndpoints = true
				break
			}
		}

		if hasDebugEndpoints {
			recommendations = append(recommendations, Recommendation{
				Priority:    "critical",
				Category:    "security",
				Title:       "Remove Debug Endpoints",
				Description: "Debug endpoints are accessible in production environment",
				Actions: []string{
					"Remove debug endpoints from production builds",
					"Implement environment-based endpoint filtering",
					"Add proper access controls for development endpoints",
					"Review deployment procedures",
				},
				References: []string{
					"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
				},
				EstimatedEffort: "1-2 hours",
			})
		}
	}

	// General security recommendations
	recommendations = append(recommendations, Recommendation{
		Priority:    "medium",
		Category:    "security",
		Title:       "Regular Security Assessments",
		Description: "Establish regular security testing procedures",
		Actions: []string{
			"Schedule monthly automated security scans",
			"Implement continuous security monitoring",
			"Establish penetration testing procedures",
			"Create security incident response plan",
		},
		References: []string{
			"https://owasp.org/www-community/Application_Security_Program",
		},
		EstimatedEffort: "8-16 hours",
	})

	return recommendations
}

// Helper functions

func (rg *ReportGenerator) calculateComplianceScore(result *attack.AttackResult) int {
	score := 100

	if result.APIEnumeration != nil {
		// Deduct points for each endpoint without proper security score
		securityIssues := 0
		for _, endpoint := range result.APIEnumeration.FoundEndpoints {
			if endpoint.SecurityScore < 80 {
				securityIssues++
			}
		}

		if len(result.APIEnumeration.FoundEndpoints) > 0 {
			penalty := (securityIssues * 20) / len(result.APIEnumeration.FoundEndpoints)
			score = max(0, score-penalty)
		}
	}

	return score
}

func (rg *ReportGenerator) calculateRiskScore(vuln api.VulnerabilityFinding) int {
	baseScore := 0

	switch strings.ToLower(vuln.Severity) {
	case "critical":
		baseScore = 90
	case "high":
		baseScore = 70
	case "medium":
		baseScore = 50
	case "low":
		baseScore = 30
	default:
		baseScore = 10
	}

	// Adjust based on vulnerability type
	switch vuln.Type {
	case "debug_endpoint":
		baseScore += 10
	case "version_disclosure":
		baseScore += 5
	case "missing_security_headers":
		baseScore += 15
	case "information_disclosure":
		baseScore += 20
	}

	return min(100, baseScore)
}

func (rg *ReportGenerator) getVulnerabilityReferences(vulnType string) []string {
	references := map[string][]string{
		"debug_endpoint": {
			"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
		},
		"missing_security_headers": {
			"https://owasp.org/www-project-secure-headers/",
			"https://securityheaders.com/",
		},
		"information_disclosure": {
			"https://owasp.org/www-community/Improper_Error_Handling",
		},
		"version_disclosure": {
			"https://owasp.org/www-community/Information_Exposure",
		},
	}

	if refs, exists := references[vulnType]; exists {
		return refs
	}
	return []string{}
}

// Utility functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================
// KILL CHAIN REPORT TYPES AND METHODS
// ============================================================

// KillChainReportData represents data for kill chain report generation
type KillChainReportData struct {
	// Meta information
	GeneratedAt       time.Time `json:"generated_at"`
	CyberRavenVersion string    `json:"cyberraven_version"`

	// Kill Chain specific
	SessionID          string             `json:"session_id"`
	TLSStatus          string             `json:"tls_status"` // "compromised" | "secure"
	Progression        string             `json:"progression"` // Description of how far the chain went
	CompromiseMethod   string             `json:"compromise_method,omitempty"`

	// Phases
	Phases             []PhaseReportData  `json:"phases"`

	// Summary
	ExecutiveSummary   KillChainSummary   `json:"executive_summary"`

	// Recommendations
	Recommendations    []Recommendation   `json:"recommendations"`
}

// PhaseReportData represents a single phase in the kill chain report
type PhaseReportData struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	Duration      string    `json:"duration"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Findings      []FindingReportData `json:"findings"`
	VulnCount     int       `json:"vulnerability_count"`
	NextStep      string    `json:"next_step"` // Why we continue or stop
	Compromised   bool      `json:"compromised"`
}

// FindingReportData represents a single finding in the report
type FindingReportData struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"`
}

// KillChainSummary provides executive summary for kill chain results
type KillChainSummary struct {
	OverallRiskLevel      string  `json:"overall_risk_level"`
	TLSSecurityStatus     string  `json:"tls_security_status"`
	AttackChainCompleted  bool    `json:"attack_chain_completed"`
	TotalPhasesExecuted   int     `json:"total_phases_executed"`
	TotalVulnerabilities  int     `json:"total_vulnerabilities"`
	CriticalCount         int     `json:"critical_count"`
	HighCount             int     `json:"high_count"`
	MediumCount           int     `json:"medium_count"`
	LowCount              int     `json:"low_count"`
	SecurityScore         int     `json:"security_score"` // 0-100
	RecommendedActions    int     `json:"recommended_actions"`
}

// GenerateKillChainReport creates a report from kill chain results
func (rg *ReportGenerator) GenerateKillChainReport(kcResult *attack.KillChainResult) (*KillChainReportData, error) {
	reportData := &KillChainReportData{
		GeneratedAt:       time.Now(),
		CyberRavenVersion: "1.0.0",
		SessionID:         kcResult.SessionID,
		TLSStatus:         kcResult.TLSStatus,
		Progression:       kcResult.Progression,
		CompromiseMethod:  kcResult.CompromiseMethod,
		Phases:            make([]PhaseReportData, 0),
	}

	// Convert phases
	for _, phase := range kcResult.Phases {
		phaseReport := PhaseReportData{
			Name:        string(phase.Phase),
			Status:      string(phase.Status),
			Duration:    phase.Duration.String(),
			StartTime:   phase.StartTime,
			EndTime:     phase.EndTime,
			VulnCount:   phase.VulnCount,
			Compromised: phase.Compromised,
			Findings:    make([]FindingReportData, 0),
		}

		// Determine next step explanation
		if phase.CanContinue {
			phaseReport.NextStep = fmt.Sprintf("Continuing to phase: %s", phase.NextPhase)
		} else if phase.SkipReason != "" {
			phaseReport.NextStep = fmt.Sprintf("Stopped: %s", phase.SkipReason)
		} else {
			phaseReport.NextStep = "Phase completed - no further action"
		}

		// Convert findings
		for _, finding := range phase.Findings {
			phaseReport.Findings = append(phaseReport.Findings, FindingReportData{
				Type:        finding.Type,
				Severity:    finding.Severity,
				Title:       finding.Title,
				Description: finding.Description,
				Evidence:    finding.Evidence,
				Remediation: finding.Remediation,
				RiskScore:   rg.calculateFindingRiskScore(finding.Severity, finding.Type),
			})
		}

		reportData.Phases = append(reportData.Phases, phaseReport)
	}

	// Generate executive summary
	reportData.ExecutiveSummary = rg.generateKillChainSummary(kcResult)

	// Generate recommendations
	reportData.Recommendations = rg.generateKillChainRecommendations(kcResult)

	return reportData, nil
}

// generateKillChainSummary creates the executive summary for kill chain report
func (rg *ReportGenerator) generateKillChainSummary(result *attack.KillChainResult) KillChainSummary {
	summary := KillChainSummary{
		TotalPhasesExecuted:  len(result.Phases),
		TotalVulnerabilities: result.TotalVulnerabilities,
		CriticalCount:        result.CriticalCount,
		HighCount:            result.HighCount,
		MediumCount:          result.MediumCount,
		LowCount:             result.LowCount,
	}

	// Determine TLS security status
	if result.TLSStatus == "compromised" {
		summary.TLSSecurityStatus = "COMPROMISED - TLS protection bypassed"
		summary.AttackChainCompleted = len(result.Phases) > 1
	} else {
		summary.TLSSecurityStatus = "SECURE - TLS protection effective"
		summary.AttackChainCompleted = false
	}

	// Calculate security score
	summary.SecurityScore = rg.calculateKillChainSecurityScore(result)

	// Determine overall risk level based on score
	switch {
	case summary.SecurityScore < 20:
		summary.OverallRiskLevel = "CRITICAL"
	case summary.SecurityScore < 40:
		summary.OverallRiskLevel = "HIGH"
	case summary.SecurityScore < 60:
		summary.OverallRiskLevel = "MEDIUM"
	case summary.SecurityScore < 80:
		summary.OverallRiskLevel = "LOW"
	default:
		summary.OverallRiskLevel = "MINIMAL"
	}

	// Count recommended actions
	summary.RecommendedActions = min(result.TotalVulnerabilities, 10) + 2

	return summary
}

// calculateKillChainSecurityScore calculates security score for kill chain results
func (rg *ReportGenerator) calculateKillChainSecurityScore(result *attack.KillChainResult) int {
	score := 100

	// Major penalty if TLS was compromised
	if result.TLSStatus == "compromised" {
		score -= 40
	}

	// Penalties for vulnerabilities by severity
	score -= result.CriticalCount * 15
	score -= result.HighCount * 10
	score -= result.MediumCount * 5
	score -= result.LowCount * 2

	// Penalty for attack chain completion
	if len(result.Phases) > 1 {
		score -= 10 * (len(result.Phases) - 1)
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

// generateKillChainRecommendations creates recommendations based on kill chain results
func (rg *ReportGenerator) generateKillChainRecommendations(result *attack.KillChainResult) []Recommendation {
	var recommendations []Recommendation

	// TLS-specific recommendations if compromised
	if result.TLSStatus == "compromised" {
		recommendations = append(recommendations, Recommendation{
			Priority:    "critical",
			Category:    "security",
			Title:       "Fix TLS Configuration",
			Description: fmt.Sprintf("TLS was compromised via: %s", result.CompromiseMethod),
			Actions: []string{
				"Disable support for SSL 3.0, TLS 1.0, and TLS 1.1",
				"Configure server to only support TLS 1.2 and TLS 1.3",
				"Remove weak cipher suites (RC4, DES, export ciphers)",
				"Use certificates from trusted CAs only",
				"Implement certificate pinning where appropriate",
				"Enable HSTS with appropriate max-age",
			},
			References: []string{
				"https://www.ssllabs.com/ssltest/",
				"https://mozilla.github.io/server-side-tls/ssl-config-generator/",
			},
			EstimatedEffort: "4-8 hours",
		})
	} else {
		recommendations = append(recommendations, Recommendation{
			Priority:    "low",
			Category:    "security",
			Title:       "TLS Configuration Review",
			Description: "TLS protection was effective - maintain current configuration",
			Actions: []string{
				"Continue monitoring TLS configuration",
				"Schedule regular security assessments",
				"Stay updated on new TLS vulnerabilities",
			},
			References: []string{
				"https://www.ssllabs.com/ssltest/",
			},
			EstimatedEffort: "1-2 hours",
		})
	}

	// Add recommendations based on vulnerability counts
	if result.CriticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "critical",
			Category:    "security",
			Title:       "Address Critical Vulnerabilities Immediately",
			Description: fmt.Sprintf("%d critical vulnerabilities were discovered", result.CriticalCount),
			Actions: []string{
				"Review all critical findings in this report",
				"Implement fixes for critical vulnerabilities within 24 hours",
				"Consider taking affected systems offline until fixed",
				"Conduct incident response if exploitation is suspected",
			},
			References:      []string{},
			EstimatedEffort: "Varies - prioritize based on risk",
		})
	}

	// General security recommendations
	recommendations = append(recommendations, Recommendation{
		Priority:    "medium",
		Category:    "security",
		Title:       "Implement Defense in Depth",
		Description: "Multiple layers of security reduce risk of successful attacks",
		Actions: []string{
			"Implement Web Application Firewall (WAF)",
			"Enable intrusion detection/prevention systems",
			"Implement rate limiting and DDoS protection",
			"Set up security monitoring and alerting",
			"Conduct regular penetration testing",
		},
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/",
		},
		EstimatedEffort: "16-40 hours",
	})

	return recommendations
}

// calculateFindingRiskScore calculates risk score for a single finding
func (rg *ReportGenerator) calculateFindingRiskScore(severity, findingType string) int {
	baseScore := 0

	switch strings.ToLower(severity) {
	case "critical":
		baseScore = 90
	case "high":
		baseScore = 70
	case "medium":
		baseScore = 50
	case "low":
		baseScore = 30
	default:
		baseScore = 10
	}

	// Adjust based on type
	switch {
	case strings.Contains(findingType, "tls") || strings.Contains(findingType, "ssl"):
		baseScore += 10
	case strings.Contains(findingType, "injection"):
		baseScore += 15
	case strings.Contains(findingType, "auth"):
		baseScore += 10
	case strings.Contains(findingType, "escalation"):
		baseScore += 20
	}

	return min(100, baseScore)
}
