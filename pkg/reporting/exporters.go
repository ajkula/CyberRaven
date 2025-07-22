package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// exportJSON exports the report as a JSON file
func (rg *ReportGenerator) exportJSON(reportData *ReportData, outputDir, sessionID string) error {
	filename := fmt.Sprintf("cyberraven_report_%s.json", sessionID)
	filepath := filepath.Join(outputDir, filename)

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// exportHTML exports the report as an HTML file
func (rg *ReportGenerator) exportHTML(reportData *ReportData, outputDir, sessionID string) error {
	filename := fmt.Sprintf("cyberraven_report_%s.html", sessionID)
	filepath := filepath.Join(outputDir, filename)

	// Create HTML file
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := rg.template.Execute(file, reportData); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

// exportText exports the report as a plain text file
func (rg *ReportGenerator) exportText(reportData *ReportData, outputDir, sessionID string) error {
	filename := fmt.Sprintf("cyberraven_report_%s.txt", sessionID)
	filepath := filepath.Join(outputDir, filename)

	// Create text file
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create text file: %w", err)
	}
	defer file.Close()

	// Write text report
	content := rg.generateTextReport(reportData)
	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write text file: %w", err)
	}

	return nil
}

// generateTextReport creates a formatted text report
func (rg *ReportGenerator) generateTextReport(reportData *ReportData) string {
	var sb strings.Builder

	// Header
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                           CYBERRAVEN                              \n")
	sb.WriteString("                  SECURITY ASSESSMENT REPORT                      \n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n\n")

	// Report metadata
	sb.WriteString(fmt.Sprintf("Generated: %s\n", reportData.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Session ID: %s\n", reportData.SessionData.SessionID))
	sb.WriteString(fmt.Sprintf("Target: %s\n", reportData.SessionData.Target.BaseURL))
	sb.WriteString(fmt.Sprintf("Duration: %v\n", reportData.SessionData.Duration.Round(time.Millisecond)))
	sb.WriteString("\n")

	// Executive Summary
	sb.WriteString("EXECUTIVE SUMMARY\n")
	sb.WriteString("─────────────────\n")
	sb.WriteString(fmt.Sprintf("Overall Risk Level: %s\n", reportData.ExecutiveSummary.OverallRiskLevel))
	sb.WriteString(fmt.Sprintf("Security Score: %d/100\n", reportData.ExecutiveSummary.SecurityScore))
	sb.WriteString(fmt.Sprintf("Compliance Score: %d/100\n", reportData.ExecutiveSummary.ComplianceScore))
	sb.WriteString(fmt.Sprintf("Total Issues Found: %d\n", reportData.ExecutiveSummary.TotalIssuesFound))

	if reportData.ExecutiveSummary.TotalIssuesFound > 0 {
		sb.WriteString("\nIssue Breakdown:\n")
		if reportData.ExecutiveSummary.CriticalIssues > 0 {
			sb.WriteString(fmt.Sprintf("  Critical: %d\n", reportData.ExecutiveSummary.CriticalIssues))
		}
		if reportData.SessionData.HighCount > 0 {
			sb.WriteString(fmt.Sprintf("  High: %d\n", reportData.SessionData.HighCount))
		}
		if reportData.SessionData.MediumCount > 0 {
			sb.WriteString(fmt.Sprintf("  Medium: %d\n", reportData.SessionData.MediumCount))
		}
		if reportData.SessionData.LowCount > 0 {
			sb.WriteString(fmt.Sprintf("  Low: %d\n", reportData.SessionData.LowCount))
		}
	}
	sb.WriteString("\n")

	// Performance Metrics
	sb.WriteString("PERFORMANCE METRICS\n")
	sb.WriteString("───────────────────\n")
	sb.WriteString(fmt.Sprintf("Total Requests: %d\n", reportData.PerformanceMetrics.TotalRequestsSent))
	sb.WriteString(fmt.Sprintf("Requests/Second: %.2f\n", reportData.PerformanceMetrics.RequestsPerSecond))
	sb.WriteString(fmt.Sprintf("Average Response Time: %v\n", reportData.PerformanceMetrics.AverageResponseTime.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("Error Rate: %.2f%%\n", reportData.PerformanceMetrics.ErrorRate))
	sb.WriteString(fmt.Sprintf("Timeout Rate: %.2f%%\n", reportData.PerformanceMetrics.TimeoutRate))
	sb.WriteString("\n")

	// API Enumeration Results
	if reportData.SessionData.APIEnumeration != nil {
		api := reportData.SessionData.APIEnumeration
		sb.WriteString("API ENUMERATION RESULTS\n")
		sb.WriteString("───────────────────────\n")
		sb.WriteString(fmt.Sprintf("Endpoints Tested: %d\n", api.TestedEndpoints))
		sb.WriteString(fmt.Sprintf("Endpoints Found: %d\n", len(api.FoundEndpoints)))
		sb.WriteString(fmt.Sprintf("Success Rate: %.1f%%\n", api.SuccessRate))
		sb.WriteString("\n")

		if len(api.FoundEndpoints) > 0 {
			sb.WriteString("Found Endpoints:\n")
			for _, endpoint := range api.FoundEndpoints {
				sb.WriteString(fmt.Sprintf("  %d %s %s (Security Score: %d/100)\n",
					endpoint.StatusCode, endpoint.Method, endpoint.Path, endpoint.SecurityScore))
			}
			sb.WriteString("\n")
		}
	}

	// Vulnerabilities
	if len(reportData.VulnerabilityAnalysis.ModuleAnalysis) > 0 {
		sb.WriteString("VULNERABILITY FINDINGS BY MODULE\n")
		sb.WriteString("────────────────────────────────\n")

		for _, module := range reportData.VulnerabilityAnalysis.ModuleAnalysis {
			if len(module.Vulnerabilities) > 0 {
				sb.WriteString(fmt.Sprintf("\n%s MODULE (%d vulnerabilities)\n",
					strings.ToUpper(module.ModuleName), len(module.Vulnerabilities)))
				sb.WriteString(strings.Repeat("─", len(module.ModuleName)+20) + "\n")

				for i, vuln := range module.Vulnerabilities {
					sb.WriteString(fmt.Sprintf("%d. %s [%s]\n",
						i+1, vuln.Description, strings.ToUpper(vuln.Severity)))
					sb.WriteString(fmt.Sprintf("   Endpoint: %s %s\n", vuln.Method, vuln.Endpoint))
					sb.WriteString(fmt.Sprintf("   Risk Score: %d/100\n", vuln.RiskScore))
					sb.WriteString(fmt.Sprintf("   Evidence: %s\n", vuln.Evidence))
					sb.WriteString(fmt.Sprintf("   Remediation: %s\n", vuln.Remediation))
					sb.WriteString("\n")
				}
			}
		}
	}

	// Recommendations
	if len(reportData.Recommendations) > 0 {
		sb.WriteString("SECURITY RECOMMENDATIONS\n")
		sb.WriteString("────────────────────────\n")

		for i, rec := range reportData.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s [%s Priority]\n", i+1, rec.Title, strings.ToUpper(rec.Priority)))
			sb.WriteString(fmt.Sprintf("   Category: %s\n", rec.Category))
			sb.WriteString(fmt.Sprintf("   Description: %s\n", rec.Description))
			sb.WriteString(fmt.Sprintf("   Estimated Effort: %s\n", rec.EstimatedEffort))

			if len(rec.Actions) > 0 {
				sb.WriteString("   Actions:\n")
				for _, action := range rec.Actions {
					sb.WriteString(fmt.Sprintf("     • %s\n", action))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Footer
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n")
	sb.WriteString("Report generated by CyberRaven v1.0.0 - Professional Security Assessment Tool\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n")

	return sb.String()
}
