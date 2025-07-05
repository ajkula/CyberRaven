package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
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
	if len(reportData.VulnerabilityAnalysis.TopIssues) > 0 {
		sb.WriteString("VULNERABILITY FINDINGS\n")
		sb.WriteString("──────────────────────\n")

		for i, vuln := range reportData.VulnerabilityAnalysis.TopIssues {
			sb.WriteString(fmt.Sprintf("%d. %s [%s]\n", i+1, vuln.Description, strings.ToUpper(vuln.Severity)))
			sb.WriteString(fmt.Sprintf("   Endpoint: %s %s\n", vuln.Method, vuln.Endpoint))
			sb.WriteString(fmt.Sprintf("   Risk Score: %d/100\n", vuln.RiskScore))
			sb.WriteString(fmt.Sprintf("   Evidence: %s\n", vuln.Evidence))
			sb.WriteString(fmt.Sprintf("   Remediation: %s\n", vuln.Remediation))
			sb.WriteString("\n")
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

// initializeTemplate initializes the HTML template for report generation
func (rg *ReportGenerator) initializeTemplate() error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberRaven Security Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.3em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        
        .header .meta {
            font-size: 1.1em;
            opacity: 0.8;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .executive-summary {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #3498db;
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .metric-label {
            font-size: 0.9em;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .risk-level {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 25px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .risk-critical { background-color: #e74c3c; }
        .risk-high { background-color: #e67e22; }
        .risk-medium { background-color: #f39c12; }
        .risk-low { background-color: #f1c40f; color: #2c3e50; }
        .risk-minimal { background-color: #27ae60; }
        
        .vulnerability-list {
            margin: 20px 0;
        }
        
        .vulnerability-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid #e74c3c;
        }
        
        .vulnerability-item.medium { border-left-color: #f39c12; }
        .vulnerability-item.low { border-left-color: #f1c40f; }
        
        .vulnerability-title {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .vulnerability-details {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .recommendations {
            margin: 20px 0;
        }
        
        .recommendation-item {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #3498db;
        }
        
        .recommendation-title {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .actions-list {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .score-bar {
            background: #ecf0f1;
            height: 20px;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .score-fill {
            height: 100%;
            background: linear-gradient(90deg, #e74c3c 0%, #f39c12 50%, #27ae60 100%);
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CYBERRAVEN 🐦‍</h1>
            <div class="subtitle">Security Assessment Report</div>
            <div class="meta">
                Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} | 
                Session: {{.SessionData.SessionID}} | 
                Target: {{.SessionData.Target.BaseURL}}
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="executive-summary">
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">{{.ExecutiveSummary.SecurityScore}}/100</div>
                            <div class="metric-label">Security Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{{.ExecutiveSummary.TotalIssuesFound}}</div>
                            <div class="metric-label">Issues Found</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{{printf "%.1f" .ExecutiveSummary.TestCoverage}}%</div>
                            <div class="metric-label">Test Coverage</div>
                        </div>
                    </div>
                    
                    <p><strong>Overall Risk Level:</strong> 
                        <span class="risk-level risk-{{.ExecutiveSummary.OverallRiskLevel | lower}}">
                            {{.ExecutiveSummary.OverallRiskLevel}}
                        </span>
                    </p>
                    
                    {{if gt .ExecutiveSummary.TotalIssuesFound 0}}
                    <p style="margin-top: 15px;"><strong>Issue Breakdown:</strong></p>
                    <ul style="margin-left: 20px;">
                        {{if gt .ExecutiveSummary.CriticalIssues 0}}<li>Critical: {{.ExecutiveSummary.CriticalIssues}}</li>{{end}}
                        {{if gt .SessionData.HighCount 0}}<li>High: {{.SessionData.HighCount}}</li>{{end}}
                        {{if gt .SessionData.MediumCount 0}}<li>Medium: {{.SessionData.MediumCount}}</li>{{end}}
                        {{if gt .SessionData.LowCount 0}}<li>Low: {{.SessionData.LowCount}}</li>{{end}}
                    </ul>
                    {{end}}
                </div>
            </div>
            
            <!-- Vulnerability Findings -->
            {{if .VulnerabilityAnalysis.TopIssues}}
            <div class="section">
                <h2>Vulnerability Findings</h2>
                <div class="vulnerability-list">
                    {{range .VulnerabilityAnalysis.TopIssues}}
                    <div class="vulnerability-item {{.Severity}}">
                        <div class="vulnerability-title">{{.Description}} [{{.Severity | title}}]</div>
                        <div class="vulnerability-details">
                            <p><strong>Endpoint:</strong> {{.Method}} {{.Endpoint}}</p>
                            <p><strong>Risk Score:</strong> {{.RiskScore}}/100</p>
                            <p><strong>Evidence:</strong> {{.Evidence}}</p>
                            <p><strong>Remediation:</strong> {{.Remediation}}</p>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <!-- Recommendations -->
            {{if .Recommendations}}
            <div class="section">
                <h2>Security Recommendations</h2>
                <div class="recommendations">
                    {{range .Recommendations}}
                    <div class="recommendation-item">
                        <div class="recommendation-title">{{.Title}} [{{.Priority | title}} Priority]</div>
                        <p>{{.Description}}</p>
                        <p><strong>Estimated Effort:</strong> {{.EstimatedEffort}}</p>
                        {{if .Actions}}
                        <p><strong>Actions:</strong></p>
                        <ul class="actions-list">
                            {{range .Actions}}<li>{{.}}</li>{{end}}
                        </ul>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <!-- Performance Metrics -->
            <div class="section">
                <h2>Performance Metrics</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{{.PerformanceMetrics.TotalRequestsSent}}</div>
                        <div class="metric-label">Total Requests</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{printf "%.2f" .PerformanceMetrics.RequestsPerSecond}}</div>
                        <div class="metric-label">Requests/Second</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{.PerformanceMetrics.AverageResponseTime.Round 1000000}}</div>
                        <div class="metric-label">Avg Response Time</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{printf "%.2f" .PerformanceMetrics.ErrorRate}}%</div>
                        <div class="metric-label">Error Rate</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Report generated by CyberRaven v{{.CyberRavenVersion}} - Security Assessment Tool
        </div>
    </div>
</body>
</html>`

	// Parse template with custom functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"title": strings.Title,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	rg.template = tmpl
	return nil
}
