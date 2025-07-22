package report

import (
	"fmt"

	"github.com/ajkula/cyberraven/pkg/reporting"
)

// ConsoleDisplay handles all console display operations
type ConsoleDisplay struct {
	formatter *ConsoleFormatter
}

// NewConsoleDisplay creates a new console display handler
func NewConsoleDisplay(formatter *ConsoleFormatter) *ConsoleDisplay {
	return &ConsoleDisplay{
		formatter: formatter,
	}
}

// DisplayReportSummary shows a summary of the generated report
func (d *ConsoleDisplay) DisplayReportSummary(reportData *reporting.ReportData) {
	fmt.Println()
	d.formatter.PrintSectionHeader("📋 REPORT ANALYSIS SUMMARY")

	// Executive summary
	exec := reportData.ExecutiveSummary
	fmt.Printf("Overall Risk Level: %s\n", exec.OverallRiskLevel)
	fmt.Printf("Security Score: %d/100\n", exec.SecurityScore)
	fmt.Printf("Compliance Score: %d/100\n", exec.ComplianceScore)
	fmt.Printf("Total Issues: %d\n", exec.TotalIssuesFound)

	if exec.TotalIssuesFound > 0 {
		fmt.Printf("Issue Breakdown:\n")
		if exec.CriticalIssues > 0 {
			d.formatter.PrintError(fmt.Sprintf("  Critical: %d", exec.CriticalIssues))
		}
		if reportData.SessionData.HighCount > 0 {
			d.formatter.PrintWarning(fmt.Sprintf("  High: %d", reportData.SessionData.HighCount))
		}
		if reportData.SessionData.MediumCount > 0 {
			d.formatter.PrintInfo(fmt.Sprintf("  Medium: %d", reportData.SessionData.MediumCount))
		}
		if reportData.SessionData.LowCount > 0 {
			fmt.Printf("  Low: %d\n", reportData.SessionData.LowCount)
		}
	}

	// Performance metrics
	perf := reportData.PerformanceMetrics
	fmt.Printf("Performance: %.2f req/sec, %.2f%% error rate\n",
		perf.RequestsPerSecond, perf.ErrorRate)

	// Recommendations
	fmt.Printf("Recommendations: %d items\n", len(reportData.Recommendations))

	fmt.Println()
}

// DisplayGenerationProgress shows progress information during report generation
func (d *ConsoleDisplay) DisplayGenerationProgress(sessionID string, current, total int) {
	d.formatter.PrintInfo(fmt.Sprintf("Generating report for session %s (%d/%d)...",
		sessionID, current, total))
}

// DisplayGenerationSuccess shows successful report generation
func (d *ConsoleDisplay) DisplayGenerationSuccess(sessionID string) {
	d.formatter.PrintSuccess(fmt.Sprintf("Report generated for session %s", sessionID))
}

// DisplayGenerationError shows report generation error
func (d *ConsoleDisplay) DisplayGenerationError(sessionID string, err error) {
	d.formatter.PrintError(fmt.Sprintf("Failed to generate report for session %s: %v",
		sessionID, err))
}

// DisplaySummary displays the final summary of report generation
func (d *ConsoleDisplay) DisplaySummary(resultsCount int, outputDir string, formats []string) {
	d.formatter.PrintSectionHeader("📊 REPORT GENERATION SUMMARY")
	fmt.Printf("Sessions processed: %d\n", resultsCount)
	fmt.Printf("Output directory: %s\n", outputDir)
	fmt.Printf("Formats generated: %s\n", formats)
	d.formatter.PrintSuccess("Report generation completed successfully!")
}
