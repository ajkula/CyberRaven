package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/reporting"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// Execute runs the report generation command
func Execute(cmd *cobra.Command, args []string) error {
	// Get command flags
	inputPath, _ := cmd.Flags().GetString("input")
	outputDir, _ := cmd.Flags().GetString("output")
	formats, _ := cmd.Flags().GetStringSlice("format")
	template, _ := cmd.Flags().GetString("template")
	verbose := viper.GetBool("verbose")
	noColor := viper.GetBool("no-color")

	// Validate input
	if inputPath == "" {
		return fmt.Errorf("input file or directory is required")
	}

	// Load attack results
	printInfo("Loading attack results...", noColor)
	attackResults, err := loadAttackResults(inputPath)
	if err != nil {
		return fmt.Errorf("failed to load attack results: %w", err)
	}

	if verbose {
		printInfo(fmt.Sprintf("Loaded %d attack session(s)", len(attackResults)), noColor)
	}

	// Create reports configuration
	reportsConfig := &config.ReportsConfig{
		Formats:        formats,
		OutputDir:      outputDir,
		Template:       template,
		IncludeLogs:    verbose,
		IncludeRawData: verbose,
		SeverityLevels: []string{"low", "medium", "high", "critical"},
	}

	// Generate reports for each attack session
	for i, attackResult := range attackResults {
		printInfo(fmt.Sprintf("Generating report for session %s (%d/%d)...",
			attackResult.SessionID, i+1, len(attackResults)), noColor)

		err := generateReport(attackResult, reportsConfig, verbose, noColor)
		if err != nil {
			printError(fmt.Sprintf("Failed to generate report for session %s: %v",
				attackResult.SessionID, err), noColor)
			continue
		}

		printSuccess(fmt.Sprintf("Report generated for session %s", attackResult.SessionID), noColor)
	}

	// Print summary
	printSectionHeader("📊 REPORT GENERATION SUMMARY", noColor)
	fmt.Printf("Sessions processed: %d\n", len(attackResults))
	fmt.Printf("Output directory: %s\n", outputDir)
	fmt.Printf("Formats generated: %s\n", strings.Join(formats, ", "))

	printSuccess("Report generation completed successfully!", noColor)
	return nil
}

// loadAttackResults loads attack results from file or directory
func loadAttackResults(inputPath string) ([]*attack.AttackResult, error) {
	var results []*attack.AttackResult

	// Check if input is file or directory
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, fmt.Errorf("input path does not exist: %w", err)
	}

	if info.IsDir() {
		// Load all JSON files from directory
		files, err := filepath.Glob(filepath.Join(inputPath, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("failed to list JSON files: %w", err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("no JSON files found in directory: %s", inputPath)
		}

		for _, file := range files {
			result, err := loadSingleAttackResult(file)
			if err != nil {
				// Skip invalid files but continue processing
				fmt.Printf("Warning: Failed to load %s: %v\n", file, err)
				continue
			}
			results = append(results, result)
		}
	} else {
		// Load single file
		result, err := loadSingleAttackResult(inputPath)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid attack results found")
	}

	return results, nil
}

// loadSingleAttackResult loads attack result from a single JSON file
func loadSingleAttackResult(filePath string) (*attack.AttackResult, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Unmarshal JSON
	var result attack.AttackResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Basic validation
	if result.SessionID == "" {
		return nil, fmt.Errorf("invalid attack result: missing session ID")
	}

	return &result, nil
}

// generateReport generates a complete report for an attack session
func generateReport(attackResult *attack.AttackResult, reportsConfig *config.ReportsConfig, verbose, noColor bool) error {
	// Create report generator
	generator, err := reporting.NewReportGenerator(reportsConfig)
	if err != nil {
		return fmt.Errorf("failed to create report generator: %w", err)
	}

	// Generate report data
	if verbose {
		printInfo("Analyzing attack results...", noColor)
	}

	reportData, err := generator.GenerateReport(attackResult)
	if err != nil {
		return fmt.Errorf("failed to generate report data: %w", err)
	}

	// Display report summary if verbose
	if verbose {
		displayReportSummary(reportData, noColor)
	}

	// Export report in requested formats
	if verbose {
		printInfo("Exporting report files...", noColor)
	}

	err = generator.ExportReport(reportData, reportsConfig.OutputDir)
	if err != nil {
		return fmt.Errorf("failed to export report: %w", err)
	}

	return nil
}

// displayReportSummary shows a summary of the generated report
func displayReportSummary(reportData *reporting.ReportData, noColor bool) {
	fmt.Println()
	printSectionHeader("📋 REPORT ANALYSIS SUMMARY", noColor)

	// Executive summary
	exec := reportData.ExecutiveSummary
	fmt.Printf("Overall Risk Level: %s\n", exec.OverallRiskLevel)
	fmt.Printf("Security Score: %d/100\n", exec.SecurityScore)
	fmt.Printf("Compliance Score: %d/100\n", exec.ComplianceScore)
	fmt.Printf("Total Issues: %d\n", exec.TotalIssuesFound)

	if exec.TotalIssuesFound > 0 {
		fmt.Printf("Issue Breakdown:\n")
		if exec.CriticalIssues > 0 {
			printError(fmt.Sprintf("  Critical: %d", exec.CriticalIssues), noColor)
		}
		if reportData.SessionData.HighCount > 0 {
			printWarning(fmt.Sprintf("  High: %d", reportData.SessionData.HighCount), noColor)
		}
		if reportData.SessionData.MediumCount > 0 {
			printInfo(fmt.Sprintf("  Medium: %d", reportData.SessionData.MediumCount), noColor)
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

// Output formatting functions

func printSectionHeader(title string, noColor bool) {
	if noColor {
		fmt.Printf("\n=== %s ===\n\n", title)
	} else {
		fmt.Printf("\n%s%s=== %s ===%s\n\n", ColorCyan, ColorBold, title, ColorReset)
	}
}

func printError(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorRed + ColorBold
	}
	fmt.Printf("%s[ERROR] %s%s\n", color, message, ColorReset)
}

func printSuccess(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorGreen + ColorBold
	}
	fmt.Printf("%s[SUCCESS] %s%s\n", color, message, ColorReset)
}

func printInfo(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorBlue
	}
	fmt.Printf("%s[INFO] %s%s\n", color, message, ColorReset)
}

func printWarning(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorYellow + ColorBold
	}
	fmt.Printf("%s[WARNING] %s%s\n", color, message, ColorReset)
}
