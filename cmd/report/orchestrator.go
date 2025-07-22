package report

import (
	"fmt"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/reporting"
)

// ReportOrchestrator coordinates the report generation process
type ReportOrchestrator struct {
	loader    *AttackResultsLoader
	validator *AttackResultValidator
	display   *ConsoleDisplay
	formatter *ConsoleFormatter
}

// NewReportOrchestrator creates a new report orchestrator
func NewReportOrchestrator(
	loader *AttackResultsLoader,
	validator *AttackResultValidator,
	display *ConsoleDisplay,
	formatter *ConsoleFormatter,
) *ReportOrchestrator {
	return &ReportOrchestrator{
		loader:    loader,
		validator: validator,
		display:   display,
		formatter: formatter,
	}
}

// GenerateReports orchestrates the complete report generation process
func (o *ReportOrchestrator) GenerateReports(
	inputPath string,
	reportsConfig *config.ReportsConfig,
	verbose bool,
) error {
	// Load attack results
	o.formatter.PrintInfo("Loading attack results...")
	attackResults, err := o.loader.LoadAttackResults(inputPath)
	if err != nil {
		return fmt.Errorf("failed to load attack results: %w", err)
	}

	if verbose {
		o.formatter.PrintInfo(fmt.Sprintf("Loaded %d attack session(s)", len(attackResults)))
	}

	// Validate attack results
	if err := o.validator.ValidateAttackResults(attackResults); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Generate reports for each attack session
	for i, attackResult := range attackResults {
		o.display.DisplayGenerationProgress(attackResult.SessionID, i+1, len(attackResults))

		err := o.generateSingleReport(attackResult, reportsConfig, verbose)
		if err != nil {
			o.display.DisplayGenerationError(attackResult.SessionID, err)
			continue
		}

		o.display.DisplayGenerationSuccess(attackResult.SessionID)
	}

	// Display final summary
	o.display.DisplaySummary(len(attackResults), reportsConfig.OutputDir, reportsConfig.Formats)

	return nil
}

// generateSingleReport generates a complete report for a single attack session
func (o *ReportOrchestrator) generateSingleReport(
	attackResult *attack.AttackResult,
	reportsConfig *config.ReportsConfig,
	verbose bool,
) error {
	// Create report generator
	generator, err := reporting.NewReportGenerator(reportsConfig)
	if err != nil {
		return fmt.Errorf("failed to create report generator: %w", err)
	}

	// Generate report data
	if verbose {
		o.formatter.PrintInfo("Analyzing attack results...")
	}

	reportData, err := generator.GenerateReport(attackResult)
	if err != nil {
		return fmt.Errorf("failed to generate report data: %w", err)
	}

	// Display report summary if verbose
	if verbose {
		o.display.DisplayReportSummary(reportData)
	}

	// Export report in requested formats
	if verbose {
		o.formatter.PrintInfo("Exporting report files...")
	}

	err = generator.ExportReport(reportData, reportsConfig.OutputDir)
	if err != nil {
		return fmt.Errorf("failed to export report: %w", err)
	}

	return nil
}

// CreateReportsConfig creates reports configuration from CLI parameters
func (o *ReportOrchestrator) CreateReportsConfig(
	formats []string,
	outputDir string,
	template string,
	verbose bool,
) *config.ReportsConfig {
	return &config.ReportsConfig{
		Formats:        formats,
		OutputDir:      outputDir,
		Template:       template,
		IncludeLogs:    verbose,
		IncludeRawData: verbose,
		SeverityLevels: []string{"low", "medium", "high", "critical"},
	}
}
