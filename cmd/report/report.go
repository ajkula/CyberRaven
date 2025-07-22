package report

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Execute runs the report generation command (CLI entry point)
func Execute(cmd *cobra.Command, args []string) error {
	// Get command flags
	inputPath, _ := cmd.Flags().GetString("input")
	outputDir, _ := cmd.Flags().GetString("output")
	formats, _ := cmd.Flags().GetStringSlice("format")
	template, _ := cmd.Flags().GetString("template")
	verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")

	// Validate input
	if inputPath == "" {
		return fmt.Errorf("input file or directory is required")
	}

	// Create dependencies (dependency injection)
	formatter := NewConsoleFormatter(noColor)
	loader := NewAttackResultsLoader(formatter)
	validator := NewAttackResultValidator()
	display := NewConsoleDisplay(formatter)
	orchestrator := NewReportOrchestrator(loader, validator, display, formatter)

	// Create reports configuration
	reportsConfig := orchestrator.CreateReportsConfig(formats, outputDir, template, verbose)

	// Execute report generation
	return orchestrator.GenerateReports(inputPath, reportsConfig, verbose)
}
