package attack

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Execute runs the attack command with the provided flags
func Execute(cmd *cobra.Command, args []string) error {
	// Get command flags
	outputDir, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")

	// Load base configuration
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Apply CLI target override if provided
	if targetURL, _ := cmd.Flags().GetString("target"); targetURL != "" {
		if err := ApplyTargetOverride(cfg, targetURL); err != nil {
			return fmt.Errorf("failed to apply target override: %w", err)
		}
		printInfo(fmt.Sprintf("Target override applied: %s", targetURL), false)
	}

	// Apply other CLI overrides
	if aggressive, _ := cmd.Flags().GetBool("aggressive"); aggressive {
		cfg.Attacks.Aggressive = true
		printInfo("Aggressive mode enabled", false)
	}

	if modules, _ := cmd.Flags().GetStringSlice("modules"); len(modules) > 0 {
		cfg.Attacks.Enabled = modules
		printInfo(fmt.Sprintf("Attack modules limited to: %v", modules), false)
	}

	if outputDir, _ := cmd.Flags().GetString("output"); outputDir != "" {
		// Apply to both results and reports
		cfg.Reports.OutputDir = outputDir
		printInfo(fmt.Sprintf("Output directory: %s", outputDir), false)
	}

	// Validate configuration
	if err := validateAttackConfig(cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create and execute orchestrator
	orchestrator := NewAttackOrchestrator(cfg, verbose, noColor, outputDir)

	// Execute attacks
	result, err := orchestrator.ExecuteAttacks(cmd.Context())
	if err != nil {
		return fmt.Errorf("attack execution failed: %w", err)
	}

	// Save results
	if err := orchestrator.SaveResults(result); err != nil {
		printWarning(fmt.Sprintf("Failed to save results: %v", err), noColor)
	}

	// Display summary
	orchestrator.calculateSummaryStats(result)

	return nil
}
