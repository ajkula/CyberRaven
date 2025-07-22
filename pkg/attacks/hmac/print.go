package hmac

import (
	"fmt"

	"github.com/ajkula/cyberraven/pkg/config"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Output formatting functions

// printTarget displays target information
func printTarget(target config.TargetConfig, noColor bool) {
	fmt.Printf("Target: %s\n", target.BaseURL)
	if target.Name != "" && target.Name != "Default Target" {
		fmt.Printf("Name: %s\n", target.Name)
	}
	if target.Description != "" {
		fmt.Printf("Description: %s\n", target.Description)
	}
	fmt.Println()
}

// printError prints error messages with proper formatting
func printError(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorRed + ColorBold
	}
	fmt.Printf("%s[ERROR] %s%s\n", color, message, ColorReset)
}

// printSuccess prints success messages with proper formatting
func printSuccess(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorGreen + ColorBold
	}
	fmt.Printf("%s[SUCCESS] %s%s\n", color, message, ColorReset)
}

// printInfo prints info messages with proper formatting
func printInfo(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorBlue
	}
	fmt.Printf("%s[INFO] %s%s\n", color, message, ColorReset)
}

// printWarning prints warning messages with proper formatting
func printWarning(message string, noColor bool) {
	color := ""
	if !noColor {
		color = ColorYellow + ColorBold
	}
	fmt.Printf("%s[WARNING] %s%s\n", color, message, ColorReset)
}
