package report

import "fmt"

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

// ConsoleFormatter handles all terminal output formatting
type ConsoleFormatter struct {
	noColor bool
}

// NewConsoleFormatter creates a new console formatter
func NewConsoleFormatter(noColor bool) *ConsoleFormatter {
	return &ConsoleFormatter{
		noColor: noColor,
	}
}

// PrintSectionHeader prints a formatted section header
func (f *ConsoleFormatter) PrintSectionHeader(title string) {
	if f.noColor {
		fmt.Printf("\n=== %s ===\n\n", title)
	} else {
		fmt.Printf("\n%s%s=== %s ===%s\n\n", ColorCyan, ColorBold, title, ColorReset)
	}
}

// PrintError prints an error message with formatting
func (f *ConsoleFormatter) PrintError(message string) {
	color := ""
	if !f.noColor {
		color = ColorRed + ColorBold
	}
	fmt.Printf("%s[ERROR] %s%s\n", color, message, ColorReset)
}

// PrintSuccess prints a success message with formatting
func (f *ConsoleFormatter) PrintSuccess(message string) {
	color := ""
	if !f.noColor {
		color = ColorGreen + ColorBold
	}
	fmt.Printf("%s[SUCCESS] %s%s\n", color, message, ColorReset)
}

// PrintInfo prints an info message with formatting
func (f *ConsoleFormatter) PrintInfo(message string) {
	color := ""
	if !f.noColor {
		color = ColorBlue
	}
	fmt.Printf("%s[INFO] %s%s\n", color, message, ColorReset)
}

// PrintWarning prints a warning message with formatting
func (f *ConsoleFormatter) PrintWarning(message string) {
	color := ""
	if !f.noColor {
		color = ColorYellow + ColorBold
	}
	fmt.Printf("%s[WARNING] %s%s\n", color, message, ColorReset)
}
