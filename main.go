package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/cmd/report"
	"github.com/ajkula/cyberraven/cmd/sniff"
	"github.com/ajkula/cyberraven/pkg/config"
)

var (
	// Version information
	Version   = "1.0.0"
	BuildTime = "development"
	GitCommit = "unknown"

	// Global flags
	configFile string
	verbose    bool
	quiet      bool
	noColor    bool
	noBanner   bool
)

// ASCII Art Banner - The magnificent CYBERRAVEN banner!
const banner = `
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
                                                                                      
        🐦‍ Professional Penetration Testing & Security Assessment Tool 🐦‍
                            Version %s | Build %s
                              Crafted by Greg | Go, Security, Pen-testing
`

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

// printBanner displays the CyberRaven banner with style
func printBanner() {
	if noBanner {
		return
	}

	color := ""
	if !noColor {
		color = ColorCyan + ColorBold
	}

	fmt.Printf(color+banner+ColorReset+"\n\n", Version, BuildTime)
}

// printError prints error messages with proper formatting
func printError(err error) {
	color := ""
	if !noColor {
		color = ColorRed + ColorBold
	}
	fmt.Fprintf(os.Stderr, color+"[ERROR] %v"+ColorReset+"\n", err)
}

// printSuccess prints success messages with proper formatting
func printSuccess(message string) {
	color := ""
	if !noColor {
		color = ColorGreen + ColorBold
	}
	fmt.Printf(color+"[SUCCESS] %s"+ColorReset+"\n", message)
}

// printInfo prints info messages with proper formatting
func printInfo(message string) {
	if quiet {
		return
	}
	color := ""
	if !noColor {
		color = ColorBlue
	}
	fmt.Printf(color+"[INFO] %s"+ColorReset+"\n", message)
}

// printWarning prints warning messages with proper formatting
func printWarning(message string) {
	color := ""
	if !noColor {
		color = ColorYellow + ColorBold
	}
	fmt.Printf(color+"[WARNING] %s"+ColorReset+"\n", message)
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cyberraven",
	Short: "Professional penetration testing and security assessment tool",
	Long: `CyberRaven is a comprehensive penetration testing framework designed to 
assess the security posture of modern applications and systems.

Features:
• JWT, HMAC, API, Injection, DoS, and TLS attack modules
• Network traffic sniffing and analysis
• Automated vulnerability detection
• Detailed security reports with metrics
• Configurable attack profiles for different target types
• Real-time monitoring and feedback

Perfect for security professionals, developers, and system administrators
who need to validate the security of their applications and infrastructure.`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Handle config initialization first
		if initConfig, _ := cmd.Flags().GetBool("init-config"); initConfig {
			return createDefaultConfig()
		}

		// Print banner for all commands except help
		if cmd.Name() != "help" && cmd.Name() != "completion" {
			printBanner()
		}

		// Initialize configuration
		return initConfig()
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		// Default behavior: show help
		return cmd.Help()
	},
}

// sniffCmd represents the sniff command
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Network traffic sniffing and analysis",
	Long: `Sniff and analyze network traffic to detect sensitive data transmission,
identify security issues in network protocols, and monitor communication patterns.

This module can detect:
• Unencrypted credentials in HTTP traffic
• Weak encryption protocols
• Suspicious data patterns
• Authentication token leakage
• JWT tokens and API keys
• HMAC signatures and timing patterns
• Technology fingerprints and vulnerabilities

The sniff command implements the revolutionary Sniffer-First approach:
1. Capture and analyze real network traffic
2. Automatically discover attack targets and tokens
3. Update cyberraven.yaml with discovered configurations
4. Generate prioritized attack recommendations

Example usage:
  cyberraven sniff --duration 5m --interface eth0
  cyberraven sniff --duration 10m --filter "tcp port 80 or tcp port 443"
  cyberraven attack  # Run attacks with discovered configuration`,

	RunE: sniff.Execute,
}

// attackCmd represents the attack command
var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute penetration testing attacks",
	Long: `Execute comprehensive penetration testing attacks against the target system.
This is the core module that orchestrates all attack vectors based on configuration.

Available attack modules:
• JWT: JSON Web Token security testing
• HMAC: Hash-based Message Authentication Code attacks
• API: REST API security assessment
• Injection: SQL, NoSQL, JSON, and path injection tests
• DoS: Denial of Service testing
• TLS: Transport Layer Security assessment`,

	RunE: attack.Execute,
}

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate detailed security reports",
	Long: `Generate comprehensive security assessment reports from previous scan results.
Reports can be exported in multiple formats with detailed vulnerability analysis.

Supported formats:
• JSON: Machine-readable format for automation
• HTML: Interactive web-based reports
• PDF: Professional documents for stakeholders
• TXT: Plain text for command-line review

Reports include:
• Executive summary with risk assessment
• Detailed vulnerability findings
• Remediation recommendations
• Technical evidence and proof-of-concept`,

	RunE: report.Execute,
}

// demoCmd represents the demo command
var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run automated demonstration scenarios",
	Long: `Execute automated demonstration scenarios to showcase CyberRaven capabilities.
Perfect for training, presentations, and proof-of-concept demonstrations.

Demo scenarios include:
• Basic vulnerability assessment
• Advanced penetration testing workflow
• Custom attack sequences
• Report generation showcase

This command is ideal for:
• Security training sessions
• Tool demonstrations
• Automated testing pipelines
• Capability validation`,

	RunE: func(cmd *cobra.Command, args []string) error {
		printInfo("Starting automated demonstration...")
		// TODO: Implement demo scenarios
		printWarning("Demo module not yet implemented")
		return nil
	},
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  `Display detailed version and build information for CyberRaven.`,

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("CyberRaven Security Assessment Tool\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Built with Go %s\n", "1.21+") // TODO: Get actual Go version
	},
}

// initConfig reads in config file and ENV variables if set
func initConfig() error {
	if _, err := os.Stat("cyberraven.yaml"); err != nil {
		printWarning("No configuration file found, using defaults")
	} else {
		printInfo("Using config file: cyberraven.yaml")
	}
	return nil
}

// setupCommands configures all CLI commands and flags
func setupCommands() {
	// Add subcommands to root
	rootCmd.AddCommand(sniffCmd)
	rootCmd.AddCommand(attackCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(versionCmd)

	// Global persistent flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "",
		"config file (default is ./cyberraven.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false,
		"quiet output (errors only)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false,
		"disable colored output")
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false,
		"disable banner display")
	rootCmd.PersistentFlags().Bool("init-config", false,
		"create default configuration file (cyberraven.yaml)")

	// Attack command specific flags
	attackCmd.Flags().StringP("target", "t", "",
		"target URL or configuration")
	attackCmd.Flags().StringP("profile", "p", "",
		"attack profile to use")
	attackCmd.Flags().StringSliceP("modules", "m", []string{},
		"specific attack modules to run")
	attackCmd.Flags().BoolP("aggressive", "a", false,
		"enable aggressive testing mode")
	attackCmd.Flags().StringP("output", "o", "./results",
		"output directory for results")

	// Report command specific flags
	reportCmd.Flags().StringP("input", "i", "./results",
		"input file or directory with scan results")
	reportCmd.Flags().StringP("output", "o", "./reports",
		"output directory for reports")
	reportCmd.Flags().StringSliceP("format", "f", []string{"html"},
		"report formats (json,html,pdf,txt)")
	reportCmd.Flags().StringP("template", "T", "",
		"custom report template")

	// Sniff command specific flags
	sniffCmd.Flags().StringP("interface", "i", "",
		"network interface to monitor")
	sniffCmd.Flags().StringP("filter", "f", "",
		"packet capture filter")
	sniffCmd.Flags().DurationP("duration", "d", 0,
		"capture duration (0 = infinite)")
	sniffCmd.Flags().StringP("output", "o", "",
		"output file for captured data")

	// Demo command specific flags
	demoCmd.Flags().StringP("scenario", "s", "basic",
		"demo scenario to run (basic,advanced,custom)")
	demoCmd.Flags().StringP("target", "t", "http://localhost:8080",
		"demo target URL")
	demoCmd.Flags().BoolP("interactive", "i", false,
		"interactive demo mode")
}

// main is the entry point for CyberRaven
func main() {
	// Setup all commands and flags
	setupCommands()

	// Execute the CLI
	if err := rootCmd.Execute(); err != nil {
		printError(err)
		os.Exit(1)
	}
}

// createDefaultConfig creates a default configuration file
func createDefaultConfig() error {

	cfg := config.CreateDefaultConfig()

	yamlData, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Printf("serialization error: %v\n", err)
		return fmt.Errorf("serialization error: %v", err)
	}

	// Write configuration file
	filename := "cyberraven.yaml"
	if err := os.WriteFile(filename, []byte(yamlData), 0644); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	fmt.Printf("✅ Default configuration file created: %s\n", filename)
	fmt.Printf("📝 Default target: http://localhost:8080 (pen-testing ready)\n")
	fmt.Printf("🚀 Run 'cyberraven attack' to start testing with defaults\n")
	fmt.Printf("🎯 Or 'cyberraven attack --target YOUR_TARGET_URL' for custom target\n")

	return nil
}
