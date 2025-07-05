package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/cmd/report"
	"github.com/ajkula/cyberraven/cmd/sniff"
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
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Search for config in common locations
		viper.SetConfigName("cyberraven")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("$HOME/.cyberraven")
		viper.AddConfigPath("/etc/cyberraven/")
	}

	// Environment variables
	viper.SetEnvPrefix("CYBERRAVEN")
	viper.AutomaticEnv()

	// Read configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			printWarning("No configuration file found, using defaults")
		} else {
			return fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		printInfo(fmt.Sprintf("Using config file: %s", viper.ConfigFileUsed()))
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
	reportCmd.Flags().StringP("input", "i", "",
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
	const defaultConfigContent = `# CyberRaven Configuration File
# Professional Security Assessment Tool
# https://github.com/ajkula/cyberraven

# Engine Configuration - Controls attack execution behavior
engine:
  max_workers: 10          # Maximum concurrent attack workers
  timeout: 30s            # Timeout for individual operations
  rate_limit: 10          # Requests per second limit
  max_retries: 3          # Maximum retry attempts for failed requests
  retry_delay: 1s         # Delay between retry attempts

# Target Configuration - Define your target system
target:
  name: "Default Target"
  description: "Target system for security assessment"
  base_url: "http://localhost:8080"  # Functional default - change to your target
  profile: "webapp-generic"          # Options: webapp-generic, api-rest, messaging-system
  
  # Custom headers to include in all requests
  headers:
    # "User-Agent": "CyberRaven Security Scanner"
    # "X-Custom-Header": "value"
  
  # Authentication configuration
  auth:
    type: "none"           # Options: none, basic, bearer, jwt, hmac, custom
    # username: "admin"    # For basic auth
    # password: "secret"   # For basic auth
    # token: "jwt_token"   # For bearer/jwt auth
    # custom_headers:      # For custom auth
    #   "Authorization": "Custom auth_value"
    
    # HMAC Authentication (when type: "hmac")
    hmac:
      secret: ""                    # HMAC secret key (required for HMAC auth)
      algorithm: "sha256"           # HMAC algorithm: sha256, sha512
      signature_header: "X-Signature"    # Header name for HMAC signature
      timestamp_header: "X-Timestamp"    # Header name for timestamp
      timestamp_tolerance: "5m"           # Tolerance for timestamp validation
  
  # TLS/SSL Configuration - Pen-testing defaults
  tls:
    insecure_skip_verify: true   # Accept self-signed certificates (pen-testing default)
    # ca_cert_path: "/path/to/ca.crt"      # Custom CA certificate
    # client_cert_path: "/path/to/cert.crt" # Client certificate for mutual TLS
    # client_key_path: "/path/to/key.key"   # Client private key
    # min_version: "1.2"   # Minimum TLS version
    # max_version: "1.3"   # Maximum TLS version

# Attack Modules Configuration
attacks:
  enabled: []              # Empty = all modules, or specify: ["api", "jwt", "injection"]
  aggressive: false        # Enable aggressive testing mode
  
  # API Enumeration Module
  api:
    enable: true
    enable_auto_discovery: true     # Auto-discover HTTP/HTTPS protocols
    test_enumeration: true
    test_method_tampering: true
    test_parameter_pollution: true
    # common_endpoints:      # Custom endpoints to test (empty = smart defaults)
    #   - "/api/users"
    #   - "/admin/dashboard"
    # wordlists:             # Custom wordlists for enumeration
    #   - "/path/to/wordlist.txt"
  
  # JWT Security Testing Module
  jwt:
    enable: true
    test_alg_none: true      # Test "none" algorithm bypass
    test_alg_confusion: true # Test algorithm confusion attacks
    test_weak_secrets: true  # Test weak HMAC secrets
    test_expiration: true    # Test expiration bypass
    # weak_secrets:          # Custom weak secrets to test
    #   - "secret"
    #   - "password123"
    #   - "your-256-bit-secret"
  
  # Injection Testing Module
  injection:
    enable: true
    test_sql: true          # Test SQL injection
    test_nosql: true        # Test NoSQL injection
    test_json: true         # Test JSON injection
    test_path: true         # Test path traversal
    # sql_payloads:          # Custom SQL injection payloads
    #   - "' OR 1=1--"
    #   - "'; DROP TABLE users--"
  
  # HMAC Security Testing Module
  hmac:
    enable: true
    test_replay: true       # Test replay attacks
    test_timing: true       # Test timing attacks
    replay_window: "5m"     # Time window for replay attack testing
    timing_requests: 50     # Number of requests for timing analysis

  # DoS Security Testing Module
  dos:
    enable: true
    test_flooding: true      # Test request flooding attacks
    test_large_payloads: true # Test large payload attacks  
    test_conn_exhaustion: true # Test connection exhaustion
    flooding_duration: "10s" # Duration of flooding tests (keep short!)
    flooding_rate: 20        # Requests per second for flooding
    max_payload_size: 5242880 # Maximum payload size (5MB)
    max_connections: 10      # Maximum concurrent connections

  # TLS Security Testing Module
  tls:
    enable: true
    test_cipher_suites: true     # Test cipher suite security
    test_certificates: true      # Test certificate validation
    test_downgrade: true         # Test protocol downgrade attacks
    test_self_signed: true       # Test self-signed certificate handling
    test_expired_certs: true     # Test expired certificate handling

# Reporting Configuration
reports:
  formats: ["html", "json", "txt"]  # Available: html, json, pdf, txt
  output_dir: "./reports"           # Directory for generated reports
  include_logs: true               # Include detailed logs in reports
  include_raw_data: false          # Include raw HTTP requests/responses
  severity_levels: ["low", "medium", "high", "critical"]

# Output and UI Configuration
output:
  verbosity: "normal"      # Options: silent, minimal, normal, verbose, debug
  colors: true            # Enable colored terminal output
  progress_bars: true     # Show progress bars during scanning
  show_banner: true      # Show ASCII art banner
`

	// Write configuration file
	filename := "cyberraven.yaml"
	if err := os.WriteFile(filename, []byte(defaultConfigContent), 0644); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	fmt.Printf("✅ Default configuration file created: %s\n", filename)
	fmt.Printf("📝 Default target: http://localhost:8080 (pen-testing ready)\n")
	fmt.Printf("🚀 Run 'cyberraven attack' to start testing with defaults\n")
	fmt.Printf("🎯 Or 'cyberraven attack --target YOUR_TARGET_URL' for custom target\n")

	return nil
}
