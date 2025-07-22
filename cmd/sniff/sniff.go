package sniff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/sniffer"
)

// Colors for terminal output (consistent with main.go)
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"

	configFile = "cyberraven.yaml"
)

// Execute runs the network sniffing command
func Execute(cmd *cobra.Command, args []string) error {
	// Get command flags
	interfaceName, _ := cmd.Flags().GetString("interface")
	filter, _ := cmd.Flags().GetString("filter")
	duration, _ := cmd.Flags().GetDuration("duration")
	outputFile, _ := cmd.Flags().GetString("output")

	// Get global flags
	verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")

	// Load configuration
	printInfo("Loading CyberRaven configuration...", noColor)
	cfg, err := loadConfiguration(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate and set defaults
	if duration == 0 {
		duration = 5 * time.Minute // Default to 5 minutes
		printInfo(fmt.Sprintf("Using default capture duration: %v", duration), noColor)
	}

	if interfaceName == "" {
		printInfo("Auto-detecting network interface...", noColor)
		// Will auto-detect in NetworkEngine
	}

	// Create sniffer configuration
	snifferConfig := &config.SnifferConfig{
		Interface:            interfaceName,
		BPFFilter:            filter,
		Duration:             duration,
		PacketLimit:          0, // Unlimited
		CaptureHTTP:          true,
		CaptureHTTPS:         true,
		RealTimeAnalysis:     true,
		DetectionInterval:    30 * time.Second,
		MinConfidence:        0.6,
		MaxEndpoints:         100,
		MaxTokens:            50,
		AutoUpdateConfig:     true,
		ConfigUpdateInterval: 30 * time.Second,
		BackupConfig:         true,
		DryRunUpdates:        false,
	}

	// Display sniffing session info
	printSniffingHeader(snifferConfig, noColor)

	// Create and start sniffing session
	printInfo("Initializing network capture engine...", noColor)
	session, err := createSniffingSession(cfg, snifferConfig)
	if err != nil {
		return fmt.Errorf("failed to create sniffing session: %w", err)
	}
	defer session.Close()

	// Start sniffing with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	printInfo("Starting network traffic capture and analysis...", noColor)
	printInfo(fmt.Sprintf("Capture duration: %v", duration), noColor)
	printInfo("Press Ctrl+C to stop early", noColor)

	// Execute sniffing session
	result, err := session.Execute(ctx)
	if err != nil {
		return fmt.Errorf("sniffing session failed: %w", err)
	}

	// Display results
	displaySniffingResults(result, verbose, noColor)

	// saving results for better attacks
	discoveryFile := "discovery.json"
	if err := saveSniffingResults(result, discoveryFile, noColor); err != nil {
		printWarning(fmt.Sprintf("Failed to save discovery results: %v", err), noColor)
	} else {
		printSuccess("Discovery results saved to discovery.json", noColor)
	}

	// Save additional copy if output file specified
	if outputFile != "" && outputFile != discoveryFile {
		if err := saveSniffingResults(result, outputFile, noColor); err != nil {
			printError(fmt.Sprintf("Failed to save additional copy: %v", err), noColor)
		} else {
			printSuccess(fmt.Sprintf("Additional copy saved to: %s", outputFile), noColor)
		}
	}

	// Display attack recommendations
	if len(result.AttackRecommendations) > 0 {
		displayAttackRecommendations(result.AttackRecommendations, noColor)
	} else {
		printInfo("No specific attack recommendations generated", noColor)
	}

	// Final summary
	printSniffingSummary(result, noColor)

	return nil
}

// SniffingSession manages a complete sniffing and analysis session
type SniffingSession struct {
	config        *config.Config
	snifferConfig *config.SnifferConfig
	networkEngine *sniffer.NetworkEngine
	parser        *sniffer.Parser
	analyzer      *sniffer.Analyzer
	detector      *sniffer.Detector
	configurator  *sniffer.Configurator
}

// createSniffingSession creates a new sniffing session with all components
func createSniffingSession(cfg *config.Config, snifferConfig *config.SnifferConfig) (*SniffingSession, error) {
	// Create network engine
	engine, err := sniffer.NewNetworkEngine(snifferConfig, snifferConfig.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to create network engine: %w", err)
	}

	// Create parser
	parser := sniffer.NewParser(snifferConfig)

	// Create analyzer
	analyzer := sniffer.NewAnalyzer(snifferConfig)

	// Create detector
	detector := sniffer.NewDetector(snifferConfig)

	// Create configurator
	configurator := sniffer.NewConfigurator(snifferConfig, cfg.Target, cfg.Attacks)

	session := &SniffingSession{
		config:        cfg,
		snifferConfig: snifferConfig,
		networkEngine: engine,
		parser:        parser,
		analyzer:      analyzer,
		detector:      detector,
		configurator:  configurator,
	}

	return session, nil
}

// Execute runs the complete sniffing and analysis pipeline
func (s *SniffingSession) Execute(ctx context.Context) (*sniffer.SnifferResult, error) {
	startTime := time.Now()
	sessionID := fmt.Sprintf("sniff_%d", startTime.Unix())

	// Set up result tracking
	result := &sniffer.SnifferResult{
		SessionID: sessionID,
		StartTime: startTime,
	}

	// Set up HTTP stream callback for real-time processing
	s.networkEngine.SetHTTPStreamCallback(func(stream *sniffer.HTTPStream) {
		fmt.Printf("[DEBUG] Processing HTTP stream: %s\n", stream.ID)

		// Parse HTTP conversation
		conversation, err := s.parser.ParseHTTPStream(stream)
		if err != nil {
			fmt.Printf("[ERROR] Parser failed: %v\n", err)
			return // Skip invalid conversations
		}
		fmt.Printf("[DEBUG] Parsed conversation: %s %s\n", conversation.Request.Method, conversation.Request.Path)

		// Analyze conversation
		analysisResults, err := s.analyzer.AnalyzeConversation(conversation)
		if err != nil {
			fmt.Printf("[ERROR] Analyzer failed: %v\n", err)
			return // Skip analysis errors
		}

		// Detect security patterns
		detectionResults, err := s.detector.ProcessConversation(conversation)
		if err != nil {
			fmt.Printf("[ERROR] Detector failed: %v\n", err)
			return // Skip detection errors
		}
		fmt.Printf("[DEBUG] Detection results: %d findings\n", len(detectionResults.Endpoints))

		// Update configurator with discoveries
		s.configurator.ProcessDiscoveries(detectionResults, analysisResults)
	})

	// Start network capture
	if err := s.networkEngine.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start network capture: %w", err)
	}

	// Wait for capture to complete or context cancellation
	<-ctx.Done()

	// Stop network capture
	if err := s.networkEngine.Stop(); err != nil {
		return nil, fmt.Errorf("failed to stop network capture: %w", err)
	}

	// Finalize results
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Get final statistics
	packetsProcessed, bytesProcessed, _, httpPackets, httpsPackets := s.networkEngine.GetStats()
	result.PacketsCaptured = int(packetsProcessed)
	result.BytesCaptured = bytesProcessed
	result.HTTPConversations = int(httpPackets)
	result.HTTPSConversations = int(httpsPackets)

	// Get final analysis and detection results
	result.ConfigUpdates = *s.configurator.GetPendingUpdates()
	result.AttackRecommendations = s.configurator.GetRecommendations()

	// Get discovered data
	result.DiscoveredEndpoints = s.detector.GetDiscoveredEndpoints()
	result.DiscoveredTokens = s.detector.GetDiscoveredTokens()
	result.DiscoveredSignatures = s.detector.GetDiscoveredSignatures()
	result.SensitiveDataLeaks = s.detector.GetSensitiveDataLeaks()
	result.TechnologyProfile = s.analyzer.GetTechnologyProfile()
	result.TLSIntelligence = s.networkEngine.GetTLSIntelligence()

	return result, nil
}

// Close cleans up session resources
func (s *SniffingSession) Close() {
	if s.networkEngine != nil {
		s.networkEngine.Close()
	}
}

// loadConfiguration loads CyberRaven configuration
func loadConfiguration(configFile string) (*config.Config, error) {
	if configFile == "" {
		configFile = "cyberraven.yaml"
	}

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configFile)
	}

	// Read config file directly
	yamlData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal into config struct
	var cfg config.Config
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// saveSniffingResults saves sniffing results to file
func saveSniffingResults(result *sniffer.SnifferResult, outputFile string, noColor bool) error {
	// Create output directory if needed
	dir := filepath.Dir(outputFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Save as JSON for now (could add other formats later)
	data, err := result.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	printSuccess(fmt.Sprintf("Results saved to: %s", outputFile), noColor)
	return nil
}

// Display functions

func printSniffingHeader(snifferConfig *config.SnifferConfig, noColor bool) {
	printSectionHeader("🔍 NETWORK TRAFFIC ANALYSIS SESSION", noColor)

	interfaceDisplay := snifferConfig.Interface
	if interfaceDisplay == "" {
		interfaceDisplay = "auto-detect"
	}

	fmt.Printf("Interface: %s\n", interfaceDisplay)

	fmt.Printf("Interface: %s\n", getInterfaceDisplay(snifferConfig.Interface))
	fmt.Printf("Duration: %v\n", snifferConfig.Duration)
	if snifferConfig.BPFFilter != "" {
		fmt.Printf("Filter: %s\n", snifferConfig.BPFFilter)
	}
	fmt.Printf("Protocols: %s\n", getProtocolsDisplay(snifferConfig))
	fmt.Printf("Real-time Analysis: %t\n", snifferConfig.RealTimeAnalysis)
	fmt.Println()
}

func displaySniffingResults(result *sniffer.SnifferResult, verbose, noColor bool) {
	printSectionHeader("📊 TRAFFIC ANALYSIS RESULTS", noColor)

	// Capture statistics
	fmt.Printf("Session Duration: %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("Packets Captured: %d\n", result.PacketsCaptured)
	fmt.Printf("Bytes Analyzed: %s\n", formatBytes(result.BytesCaptured))
	fmt.Printf("HTTP Conversations: %d\n", result.HTTPConversations)
	fmt.Printf("HTTPS Conversations: %d\n", result.HTTPSConversations)
	fmt.Println()

	// Discovery summary
	fmt.Printf("Endpoints Discovered: %d\n", len(result.DiscoveredEndpoints))
	fmt.Printf("Tokens Found: %d\n", len(result.DiscoveredTokens))
	fmt.Printf("Signatures Detected: %d\n", len(result.DiscoveredSignatures))
	fmt.Printf("Sensitive Data Leaks: %d\n", len(result.SensitiveDataLeaks))
	fmt.Println()

	// Technology profile
	if result.TechnologyProfile.WebServer != "" || result.TechnologyProfile.Framework != "" {
		printSectionHeader("🔧 TECHNOLOGY PROFILE", noColor)
		if result.TechnologyProfile.WebServer != "" {
			fmt.Printf("Web Server: %s\n", result.TechnologyProfile.WebServer)
		}
		if result.TechnologyProfile.Framework != "" {
			fmt.Printf("Framework: %s\n", result.TechnologyProfile.Framework)
		}
		if result.TechnologyProfile.Language != "" {
			fmt.Printf("Language: %s\n", result.TechnologyProfile.Language)
		}
		if result.TechnologyProfile.Database != "" {
			fmt.Printf("Database: %s\n", result.TechnologyProfile.Database)
		}
		fmt.Println()
	}

	// Detailed results if verbose
	if verbose {
		displayDetailedFindings(result, noColor)
	}
}

func displayDetailedFindings(result *sniffer.SnifferResult, noColor bool) {
	// Endpoints
	if len(result.DiscoveredEndpoints) > 0 {
		printSectionHeader("🌐 DISCOVERED ENDPOINTS", noColor)
		for i, endpoint := range result.DiscoveredEndpoints {
			if i >= 10 { // Limit display
				fmt.Printf("... and %d more\n", len(result.DiscoveredEndpoints)-10)
				break
			}
			fmt.Printf("  %s %s (Requests: %d)\n", endpoint.Method, endpoint.Path, endpoint.RequestCount)
		}
		fmt.Println()
	}

	// Tokens
	if len(result.DiscoveredTokens) > 0 {
		printSectionHeader("🔑 DISCOVERED TOKENS", noColor)
		for i, token := range result.DiscoveredTokens {
			if i >= 5 { // Limit display
				fmt.Printf("... and %d more\n", len(result.DiscoveredTokens)-5)
				break
			}
			fmt.Printf("  %s token in %s:%s (Used %d times)\n",
				token.Type, token.Location, token.LocationKey, token.UsageCount)
		}
		fmt.Println()
	}

	// Sensitive data leaks
	if len(result.SensitiveDataLeaks) > 0 {
		printSectionHeader("⚠️  SENSITIVE DATA LEAKS", noColor)
		for _, leak := range result.SensitiveDataLeaks {
			sevColor := getSeverityColor(leak.Severity, noColor)
			fmt.Printf("  %s[%s]%s %s in %s\n",
				sevColor, leak.Severity, ColorReset, leak.DataType, leak.Location)
		}
		fmt.Println()
	}
}

func displayAttackRecommendations(recommendations []sniffer.AttackRecommendation, noColor bool) {
	printSectionHeader("🎯 ATTACK RECOMMENDATIONS", noColor)

	if len(recommendations) == 0 {
		printInfo("No specific attack recommendations based on discovered traffic", noColor)
		return
	}

	fmt.Printf("Based on traffic analysis, consider running these attack modules:\n\n")

	for _, rec := range recommendations {
		priorityColor := getSeverityColor(rec.Priority, noColor)
		fmt.Printf("%s[%s]%s %s Module (Confidence: %.1f%%)\n",
			priorityColor, rec.Priority, ColorReset, rec.Module, rec.Confidence*100)
		fmt.Printf("  Reason: %s\n", rec.Description)
		if len(rec.Targets) > 0 {
			fmt.Printf("  Targets: %d discovered\n", len(rec.Targets))
		}
		fmt.Println()
	}

	printInfo("Run 'cyberraven attack' to execute recommended tests", noColor)
}

func printSniffingSummary(result *sniffer.SnifferResult, noColor bool) {
	printSectionHeader("✅ SNIFFING SESSION COMPLETE", noColor)

	if len(result.AttackRecommendations) > 0 {
		printSuccess("Traffic analysis complete! Attack recommendations generated.", noColor)
		printInfo("Discovery results saved to discovery.json for intelligent attack targeting", noColor)
		printInfo("Run 'cyberraven attack' to execute targeted penetration testing", noColor)
	} else {
		printInfo("Traffic analysis complete - baseline established", noColor)
		printInfo("Discovery results saved to discovery.json", noColor)
		printInfo("Run 'cyberraven attack' for standard penetration tests", noColor)
	}
}

// Utility functions

func getInterfaceDisplay(iface string) string {
	if iface == "" {
		return "auto-detect"
	}
	return iface
}

func getProtocolsDisplay(config *config.SnifferConfig) string {
	protocols := []string{}
	if config.CaptureHTTP {
		protocols = append(protocols, "HTTP")
	}
	if config.CaptureHTTPS {
		protocols = append(protocols, "HTTPS")
	}
	if config.CaptureOther {
		protocols = append(protocols, "DNS")
	}
	if len(protocols) == 0 {
		return "All"
	}
	return fmt.Sprintf("%v", protocols)
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func getSeverityColor(severity string, noColor bool) string {
	if noColor {
		return ""
	}
	switch severity {
	case "critical":
		return ColorRed + ColorBold
	case "high":
		return ColorRed
	case "medium":
		return ColorYellow
	case "low":
		return ColorBlue
	default:
		return ""
	}
}

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
