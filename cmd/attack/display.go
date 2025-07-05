package attack

import (
	"fmt"
	"strings"

	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/attacks/dos"
	"github.com/ajkula/cyberraven/pkg/attacks/hmac"
	"github.com/ajkula/cyberraven/pkg/attacks/injection"
	"github.com/ajkula/cyberraven/pkg/attacks/jwt"
	"github.com/ajkula/cyberraven/pkg/attacks/tls"
	"github.com/ajkula/cyberraven/pkg/config"
)

// DisplayResults shows a formatted summary of attack results
func (ao *AttackOrchestrator) DisplayResults(result *AttackResult) {
	fmt.Println()
	ao.printSectionHeader("🔍 ATTACK SESSION SUMMARY")

	// Session information
	fmt.Printf("Session ID: %s\n", result.SessionID)
	fmt.Printf("Duration: %v\n", result.Duration.Round(1000000)) // Round to milliseconds
	fmt.Printf("Target: %s\n", result.Target.BaseURL)
	fmt.Printf("Modules: %s\n", strings.Join(result.EnabledModules, ", "))
	fmt.Println()

	// Vulnerability summary
	ao.printVulnerabilitySummary(result)

	// Module-specific results
	if result.APIEnumeration != nil {
		ao.displayAPIResults(result.APIEnumeration)
	}

	if result.JWTTesting != nil {
		ao.displayJWTResults(result.JWTTesting)
	}

	if result.InjectionTesting != nil {
		ao.displayInjectionResults(result.InjectionTesting)
	}

	if result.HMACTesting != nil {
		ao.displayHMACResults(result.HMACTesting)
	}

	if result.DoSTesting != nil {
		ao.displayDoSResults(result.DoSTesting)
	}

	if result.TLSTesting != nil {
		ao.displayTLSResults(result.TLSTesting)
	}

	// Overall assessment
	ao.printOverallAssessment(result)
}

// printSectionHeader prints a formatted section header
func (ao *AttackOrchestrator) printSectionHeader(title string) {
	if ao.noColor {
		fmt.Printf("\n=== %s ===\n\n", title)
	} else {
		fmt.Printf("\n%s%s=== %s ===%s\n\n", ColorCyan, ColorBold, title, ColorReset)
	}
}

// printModuleStart prints a module start message
func (ao *AttackOrchestrator) printModuleStart(moduleName string) {
	if ao.noColor {
		fmt.Printf("[RUNNING] %s module...\n", moduleName)
	} else {
		fmt.Printf("%s[RUNNING]%s %s module...\n", ColorYellow, ColorReset, moduleName)
	}
}

// printModuleComplete prints API module completion message
func (ao *AttackOrchestrator) printModuleComplete(moduleName string, result *api.EnumerationResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Found %d endpoints, %d vulnerabilities\n",
			moduleName, len(result.FoundEndpoints), len(result.Vulnerabilities))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Found %d endpoints, %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, len(result.FoundEndpoints), len(result.Vulnerabilities))
	}
}

// printJWTModuleComplete prints JWT module completion message
func (ao *AttackOrchestrator) printJWTModuleComplete(moduleName string, result *jwt.JWTTestResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Analyzed %d tokens, found %d vulnerabilities\n",
			moduleName, len(result.TokensAnalyzed), len(result.VulnerabilitiesFound))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Analyzed %d tokens, found %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, len(result.TokensAnalyzed), len(result.VulnerabilitiesFound))
	}
}

// printInjectionModuleComplete prints Injection module completion message
func (ao *AttackOrchestrator) printInjectionModuleComplete(moduleName string, result *injection.InjectionTestResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Tested %d parameters, found %d vulnerabilities\n",
			moduleName, len(result.TestedParameters), len(result.VulnerabilitiesFound))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Tested %d parameters, found %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, len(result.TestedParameters), len(result.VulnerabilitiesFound))
	}
}

// printHMACModuleComplete prints HMAC module completion message
func (ao *AttackOrchestrator) printHMACModuleComplete(moduleName string, result *hmac.HMACTestResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Tested %d signatures, found %d vulnerabilities\n",
			moduleName, len(result.SignatureTests), len(result.VulnerabilitiesFound))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Tested %d signatures, found %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, len(result.SignatureTests), len(result.VulnerabilitiesFound))
	}
}

// printDoSModuleComplete prints DoS module completion message
func (ao *AttackOrchestrator) printDoSModuleComplete(moduleName string, result *dos.DoSTestResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Sent %d requests, found %d vulnerabilities\n",
			moduleName, result.TotalRequestsSent, len(result.VulnerabilitiesFound))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Sent %d requests, found %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, result.TotalRequestsSent, len(result.VulnerabilitiesFound))
	}
}

// printTLSModuleComplete prints TLS module completion message
func (ao *AttackOrchestrator) printTLSModuleComplete(moduleName string, result *tls.TLSTestResult) {
	if ao.noColor {
		fmt.Printf("[COMPLETE] %s - Executed %d tests, found %d vulnerabilities\n",
			moduleName, result.TestsExecuted, len(result.VulnerabilitiesFound))
	} else {
		fmt.Printf("%s[COMPLETE]%s %s - Executed %d tests, found %d vulnerabilities\n",
			ColorGreen, ColorReset, moduleName, result.TestsExecuted, len(result.VulnerabilitiesFound))
	}
}

func (ao *AttackOrchestrator) printVulnerabilitySummary(result *AttackResult) {
	ao.printSectionHeader("🚨 VULNERABILITY SUMMARY")

	if result.TotalVulnerabilities == 0 {
		printSuccess("No vulnerabilities detected", ao.noColor)
		return
	}

	fmt.Printf("Total Vulnerabilities: %d\n", result.TotalVulnerabilities)
	if result.CriticalCount > 0 {
		color := ""
		if !ao.noColor {
			color = ColorRed + ColorBold
		}
		fmt.Printf("%s  Critical: %d%s\n", color, result.CriticalCount, ColorReset)
	}
	if result.HighCount > 0 {
		color := ""
		if !ao.noColor {
			color = ColorRed
		}
		fmt.Printf("%s  High: %d%s\n", color, result.HighCount, ColorReset)
	}
	if result.MediumCount > 0 {
		color := ""
		if !ao.noColor {
			color = ColorYellow
		}
		fmt.Printf("%s  Medium: %d%s\n", color, result.MediumCount, ColorReset)
	}
	if result.LowCount > 0 {
		color := ""
		if !ao.noColor {
			color = ColorBlue
		}
		fmt.Printf("%s  Low: %d%s\n", color, result.LowCount, ColorReset)
	}
	fmt.Println()
}

// displayAPIResults displays API enumeration results
func (ao *AttackOrchestrator) displayAPIResults(result *api.EnumerationResult) {
	ao.printSectionHeader("🌐 API ENUMERATION RESULTS")

	fmt.Printf("Tested Endpoints: %d\n", result.TestedEndpoints)
	fmt.Printf("Found Endpoints: %d\n", len(result.FoundEndpoints))
	fmt.Printf("Success Rate: %.1f%%\n", result.SuccessRate)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Println()

	if ao.verbose && len(result.FoundEndpoints) > 0 {
		fmt.Println("Found Endpoints:")
		for _, endpoint := range result.FoundEndpoints {
			statusColor := ao.getStatusColor(endpoint.StatusCode)
			fmt.Printf("  %s%d%s %s %s (Score: %d/100)\n",
				statusColor, endpoint.StatusCode, ColorReset,
				endpoint.Method, endpoint.Path, endpoint.SecurityScore)
		}
		fmt.Println()
	}

	if len(result.Vulnerabilities) > 0 {
		fmt.Println("Vulnerabilities Found:")
		for _, vuln := range result.Vulnerabilities {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s %s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				vuln.Method, vuln.Endpoint, vuln.Description)
		}
		fmt.Println()
	}
}

// displayJWTResults displays JWT testing results
func (ao *AttackOrchestrator) displayJWTResults(result *jwt.JWTTestResult) {
	ao.printSectionHeader("🔑 JWT SECURITY TESTING RESULTS")

	fmt.Printf("Tests Executed: %d\n", result.TestsExecuted)
	fmt.Printf("Tokens Analyzed: %d\n", len(result.TokensAnalyzed))
	fmt.Printf("Successful Tests: %d\n", result.SuccessfulTests)
	fmt.Printf("Failed Tests: %d\n", result.FailedTests)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Println()

	if ao.verbose && len(result.TokensAnalyzed) > 0 {
		fmt.Println("Token Analysis:")
		for i, token := range result.TokensAnalyzed {
			fmt.Printf("  Token %d: Algorithm: %s, Valid: %t\n",
				i+1, token.Algorithm, token.IsValid)
			if len(token.SecurityIssues) > 0 {
				fmt.Printf("    Issues: %s\n", strings.Join(token.SecurityIssues, ", "))
			}
		}
		fmt.Println()
	}

	if len(result.VulnerabilitiesFound) > 0 {
		fmt.Println("JWT Vulnerabilities Found:")
		for _, vuln := range result.VulnerabilitiesFound {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				vuln.AttackVector, vuln.Description)
		}
		fmt.Println()
	}
}

// displayInjectionResults displays injection testing results
func (ao *AttackOrchestrator) displayInjectionResults(result *injection.InjectionTestResult) {
	ao.printSectionHeader("💉 INJECTION SECURITY TESTING RESULTS")

	fmt.Printf("Tests Executed: %d\n", result.TestsExecuted)
	fmt.Printf("Parameters Tested: %d\n", len(result.TestedParameters))
	fmt.Printf("Successful Tests: %d\n", result.SuccessfulTests)
	fmt.Printf("Failed Tests: %d\n", result.FailedTests)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Println()

	if ao.verbose && len(result.TestedParameters) > 0 {
		fmt.Println("Parameter Testing Summary:")
		vulnerableCount := 0
		for _, param := range result.TestedParameters {
			if param.Vulnerable {
				vulnerableCount++
			}
		}
		fmt.Printf("  Total Parameters Tested: %d\n", len(result.TestedParameters))
		fmt.Printf("  Vulnerable Parameters: %d\n", vulnerableCount)
		fmt.Printf("  Vulnerability Rate: %.1f%%\n", float64(vulnerableCount)/float64(len(result.TestedParameters))*100)
		fmt.Println()
	}

	if len(result.VulnerabilitiesFound) > 0 {
		fmt.Println("Injection Vulnerabilities Found:")
		for _, vuln := range result.VulnerabilitiesFound {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s %s:%s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				strings.ToUpper(vuln.Type), vuln.Method, vuln.Parameter, vuln.Description)
			if ao.verbose {
				fmt.Printf("    Payload: %s\n", vuln.PayloadUsed)
				fmt.Printf("    Risk Score: %d/100\n", vuln.RiskScore)
			}
		}
		fmt.Println()
	}
}

// displayHMACResults displays HMAC testing results
func (ao *AttackOrchestrator) displayHMACResults(result *hmac.HMACTestResult) {
	ao.printSectionHeader("🔐 HMAC SECURITY TESTING RESULTS")

	fmt.Printf("Tests Executed: %d\n", result.TestsExecuted)
	fmt.Printf("Signatures Tested: %d\n", len(result.SignatureTests))
	fmt.Printf("Successful Tests: %d\n", result.SuccessfulTests)
	fmt.Printf("Failed Tests: %d\n", result.FailedTests)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Printf("Average Response Time: %v\n", result.AverageResponseTime.Round(1000000)) // Round to milliseconds
	fmt.Println()

	if result.ReplayAttemptsSuccessful > 0 || result.TimingAnomaliesDetected > 0 {
		fmt.Println("HMAC Security Issues:")
		if result.ReplayAttemptsSuccessful > 0 {
			fmt.Printf("  Replay Attacks Successful: %d\n", result.ReplayAttemptsSuccessful)
		}
		if result.TimingAnomaliesDetected > 0 {
			fmt.Printf("  Timing Anomalies Detected: %d\n", result.TimingAnomaliesDetected)
		}
		fmt.Println()
	}

	if ao.verbose && len(result.SignatureTests) > 0 {
		fmt.Println("Signature Testing Summary:")
		validCount := 0
		for _, sig := range result.SignatureTests {
			if sig.Valid {
				validCount++
			}
		}
		fmt.Printf("  Total Signatures Tested: %d\n", len(result.SignatureTests))
		fmt.Printf("  Valid Signatures: %d\n", validCount)
		fmt.Printf("  Validation Rate: %.1f%%\n", float64(validCount)/float64(len(result.SignatureTests))*100)
		fmt.Println()
	}

	if len(result.VulnerabilitiesFound) > 0 {
		fmt.Println("HMAC Vulnerabilities Found:")
		for _, vuln := range result.VulnerabilitiesFound {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				vuln.AttackVector, vuln.Description)
			if ao.verbose {
				fmt.Printf("    Algorithm: %s\n", vuln.Algorithm)
				fmt.Printf("    Risk Score: %d/100\n", vuln.RiskScore)
				if vuln.ResponseTime > 0 {
					fmt.Printf("    Response Time: %v\n", vuln.ResponseTime.Round(1000000))
				}
			}
		}
		fmt.Println()
	}
}

// displayDoSResults displays DoS testing results
func (ao *AttackOrchestrator) displayDoSResults(result *dos.DoSTestResult) {
	ao.printSectionHeader("💥 DOS SECURITY TESTING RESULTS")

	fmt.Printf("Tests Executed: %d\n", result.TestsExecuted)
	fmt.Printf("Total Requests Sent: %d\n", result.TotalRequestsSent)
	fmt.Printf("Successful Requests: %d\n", result.SuccessfulRequests)
	fmt.Printf("Failed Requests: %d\n", result.FailedRequests)
	fmt.Printf("Timeout Requests: %d\n", result.TimeoutRequests)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Printf("Average Response Time: %v\n", result.AverageResponseTime.Round(1000000))

	if result.ServiceDegradation {
		printWarning("Service degradation detected during testing", ao.noColor)
	}
	fmt.Println()

	if len(result.VulnerabilitiesFound) > 0 {
		fmt.Println("DoS Vulnerabilities Found:")
		for _, vuln := range result.VulnerabilitiesFound {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s %s:%s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				strings.ToUpper(vuln.Type), vuln.Method, vuln.Endpoint, vuln.Description)
			if ao.verbose {
				fmt.Printf("    Attack Duration: %v\n", vuln.AttackDuration.Round(1000000))
				fmt.Printf("    Risk Score: %d/100\n", vuln.RiskScore)
				if vuln.ServiceUnavailable {
					fmt.Printf("    Service became unavailable\n")
				}
			}
		}
		fmt.Println()
	}
}

// displayTLSResults displays TLS testing results
func (ao *AttackOrchestrator) displayTLSResults(result *tls.TLSTestResult) {
	ao.printSectionHeader("🔒 TLS SECURITY TESTING RESULTS")

	fmt.Printf("Tests Executed: %d\n", result.TestsExecuted)
	fmt.Printf("Successful Tests: %d\n", result.SuccessfulTests)
	fmt.Printf("Failed Tests: %d\n", result.FailedTests)
	fmt.Printf("Requests/Second: %.1f\n", result.RequestsPerSecond)
	fmt.Printf("Supported TLS Versions: %s\n", strings.Join(result.SupportedTLSVersions, ", "))
	fmt.Printf("Weak Ciphers Found: %d\n", result.WeakCiphersFound)
	fmt.Printf("Certificate Issues: %d\n", result.CertificateIssues)
	fmt.Println()

	if len(result.VulnerabilitiesFound) > 0 {
		fmt.Println("TLS Vulnerabilities Found:")
		for _, vuln := range result.VulnerabilitiesFound {
			sevColor := ao.getSeverityColor(vuln.Severity)
			fmt.Printf("  %s[%s]%s %s:%s - %s\n",
				sevColor, strings.ToUpper(vuln.Severity), ColorReset,
				strings.ToUpper(vuln.Type), vuln.Component, vuln.Description)
			if ao.verbose {
				fmt.Printf("    Risk Score: %d/100\n", vuln.RiskScore)
				if vuln.TLSVersion != "" {
					fmt.Printf("    TLS Version: %s\n", vuln.TLSVersion)
				}
				if vuln.CipherSuite != "" {
					fmt.Printf("    Cipher Suite: %s\n", vuln.CipherSuite)
				}
				if vuln.Exploitable {
					fmt.Printf("    Exploitable: Yes\n")
				}
			}
		}
		fmt.Println()
	}
}

// printOverallAssessment prints the overall security assessment
func (ao *AttackOrchestrator) printOverallAssessment(result *AttackResult) {
	ao.printSectionHeader("📊 OVERALL SECURITY ASSESSMENT")

	if result.TotalVulnerabilities == 0 {
		printSuccess("🎉 Target appears to be well-secured against tested attack vectors", ao.noColor)
	} else if result.CriticalCount > 0 || result.HighCount > 0 {
		printError("⚠️  Critical security issues detected - immediate attention required", ao.noColor)
	} else if result.MediumCount > 0 {
		printWarning("⚡ Moderate security concerns identified - review recommended", ao.noColor)
	} else {
		printInfo("✅ Minor security improvements identified", ao.noColor)
	}

	fmt.Printf("\nRecommendation: Review detailed results and implement appropriate remediation measures.\n")
}

// Color utility methods

// getStatusColor returns the appropriate color for HTTP status codes
func (ao *AttackOrchestrator) getStatusColor(statusCode int) string {
	if ao.noColor {
		return ""
	}

	switch {
	case statusCode >= 200 && statusCode < 300:
		return ColorGreen
	case statusCode >= 300 && statusCode < 400:
		return ColorYellow
	case statusCode >= 400 && statusCode < 500:
		return ColorRed
	case statusCode >= 500:
		return ColorRed + ColorBold
	default:
		return ""
	}
}

// getSeverityColor returns the appropriate color for vulnerability severity
func (ao *AttackOrchestrator) getSeverityColor(severity string) string {
	if ao.noColor {
		return ""
	}

	switch strings.ToLower(severity) {
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
