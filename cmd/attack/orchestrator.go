package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/attacks/dos"
	"github.com/ajkula/cyberraven/pkg/attacks/hmac"
	"github.com/ajkula/cyberraven/pkg/attacks/injection"
	"github.com/ajkula/cyberraven/pkg/attacks/jwt"
	"github.com/ajkula/cyberraven/pkg/attacks/tls"
)

// ExecuteAttacks orchestrates the execution of all enabled attack modules
func (ao *AttackOrchestrator) ExecuteAttacks(ctx context.Context) (*AttackResult, error) {
	startTime := time.Now()
	sessionID := fmt.Sprintf("cr_%d", startTime.Unix())

	result := &AttackResult{
		SessionID:      sessionID,
		StartTime:      startTime,
		Target:         *ao.target,
		EnabledModules: ao.config.Attacks.Enabled,
		AggressiveMode: ao.config.Attacks.Aggressive,
	}
	// Count HMAC vulnerabilities
	if result.HMACTesting != nil {
		for _, vuln := range result.HMACTesting.VulnerabilitiesFound {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}

	// Execute API enumeration if enabled
	if ao.isModuleEnabled("api") && ao.config.Attacks.API.Enable {
		ao.printModuleStart("API Enumeration")

		// Use enhanced enumerator with auto-discovery
		enumerator, err := api.NewEnumeratorWithDiscovery(&ao.config.Attacks.API, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create API enumerator: %v", err), ao.noColor)
		} else {
			apiResult, err := enumerator.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("API enumeration failed: %v", err), ao.noColor)
			} else {
				result.APIEnumeration = apiResult
				ao.printModuleComplete("API Enumeration", apiResult)
			}
			// Clean up resources
			enumerator.Close()
		}
	}

	// Execute JWT testing if enabled
	if ao.isModuleEnabled("jwt") && ao.config.Attacks.JWT.Enable {
		ao.printModuleStart("JWT Security Testing")

		jwtFuzzer, err := jwt.NewJWTFuzzer(&ao.config.Attacks.JWT, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create JWT fuzzer: %v", err), ao.noColor)
		} else {
			jwtResult, err := jwtFuzzer.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("JWT testing failed: %v", err), ao.noColor)
			} else {
				result.JWTTesting = jwtResult
				ao.printJWTModuleComplete("JWT Security Testing", jwtResult)
			}
			// Clean up resources
			jwtFuzzer.Close()
		}
	}

	// Execute Injection testing if enabled
	if ao.isModuleEnabled("injection") && ao.config.Attacks.Injection.Enable {
		ao.printModuleStart("Injection Security Testing")

		injectionTester, err := injection.NewInjectionTester(&ao.config.Attacks.Injection, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create injection tester: %v", err), ao.noColor)
		} else {
			injectionResult, err := injectionTester.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("Injection testing failed: %v", err), ao.noColor)
			} else {
				result.InjectionTesting = injectionResult
				ao.printInjectionModuleComplete("Injection Security Testing", injectionResult)
			}
			// Clean up resources
			injectionTester.Close()
		}
	}

	// Execute HMAC testing if enabled
	if ao.isModuleEnabled("hmac") && ao.config.Attacks.HMAC.Enable {
		ao.printModuleStart("HMAC Security Testing")

		hmacTester, err := hmac.NewHMACTester(&ao.config.Attacks.HMAC, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create HMAC tester: %v", err), ao.noColor)
		} else {
			hmacResult, err := hmacTester.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("HMAC testing failed: %v", err), ao.noColor)
			} else {
				result.HMACTesting = hmacResult
				ao.printHMACModuleComplete("HMAC Security Testing", hmacResult)
			}
			// Clean up resources
			hmacTester.Close()
		}
	}

	// Execute DoS testing if enabled
	if ao.isModuleEnabled("dos") && ao.config.Attacks.DoS.Enable {
		ao.printModuleStart("DoS Security Testing")

		dosTester, err := dos.NewDoSTester(&ao.config.Attacks.DoS, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create DoS tester: %v", err), ao.noColor)
		} else {
			dosResult, err := dosTester.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("DoS testing failed: %v", err), ao.noColor)
			} else {
				result.DoSTesting = dosResult
				ao.printDoSModuleComplete("DoS Security Testing", dosResult)
			}
			// Clean up resources
			dosTester.Close()
		}
	}

	// Execute TLS testing if enabled
	if ao.isModuleEnabled("tls") && ao.config.Attacks.TLS.Enable {
		ao.printModuleStart("TLS Security Testing")

		tlsTester, err := tls.NewTLSTester(&ao.config.Attacks.TLS, ao.target)
		if err != nil {
			printError(fmt.Sprintf("Failed to create TLS tester: %v", err), ao.noColor)
		} else {
			tlsResult, err := tlsTester.Execute(ctx)
			if err != nil {
				printError(fmt.Sprintf("TLS testing failed: %v", err), ao.noColor)
			} else {
				result.TLSTesting = tlsResult
				ao.printTLSModuleComplete("TLS Security Testing", tlsResult)
			}
			// Clean up resources
			tlsTester.Close()
		}
	}

	// Finalize results
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	ao.calculateSummaryStats(result)

	return result, nil
}

// SaveResults saves the attack results to files
func (ao *AttackOrchestrator) SaveResults(result *AttackResult) error {
	// Create output directory
	if ao.outputDir == "" {
		ao.outputDir = "./results"
	}

	if err := os.MkdirAll(ao.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save JSON result
	filename := fmt.Sprintf("cyberraven_%s.json", result.SessionID)
	filepath := filepath.Join(ao.outputDir, filename)

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	printSuccess(fmt.Sprintf("Results saved to: %s", filepath), ao.noColor)
	return nil
}

// isModuleEnabled checks if a specific module is enabled
func (ao *AttackOrchestrator) isModuleEnabled(moduleName string) bool {
	if len(ao.config.Attacks.Enabled) == 0 {
		return true // If no specific modules enabled, run all
	}

	for _, enabled := range ao.config.Attacks.Enabled {
		if strings.EqualFold(enabled, moduleName) {
			return true
		}
	}
	return false
}

// calculateSummaryStats calculates vulnerability statistics across all modules
func (ao *AttackOrchestrator) calculateSummaryStats(result *AttackResult) {
	// Count vulnerabilities by severity from all modules
	if result.APIEnumeration != nil {
		for _, vuln := range result.APIEnumeration.Vulnerabilities {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}

	// Count JWT vulnerabilities
	if result.JWTTesting != nil {
		for _, vuln := range result.JWTTesting.VulnerabilitiesFound {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}

	// Count injection vulnerabilities
	if result.InjectionTesting != nil {
		for _, vuln := range result.InjectionTesting.VulnerabilitiesFound {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}

	// Count DoS vulnerabilities
	if result.DoSTesting != nil {
		for _, vuln := range result.DoSTesting.VulnerabilitiesFound {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}

	// Count TLS vulnerabilities
	if result.TLSTesting != nil {
		for _, vuln := range result.TLSTesting.VulnerabilitiesFound {
			result.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			}
		}
	}
}
