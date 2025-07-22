package reporting

import (
	"fmt"
	"math"
	"reflect"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/attacks/dos"
	"github.com/ajkula/cyberraven/pkg/attacks/hmac"
	"github.com/ajkula/cyberraven/pkg/attacks/injection"
	"github.com/ajkula/cyberraven/pkg/attacks/jwt"
	"github.com/ajkula/cyberraven/pkg/attacks/tls"
)

// calculateModularSecurityScore calculates security score using modular approach
func (rg *ReportGenerator) calculateModularSecurityScore(result *attack.AttackResult) int {
	var totalScore float64 = 0
	var totalWeight float64 = 0

	// Module weights based on business criticality
	modules := []struct {
		name     string
		data     any
		weight   float64
		isActive bool
	}{
		{"jwt", result.JWTTesting, 0.20, result.JWTTesting != nil},
		{"tls", result.TLSTesting, 0.20, result.TLSTesting != nil},
		{"injection", result.InjectionTesting, 0.15, result.InjectionTesting != nil},
		{"hmac", result.HMACTesting, 0.15, result.HMACTesting != nil},
		{"api", result.APIEnumeration, 0.15, result.APIEnumeration != nil},
		{"dos", result.DoSTesting, 0.15, result.DoSTesting != nil},
	}

	// Calculate weighted score
	for _, module := range modules {
		if module.isActive {
			moduleScore := rg.calculateModuleScore(module.name, module.data)
			totalScore += moduleScore * module.weight
			totalWeight += module.weight
		}
	}

	// Normalize by active modules weight
	if totalWeight > 0 {
		return int(totalScore / totalWeight)
	}

	return 50 // Default score if no modules active
}

// calculateModuleScore calculates security score for a specific module
func (rg *ReportGenerator) calculateModuleScore(moduleType string, moduleData any) float64 {
	baseScore := 100.0

	successfulAttacks := rg.countSuccessfulAttacks(moduleType, moduleData)
	potentialVulns := rg.countPotentialVulnerabilities(moduleType, moduleData)

	if successfulAttacks == 0 {
		vulnPenalty := math.Min(20, float64(potentialVulns)*0.5)
		score := baseScore - vulnPenalty
		return math.Max(75, score)
	}

	attackPenalty := float64(successfulAttacks) * 25
	vulnPenalty := float64(potentialVulns) * 2

	score := baseScore - attackPenalty - vulnPenalty
	return math.Max(0, score)
}

// countSuccessfulAttacks counts actual successful attacks/exploitations
func (rg *ReportGenerator) countSuccessfulAttacks(moduleType string, moduleData any) int {
	if moduleData == nil {
		return 0
	}

	successfulAttacks := 0

	switch moduleType {
	case "jwt":
		if jwtData, ok := moduleData.(*jwt.JWTTestResult); ok {
			fmt.Printf("DEBUG JWT: VulnerabilitiesFound count = %d\n", len(jwtData.VulnerabilitiesFound))
			// Parcourir les vraies vulnérabilités JWT typées
			for _, vuln := range jwtData.VulnerabilitiesFound {
				// "none" algorithm accepted = successful authentication bypass
				if vuln.Type == "none_algorithm_bypass" {
					successfulAttacks++
				}
				// High risk score + critical severity = likely exploitable
				if vuln.Severity == "critical" && vuln.RiskScore >= 85 {
					successfulAttacks++
				}
			}
		} else {
			fmt.Printf("DEBUG JWT: Type assertion failed!\n")
		}

	case "dos":
		if dosData, ok := moduleData.(*dos.DoSTestResult); ok {
			// Count services actually impacted
			for _, result := range dosData.AttackResults {
				if result.ServiceImpacted {
					successfulAttacks++
				}
			}
			// Service degradation is critical
			if dosData.ServiceDegradation {
				successfulAttacks += 2
			}
		}

	case "injection":
		if injData, ok := moduleData.(*injection.InjectionTestResult); ok {
			for _, vuln := range injData.VulnerabilitiesFound {
				// Critical injection vulnerabilities = successful exploitation
				if vuln.Severity == "critical" ||
					(vuln.Severity == "high" && vuln.RiskScore >= 85) {
					successfulAttacks++
				}
			}
		}

	case "hmac":
		if hmacData, ok := moduleData.(*hmac.HMACTestResult); ok {
			// Count actual successful replay attacks
			successfulAttacks = hmacData.ReplayAttemptsSuccessful
		}

	case "api":
		if apiData, ok := moduleData.(*api.EnumerationResult); ok {
			// Count endpoints with very low security scores (compromised)
			for _, endpoint := range apiData.FoundEndpoints {
				if endpoint.SecurityScore < 30 {
					successfulAttacks++
				}
			}
		}

	case "tls":
		if tlsData, ok := moduleData.(*tls.TLSTestResult); ok {
			for _, vuln := range tlsData.VulnerabilitiesFound {
				// Count exploitable TLS vulnerabilities only
				if vuln.Exploitable && vuln.RiskScore >= 80 {
					successfulAttacks++
				}
			}
		}

	default:
		totalVulns := rg.getVulnerabilityCount(moduleData)
		if totalVulns > 0 {
			successfulAttacks = int(float64(totalVulns) * 0.2)
		}
	}

	return successfulAttacks
}

// countPotentialVulnerabilities counts theoretical/configuration vulnerabilities
func (rg *ReportGenerator) countPotentialVulnerabilities(moduleType string, moduleData any) int {
	if moduleData == nil {
		return 0
	}

	potentialVulns := 0

	switch moduleType {
	case "jwt":
		if jwtData, ok := moduleData.(*jwt.JWTTestResult); ok {
			for _, vuln := range jwtData.VulnerabilitiesFound {
				// Skip successful attacks, count the rest as potential
				if vuln.Type != "none_algorithm_bypass" &&
					!(vuln.Severity == "critical" && vuln.RiskScore >= 85) {
					potentialVulns++
				}
			}
		}

	case "tls":
		if tlsData, ok := moduleData.(*tls.TLSTestResult); ok {
			for _, vuln := range tlsData.VulnerabilitiesFound {
				// Count non-exploitable or low-risk config issues
				if !vuln.Exploitable || vuln.RiskScore < 80 {
					potentialVulns++
				}
			}
		}

	case "injection":
		if injData, ok := moduleData.(*injection.InjectionTestResult); ok {
			for _, vuln := range injData.VulnerabilitiesFound {
				if vuln.Severity != "critical" &&
					!(vuln.Severity == "high" && vuln.RiskScore >= 85) {
					potentialVulns++
				}
			}
		}

	case "dos":
		if dosData, ok := moduleData.(*dos.DoSTestResult); ok {
			if dosData.ServiceDegradation {
				totalVulns := len(dosData.VulnerabilitiesFound)
				successfulAttacks := rg.countSuccessfulAttacks("dos", moduleData)
				potentialVulns = totalVulns - successfulAttacks
			} else {
				potentialVulns = len(dosData.VulnerabilitiesFound)
			}
		}

	case "api":
		if apiData, ok := moduleData.(*api.EnumerationResult); ok {
			potentialVulns = len(apiData.Vulnerabilities)
		}

	case "hmac":
		if hmacData, ok := moduleData.(*hmac.HMACTestResult); ok {
			// Total vulnerabilities minus successful attacks = potential
			totalVulns := len(hmacData.VulnerabilitiesFound)
			potentialVulns = totalVulns - hmacData.ReplayAttemptsSuccessful
		}

	default:
		totalVulns := rg.getVulnerabilityCount(moduleData)
		successfulAttacks := rg.countSuccessfulAttacks(moduleType, moduleData)
		potentialVulns = totalVulns - successfulAttacks

		if successfulAttacks == 0 && totalVulns > 0 {
			potentialVulns = int(float64(totalVulns) * 0.8)
		}
	}

	return potentialVulns
}

// getVulnerabilityCount gets total vulnerability count from any module
func (rg *ReportGenerator) getVulnerabilityCount(moduleData any) int {
	if moduleData == nil {
		return 0
	}

	// Type switching based on actual module structures
	switch data := moduleData.(type) {
	case *jwt.JWTTestResult:
		return len(data.VulnerabilitiesFound)

	case *tls.TLSTestResult:
		return len(data.VulnerabilitiesFound)

	case *injection.InjectionTestResult:
		return len(data.VulnerabilitiesFound)

	case *dos.DoSTestResult:
		return len(data.VulnerabilitiesFound)

	case *hmac.HMACTestResult:
		return len(data.VulnerabilitiesFound)

	case *api.EnumerationResult:
		return len(data.Vulnerabilities)

	default:
		// Fallback: try reflection if it's an unknown type
		return rg.getVulnerabilityCountViaReflection(moduleData)
	}
}

// getVulnerabilityCountViaReflection fallback using reflection for unknown types
func (rg *ReportGenerator) getVulnerabilityCountViaReflection(moduleData any) int {
	if moduleData == nil {
		return 0
	}

	// Use reflection as fallback
	val := reflect.ValueOf(moduleData)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return 0
	}

	// Look for common vulnerability field names
	vulnerabilityFields := []string{
		"VulnerabilitiesFound",
		"Vulnerabilities",
		"VulnerabilityList",
		"Issues",
		"Findings",
	}

	for _, fieldName := range vulnerabilityFields {
		field := val.FieldByName(fieldName)
		if field.IsValid() && field.Kind() == reflect.Slice {
			return field.Len()
		}
	}

	return 0
}
