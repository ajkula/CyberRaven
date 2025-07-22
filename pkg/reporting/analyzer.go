package reporting

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/ajkula/cyberraven/cmd/attack"
	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/attacks/dos"
	"github.com/ajkula/cyberraven/pkg/attacks/hmac"
	"github.com/ajkula/cyberraven/pkg/attacks/injection"
	"github.com/ajkula/cyberraven/pkg/attacks/jwt"
	"github.com/ajkula/cyberraven/pkg/attacks/tls"
)

// ModuleConfig defines configuration for processing a module
type ModuleConfig struct {
	name        string
	key         string
	moduleData  any
	isAPIModule bool
}

func (rg *ReportGenerator) analyzeVulnerabilities(result *attack.AttackResult) VulnerabilityAnalysis {
	analysis := VulnerabilityAnalysis{
		ByCategory:     make(map[string]int),
		BySeverity:     make(map[string]int),
		TopIssues:      []VulnerabilityDetail{},
		ModuleAnalysis: make(map[string]ModuleVulnerabilityAnalysis),
	}

	fmt.Printf("DEBUG: Starting analysis...\n")
	fmt.Printf("DEBUG: JWT data present: %v\n", result.JWTTesting != nil)

	// Define module configurations
	modules := []ModuleConfig{
		{"API Enumeration", "api_enumeration", result.APIEnumeration, true},
		{"JWT Security", "jwt_testing", result.JWTTesting, false},
		{"Injection Testing", "injection_testing", result.InjectionTesting, false},
		{"HMAC Security", "hmac_testing", result.HMACTesting, false},
		{"DoS Assessment", "dos_testing", result.DoSTesting, false},
		{"TLS Security", "tls_testing", result.TLSTesting, false},
	}

	// Process each module
	for _, moduleConfig := range modules {
		if moduleConfig.moduleData != nil {
			rg.processModule(moduleConfig, &analysis)
		}
	}

	// Sort and limit top issues
	sort.Slice(analysis.TopIssues, func(i, j int) bool {
		return analysis.TopIssues[i].RiskScore > analysis.TopIssues[j].RiskScore
	})

	if len(analysis.TopIssues) > 20 {
		analysis.TopIssues = analysis.TopIssues[:20]
	}

	fmt.Printf("DEBUG: ModuleAnalysis count: %d\n", len(analysis.ModuleAnalysis))
	return analysis
}

func (rg *ReportGenerator) processModule(config ModuleConfig, analysis *VulnerabilityAnalysis) {
	moduleAnalysis := ModuleVulnerabilityAnalysis{
		ModuleName:      config.name,
		Vulnerabilities: []VulnerabilityDetail{},
	}

	// Extract module-specific data based on type
	switch config.key {
	case "api_enumeration":
		if apiResult := config.moduleData.(*api.EnumerationResult); apiResult != nil {
			moduleAnalysis.TestsExecuted = apiResult.TestedEndpoints
			moduleAnalysis.TestDuration = apiResult.Duration
			moduleAnalysis.RequestsPerSecond = apiResult.RequestsPerSecond

			for _, vuln := range apiResult.Vulnerabilities {
				detail := rg.processVulnerabilityToDetail(vuln)
				rg.addToAnalysis(detail, analysis)
				moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, detail)
			}
		}

	case "jwt_testing":
		if jwtResult := config.moduleData.(*jwt.JWTTestResult); jwtResult != nil {
			moduleAnalysis.TestsExecuted = jwtResult.TestsExecuted
			moduleAnalysis.TestDuration = jwtResult.Duration
			moduleAnalysis.RequestsPerSecond = jwtResult.RequestsPerSecond

			for _, vuln := range jwtResult.VulnerabilitiesFound {
				if detail := rg.processGenericVulnerabilityToDetail(vuln); detail != nil {
					rg.addToAnalysis(*detail, analysis)
					moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, *detail)
				}
			}
		}

	case "injection_testing":
		if injResult := config.moduleData.(*injection.InjectionTestResult); injResult != nil {
			moduleAnalysis.TestsExecuted = injResult.TestsExecuted
			moduleAnalysis.TestDuration = injResult.Duration
			moduleAnalysis.RequestsPerSecond = injResult.RequestsPerSecond

			for _, vuln := range injResult.VulnerabilitiesFound {
				if detail := rg.processGenericVulnerabilityToDetail(vuln); detail != nil {
					rg.addToAnalysis(*detail, analysis)
					moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, *detail)
				}
			}
		}

	case "hmac_testing":
		if hmacResult := config.moduleData.(*hmac.HMACTestResult); hmacResult != nil {
			moduleAnalysis.TestsExecuted = hmacResult.TestsExecuted
			moduleAnalysis.TestDuration = hmacResult.Duration
			moduleAnalysis.RequestsPerSecond = hmacResult.RequestsPerSecond

			for _, vuln := range hmacResult.VulnerabilitiesFound {
				if detail := rg.processGenericVulnerabilityToDetail(vuln); detail != nil {
					rg.addToAnalysis(*detail, analysis)
					moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, *detail)
				}
			}
		}

	case "dos_testing":
		if dosResult := config.moduleData.(*dos.DoSTestResult); dosResult != nil {
			moduleAnalysis.TestsExecuted = dosResult.TestsExecuted
			moduleAnalysis.TestDuration = dosResult.Duration
			moduleAnalysis.RequestsPerSecond = dosResult.RequestsPerSecond

			for _, vuln := range dosResult.VulnerabilitiesFound {
				if detail := rg.processGenericVulnerabilityToDetail(vuln); detail != nil {
					rg.addToAnalysis(*detail, analysis)
					moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, *detail)
				}
			}
		}

	case "tls_testing":
		if tlsResult := config.moduleData.(*tls.TLSTestResult); tlsResult != nil {
			moduleAnalysis.TestsExecuted = tlsResult.TestsExecuted
			moduleAnalysis.TestDuration = tlsResult.Duration
			moduleAnalysis.RequestsPerSecond = tlsResult.RequestsPerSecond

			for _, vuln := range tlsResult.VulnerabilitiesFound {
				if detail := rg.processGenericVulnerabilityToDetail(vuln); detail != nil {
					rg.addToAnalysis(*detail, analysis)
					moduleAnalysis.Vulnerabilities = append(moduleAnalysis.Vulnerabilities, *detail)
				}
			}
		}
	}

	rg.finalizeModuleAnalysis(&moduleAnalysis)
	analysis.ModuleAnalysis[config.key] = moduleAnalysis
}

// process different vulnerability types

// processVulnerabilityToDetail processes API enumeration vulnerabilities to detail
func (rg *ReportGenerator) processVulnerabilityToDetail(vuln api.VulnerabilityFinding) VulnerabilityDetail {
	return VulnerabilityDetail{
		VulnerabilityFinding: vuln,
		RiskScore:            rg.calculateRiskScore(vuln),
		AffectedURLs:         []string{vuln.Endpoint},
		References:           rg.getVulnerabilityReferences(vuln.Type),
	}
}

// processGenericVulnerabilityToDetail processes vulnerabilities from any module using interface parsing
func (rg *ReportGenerator) processGenericVulnerabilityToDetail(vuln any) *VulnerabilityDetail {
	// Convert struct to map using reflection
	vulnMap := rg.structToMap(vuln)
	if vulnMap == nil {
		return nil
	}

	finding := api.VulnerabilityFinding{
		Type:        rg.extractString(vulnMap, "type"),
		Severity:    rg.extractString(vulnMap, "severity"),
		Endpoint:    rg.extractString(vulnMap, "endpoint"),
		Method:      rg.extractString(vulnMap, "method"),
		Description: rg.extractString(vulnMap, "description"),
		Evidence:    rg.extractString(vulnMap, "evidence"),
		Remediation: rg.extractString(vulnMap, "remediation"),
	}

	riskScore := int(rg.extractFloat64(vulnMap, "risk_score"))

	return &VulnerabilityDetail{
		VulnerabilityFinding: finding,
		RiskScore:            riskScore,
		AffectedURLs:         []string{finding.Endpoint},
		References:           rg.getVulnerabilityReferences(finding.Type),
	}
}

// structToMap converts any struct to map[string]any using reflection
func (rg *ReportGenerator) structToMap(obj any) map[string]any {
	if obj == nil {
		return nil
	}

	result := make(map[string]any)
	val := reflect.ValueOf(obj)
	typ := reflect.TypeOf(obj)

	// Handle pointer
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
		typ = typ.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Get JSON tag or use field name
		tagName := fieldType.Tag.Get("json")
		if tagName == "" || tagName == "-" {
			tagName = strings.ToLower(fieldType.Name)
		} else {
			// Remove ",omitempty" etc
			if idx := strings.Index(tagName, ","); idx != -1 {
				tagName = tagName[:idx]
			}
		}

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		result[tagName] = field.Interface()
	}

	return result
}

// addToAnalysis adds a vulnerability detail to the overall analysis
func (rg *ReportGenerator) addToAnalysis(detail VulnerabilityDetail, analysis *VulnerabilityAnalysis) {
	analysis.ByCategory[detail.Type]++
	analysis.BySeverity[detail.Severity]++
	analysis.TopIssues = append(analysis.TopIssues, detail)
}

// finalizeModuleAnalysis calculates final statistics for a module
func (rg *ReportGenerator) finalizeModuleAnalysis(moduleAnalysis *ModuleVulnerabilityAnalysis) {
	moduleAnalysis.VulnCount = len(moduleAnalysis.Vulnerabilities)

	// Find highest severity
	severityPriority := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	highestPriority := 0

	for _, vuln := range moduleAnalysis.Vulnerabilities {
		if priority := severityPriority[strings.ToLower(vuln.Severity)]; priority > highestPriority {
			highestPriority = priority
			moduleAnalysis.HighestSeverity = vuln.Severity
		}
	}

	if moduleAnalysis.HighestSeverity == "" {
		moduleAnalysis.HighestSeverity = "none"
	}
}

// Helper functions for safe type extraction
func (rg *ReportGenerator) extractString(m map[string]any, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func (rg *ReportGenerator) extractFloat64(m map[string]any, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return 0.0
}
