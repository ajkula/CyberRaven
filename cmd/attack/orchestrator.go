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

	// Execute API enumeration if enabled
	if ao.isModuleEnabled("api") && ao.config.Attacks.API.Enable {
		ao.executeAPIModule(ctx, result)
	}

	// Execute JWT testing if enabled
	if ao.isModuleEnabled("jwt") && ao.config.Attacks.JWT.Enable {
		ao.executeJWTModule(ctx, result)
	}

	// Execute Injection testing if enabled
	if ao.isModuleEnabled("injection") && ao.config.Attacks.Injection.Enable {
		ao.executeInjectionModule(ctx, result)
	}

	// Execute HMAC testing if enabled
	if ao.isModuleEnabled("hmac") && ao.config.Attacks.HMAC.Enable {
		ao.executeHMACModule(ctx, result)
	}

	// Execute DoS testing if enabled
	if ao.isModuleEnabled("dos") && ao.config.Attacks.DoS.Enable {
		ao.executeDoSModule(ctx, result)
	}

	// Execute TLS testing if enabled
	if ao.isModuleEnabled("tls") && ao.config.Attacks.TLS.Enable {
		ao.executeTLSModule(ctx, result)
	}

	// Finalize results
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	ao.calculateSummaryStats(result)

	return result, nil
}

// executeAPIModule executes the API enumeration module
func (ao *AttackOrchestrator) executeAPIModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("API Enumeration")

	enumerator, err := api.NewEnumeratorWithDiscovery(ao.config.Attacks.API, ao.target)
	if err != nil {
		printError(fmt.Sprintf("Failed to create API enumerator: %v", err), ao.noColor)
		return
	}
	defer enumerator.Close()

	apiResult, err := enumerator.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("API enumeration failed: %v", err), ao.noColor)
		return
	}

	result.APIEnumeration = apiResult
	ao.printModuleComplete("API Enumeration", apiResult)
}

// executeJWTModule executes the JWT security testing module
func (ao *AttackOrchestrator) executeJWTModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("JWT Security Testing")

	jwtFuzzer, err := jwt.NewJWTFuzzer(ao.config.Attacks.JWT, ao.target)
	if err != nil {
		printError(fmt.Sprintf("Failed to create JWT fuzzer: %v", err), ao.noColor)
		return
	}
	defer jwtFuzzer.Close()

	jwtResult, err := jwtFuzzer.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("JWT testing failed: %v", err), ao.noColor)
		return
	}

	result.JWTTesting = jwtResult
	ao.printJWTModuleComplete("JWT Security Testing", jwtResult)
}

// executeInjectionModule executes the injection security testing module
func (ao *AttackOrchestrator) executeInjectionModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("Injection Security Testing")

	injectionTester, err := injection.NewInjectionTester(ao.config.Attacks.Injection, ao.target, ao.attackContext)
	if err != nil {
		printError(fmt.Sprintf("Failed to create injection tester: %v", err), ao.noColor)
		return
	}
	defer injectionTester.Close()

	injectionResult, err := injectionTester.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("Injection testing failed: %v", err), ao.noColor)
		return
	}

	result.InjectionTesting = injectionResult
	ao.printInjectionModuleComplete("Injection Security Testing", injectionResult)
}

// executeHMACModule executes the HMAC security testing module
func (ao *AttackOrchestrator) executeHMACModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("HMAC Security Testing")

	hmacTester, err := hmac.NewHMACTester(ao.config.Attacks.HMAC, ao.target)
	if err != nil {
		printError(fmt.Sprintf("Failed to create HMAC tester: %v", err), ao.noColor)
		return
	}
	defer hmacTester.Close()

	hmacResult, err := hmacTester.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("HMAC testing failed: %v", err), ao.noColor)
		return
	}

	result.HMACTesting = hmacResult
	ao.printHMACModuleComplete("HMAC Security Testing", hmacResult)
}

// executeDoSModule executes the DoS security testing module
func (ao *AttackOrchestrator) executeDoSModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("DoS Security Testing")

	dosTester, err := dos.NewDoSTester(ao.config.Attacks.DoS, ao.target, ao.attackContext)
	if err != nil {
		printError(fmt.Sprintf("Failed to create DoS tester: %v", err), ao.noColor)
		return
	}
	defer dosTester.Close()

	dosResult, err := dosTester.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("DoS testing failed: %v", err), ao.noColor)
		return
	}

	result.DoSTesting = dosResult
	ao.printDoSModuleComplete("DoS Security Testing", dosResult)
}

// executeTLSModule executes the TLS security testing module
func (ao *AttackOrchestrator) executeTLSModule(ctx context.Context, result *AttackResult) {
	ao.printModuleStart("TLS Security Testing")

	tlsTester, err := tls.NewTLSTester(ao.config.Attacks.TLS, ao.target, ao.attackContext)
	if err != nil {
		printError(fmt.Sprintf("Failed to create TLS tester: %v", err), ao.noColor)
		return
	}
	defer tlsTester.Close()

	tlsResult, err := tlsTester.Execute(ctx)
	if err != nil {
		printError(fmt.Sprintf("TLS testing failed: %v", err), ao.noColor)
		return
	}

	result.TLSTesting = tlsResult
	ao.printTLSModuleComplete("TLS Security Testing", tlsResult)
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

// SaveKillChainResults saves the kill chain results to files
func (ao *AttackOrchestrator) SaveKillChainResults(result *KillChainResult) error {
	// Create output directory
	if ao.outputDir == "" {
		ao.outputDir = "./results"
	}

	if err := os.MkdirAll(ao.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save JSON result
	filename := fmt.Sprintf("killchain_%s.json", result.SessionID)
	filepath := filepath.Join(ao.outputDir, filename)

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal kill chain results: %w", err)
	}

	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write kill chain results file: %w", err)
	}

	printSuccess(fmt.Sprintf("Kill Chain results saved to: %s", filepath), ao.noColor)
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

// countVulnerabilitiesBySeverity counts vulnerabilities and updates severity counters
func (ao *AttackOrchestrator) countVulnerabilitiesBySeverity(result *AttackResult, severities []string) {
	for _, severity := range severities {
		result.TotalVulnerabilities++
		switch strings.ToLower(severity) {
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

// extractSeverities extracts severity strings from different vulnerability types
func (ao *AttackOrchestrator) extractSeverities(result *AttackResult) []string {
	var severities []string

	// Extract API vulnerabilities
	if result.APIEnumeration != nil {
		for _, vuln := range result.APIEnumeration.Vulnerabilities {
			severities = append(severities, vuln.Severity)
		}
	}

	// Extract JWT vulnerabilities
	if result.JWTTesting != nil {
		for _, vuln := range result.JWTTesting.VulnerabilitiesFound {
			severities = append(severities, vuln.Severity)
		}
	}

	// Extract injection vulnerabilities
	if result.InjectionTesting != nil {
		for _, vuln := range result.InjectionTesting.VulnerabilitiesFound {
			severities = append(severities, vuln.Severity)
		}
	}

	// Extract HMAC vulnerabilities
	if result.HMACTesting != nil {
		for _, vuln := range result.HMACTesting.VulnerabilitiesFound {
			severities = append(severities, vuln.Severity)
		}
	}

	// Extract DoS vulnerabilities
	if result.DoSTesting != nil {
		for _, vuln := range result.DoSTesting.VulnerabilitiesFound {
			severities = append(severities, vuln.Severity)
		}
	}

	// Extract TLS vulnerabilities
	if result.TLSTesting != nil {
		for _, vuln := range result.TLSTesting.VulnerabilitiesFound {
			severities = append(severities, vuln.Severity)
		}
	}

	return severities
}

// calculateSummaryStats calculates vulnerability statistics across all modules (DRY version)
func (ao *AttackOrchestrator) calculateSummaryStats(result *AttackResult) {
	// Extract all severities and count them
	severities := ao.extractSeverities(result)
	ao.countVulnerabilitiesBySeverity(result, severities)
}

// ============================================================
// KILL CHAIN EXECUTION - Progression conditionnelle
// ============================================================

// ExecuteKillChain exécute les attaques en chaîne conditionnelle
// Phase 1: TLS Exploitation - Tentative de casser TLS
// Phase 2: Application Attacks - Si TLS compromis, attaques via canal compromis
// Phase 3: Escalation - Si vulnérabilités trouvées
func (ao *AttackOrchestrator) ExecuteKillChain(ctx context.Context) (*KillChainResult, error) {
	startTime := time.Now()
	sessionID := fmt.Sprintf("kc_%d", startTime.Unix())

	result := &KillChainResult{
		SessionID:  sessionID,
		StartTime:  startTime,
		Target:     *ao.target,
		Phases:     make([]PhaseResult, 0),
	}

	ao.printKillChainHeader()

	// ========================================
	// PHASE 1: TLS EXPLOITATION
	// ========================================
	ao.printPhaseStart(PhaseTLSExploit, "Tentative d'exploitation TLS")

	tlsPhase := ao.executeTLSExploitationPhase(ctx)
	result.Phases = append(result.Phases, tlsPhase)
	ao.killChainState.AdvancePhase(PhaseTLSExploit, &tlsPhase)

	ao.printPhaseResult(PhaseTLSExploit, &tlsPhase)

	// Décision: continuer ou s'arrêter
	if !tlsPhase.TLSCompromised {
		// TLS secure - documenter et terminer
		result.TLSStatus = "secure"
		result.Progression = "Phase 1 only - TLS secure"
		result.Summary = "TLS protection is effective. Target appears secure against TLS exploitation attempts."
		result.FinalPhase = PhaseTLSExploit

		ao.printKillChainConclusion(result)
	} else {
		// TLS compromis - continuer avec les attaques applicatives
		result.TLSStatus = "compromised"
		result.CompromiseMethod = tlsPhase.CompromiseMethod

		ao.printColor(ColorRed, "\n[!] TLS COMPROMIS via %s - Poursuite des attaques via canal compromis\n", tlsPhase.CompromiseMethod)

		// ========================================
		// PHASE 2: APPLICATION ATTACKS
		// ========================================
		ao.printPhaseStart(PhaseAppAttacks, "Attaques applicatives via canal compromis")

		appPhase := ao.executeApplicationAttacksPhase(ctx)
		result.Phases = append(result.Phases, appPhase)
		ao.killChainState.AdvancePhase(PhaseAppAttacks, &appPhase)

		// Stocker les résultats des modules
		result.APIEnumeration = ao.getAPIResult()
		result.JWTTesting = ao.getJWTResult()
		result.InjectionTesting = ao.getInjectionResult()
		result.HMACTesting = ao.getHMACResult()
		result.DoSTesting = ao.getDoSResult()
		result.TLSTesting = ao.getTLSResult()

		ao.printPhaseResult(PhaseAppAttacks, &appPhase)

		// ========================================
		// PHASE 3: ESCALATION (si vulnérabilités trouvées)
		// ========================================
		if appPhase.HasVulnerabilities() {
			ao.printPhaseStart(PhaseEscalation, "Tentative d'escalade")

			escPhase := ao.executeEscalationPhase(ctx)
			result.Phases = append(result.Phases, escPhase)
			ao.killChainState.AdvancePhase(PhaseEscalation, &escPhase)

			ao.printPhaseResult(PhaseEscalation, &escPhase)
			result.FinalPhase = PhaseEscalation
			result.Progression = "Full chain - TLS compromised + Application attacks + Escalation"
		} else {
			result.FinalPhase = PhaseAppAttacks
			result.Progression = "Partial chain - TLS compromised + Application attacks"
		}

		result.Summary = fmt.Sprintf("TLS compromised via %s. Application layer attacks executed through compromised channel.",
			tlsPhase.CompromiseMethod)

		ao.printKillChainConclusion(result)
	}

	// Finaliser
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculer les statistiques de vulnérabilités
	ao.calculateKillChainStats(result)

	return result, nil
}

// executeTLSExploitationPhase exécute la phase d'exploitation TLS
func (ao *AttackOrchestrator) executeTLSExploitationPhase(ctx context.Context) PhaseResult {
	startTime := time.Now()

	phase := PhaseResult{
		Phase:     PhaseTLSExploit,
		Status:    StatusRunning,
		StartTime: startTime,
		Findings:  make([]Finding, 0),
	}

	// Exécuter le module TLS avec mode exploitation
	if ao.config.Attacks.TLS.Enable {
		ao.printColor(ColorCyan, "  [*] Analyse TLS et tentative d'exploitation...\n")

		tlsTester, err := tls.NewTLSTester(ao.config.Attacks.TLS, ao.target, ao.attackContext)
		if err != nil {
			phase.Status = StatusFailed
			phase.SkipReason = fmt.Sprintf("Failed to create TLS tester: %v", err)
			phase.EndTime = time.Now()
			phase.Duration = phase.EndTime.Sub(startTime)
			return phase
		}
		defer tlsTester.Close()

		tlsResult, err := tlsTester.Execute(ctx)
		if err != nil {
			phase.Status = StatusFailed
			phase.SkipReason = fmt.Sprintf("TLS testing failed: %v", err)
			phase.EndTime = time.Now()
			phase.Duration = phase.EndTime.Sub(startTime)
			return phase
		}

		// Analyser les résultats pour déterminer si TLS est exploitable
		phase.TLSCompromised, phase.CompromiseMethod = ao.analyzeTLSExploitability(tlsResult)

		// Convertir les vulnérabilités TLS en findings
		for _, vuln := range tlsResult.VulnerabilitiesFound {
			phase.Findings = append(phase.Findings, Finding{
				Type:        vuln.Type,
				Severity:    vuln.Severity,
				Title:       vuln.Type,
				Description: vuln.Description,
				Evidence:    vuln.Evidence,
				Remediation: vuln.Remediation,
			})
		}
		phase.VulnCount = len(tlsResult.VulnerabilitiesFound)
	} else {
		phase.Status = StatusSkipped
		phase.SkipReason = "TLS testing disabled in config"
	}

	// Déterminer l'état final
	if phase.TLSCompromised {
		phase.Status = StatusSuccess
		phase.Compromised = true
		phase.CanContinue = true
		phase.NextPhase = PhaseAppAttacks
		phase.ProxyActive = false // Pour l'instant pas de vrai proxy

		ao.printColor(ColorRed, "  [!] TLS EXPLOITABLE - Méthode: %s\n", phase.CompromiseMethod)
	} else {
		phase.Status = StatusSuccess // Test réussi, même si pas de compromis
		phase.Compromised = false
		phase.CanContinue = false
		phase.SkipReason = "TLS configuration is secure, no exploitable weaknesses found"

		ao.printColor(ColorGreen, "  [+] TLS Secure - Aucune faiblesse exploitable\n")
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(startTime)

	return phase
}

// analyzeTLSExploitability analyse les résultats TLS pour déterminer l'exploitabilité
func (ao *AttackOrchestrator) analyzeTLSExploitability(tlsResult *tls.TLSTestResult) (bool, string) {
	if tlsResult == nil {
		return false, ""
	}

	// Critères d'exploitabilité réelle
	for _, vuln := range tlsResult.VulnerabilitiesFound {
		// Exploitable si:
		// 1. Protocole vulnérable (SSL3, TLS1.0 avec CBC = POODLE/BEAST)
		if strings.Contains(vuln.Type, "downgrade") && vuln.Exploitable {
			if strings.Contains(vuln.Evidence, "SSL") || strings.Contains(vuln.Evidence, "TLS 1.0") {
				return true, "Protocol Downgrade (POODLE/BEAST potential)"
			}
		}

		// 2. Cipher faible RC4, DES, Export
		if strings.Contains(vuln.Type, "cipher") && vuln.Severity == "critical" {
			if strings.Contains(strings.ToUpper(vuln.CipherSuite), "RC4") ||
				strings.Contains(strings.ToUpper(vuln.CipherSuite), "DES") ||
				strings.Contains(strings.ToUpper(vuln.CipherSuite), "EXPORT") {
				return true, fmt.Sprintf("Weak Cipher (%s)", vuln.CipherSuite)
			}
		}

		// 3. Certificat self-signed ou expiré (MITM possible)
		if strings.Contains(vuln.Type, "certificate") {
			if strings.Contains(vuln.Description, "self-signed") ||
				strings.Contains(vuln.Description, "expired") {
				return true, "Certificate Weakness (MITM possible)"
			}
		}

		// 4. Renegotiation insécure
		if strings.Contains(vuln.Type, "renegotiation") && vuln.Severity == "critical" {
			return true, "Insecure Renegotiation"
		}
	}

	// Vérifier les résultats de downgrade
	for _, downgrade := range tlsResult.DowngradeTests {
		if downgrade.IsVulnerable && downgrade.MITMPossible {
			return true, fmt.Sprintf("Protocol Downgrade to %s", downgrade.NegotiatedVersion)
		}
	}

	return false, ""
}

// executeApplicationAttacksPhase exécute les attaques applicatives
func (ao *AttackOrchestrator) executeApplicationAttacksPhase(ctx context.Context) PhaseResult {
	startTime := time.Now()

	phase := PhaseResult{
		Phase:     PhaseAppAttacks,
		Status:    StatusRunning,
		StartTime: startTime,
		Findings:  make([]Finding, 0),
	}

	// Note: Si on avait un vrai proxy MITM, on l'utiliserait ici
	// Pour l'instant, on exécute les attaques normalement mais on documente
	// que c'est via le "canal compromis"

	if ao.killChainState.TLSCompromised {
		ao.printColor(ColorYellow, "  [*] Exécution des attaques via canal TLS compromis...\n")
	}

	// Créer un résultat temporaire pour collecter les résultats des modules
	tempResult := &AttackResult{
		EnabledModules: ao.config.Attacks.Enabled,
		AggressiveMode: ao.config.Attacks.Aggressive,
	}

	// API Enumeration
	if ao.isModuleEnabled("api") && ao.config.Attacks.API.Enable {
		ao.printColor(ColorCyan, "  [*] API Enumeration...\n")
		ao.executeAPIModule(ctx, tempResult)
		if tempResult.APIEnumeration != nil {
			for _, vuln := range tempResult.APIEnumeration.Vulnerabilities {
				phase.Findings = append(phase.Findings, Finding{
					Type:        vuln.Type,
					Severity:    vuln.Severity,
					Title:       vuln.Type,
					Description: vuln.Description,
					Evidence:    vuln.Evidence,
					Remediation: vuln.Remediation,
				})
			}
		}
	}

	// JWT Testing
	if ao.isModuleEnabled("jwt") && ao.config.Attacks.JWT.Enable {
		ao.printColor(ColorCyan, "  [*] JWT Security Testing...\n")
		ao.executeJWTModule(ctx, tempResult)
		if tempResult.JWTTesting != nil {
			for _, vuln := range tempResult.JWTTesting.VulnerabilitiesFound {
				phase.Findings = append(phase.Findings, Finding{
					Type:        vuln.Type,
					Severity:    vuln.Severity,
					Title:       vuln.Type,
					Description: vuln.Description,
					Evidence:    vuln.Evidence,
					Remediation: vuln.Remediation,
				})
			}
		}
	}

	// Injection Testing
	if ao.isModuleEnabled("injection") && ao.config.Attacks.Injection.Enable {
		ao.printColor(ColorCyan, "  [*] Injection Testing...\n")
		ao.executeInjectionModule(ctx, tempResult)
		if tempResult.InjectionTesting != nil {
			for _, vuln := range tempResult.InjectionTesting.VulnerabilitiesFound {
				phase.Findings = append(phase.Findings, Finding{
					Type:        vuln.Type,
					Severity:    vuln.Severity,
					Title:       vuln.Type,
					Description: vuln.Description,
					Evidence:    vuln.Evidence,
					Remediation: vuln.Remediation,
				})
			}
		}
	}

	// HMAC Testing
	if ao.isModuleEnabled("hmac") && ao.config.Attacks.HMAC.Enable {
		ao.printColor(ColorCyan, "  [*] HMAC Security Testing...\n")
		ao.executeHMACModule(ctx, tempResult)
		if tempResult.HMACTesting != nil {
			for _, vuln := range tempResult.HMACTesting.VulnerabilitiesFound {
				phase.Findings = append(phase.Findings, Finding{
					Type:        vuln.Type,
					Severity:    vuln.Severity,
					Title:       vuln.Type,
					Description: vuln.Description,
					Evidence:    vuln.Evidence,
					Remediation: vuln.Remediation,
				})
			}
		}
	}

	// DoS Testing
	if ao.isModuleEnabled("dos") && ao.config.Attacks.DoS.Enable {
		ao.printColor(ColorCyan, "  [*] DoS Security Testing...\n")
		ao.executeDoSModule(ctx, tempResult)
		if tempResult.DoSTesting != nil {
			for _, vuln := range tempResult.DoSTesting.VulnerabilitiesFound {
				phase.Findings = append(phase.Findings, Finding{
					Type:        vuln.Type,
					Severity:    vuln.Severity,
					Title:       vuln.Type,
					Description: vuln.Description,
					Evidence:    vuln.Evidence,
					Remediation: vuln.Remediation,
				})
			}
		}
	}

	phase.VulnCount = len(phase.Findings)

	// Déterminer l'état final
	if phase.VulnCount > 0 {
		phase.Status = StatusSuccess
		phase.Compromised = true
		phase.CanContinue = true
		phase.NextPhase = PhaseEscalation
	} else {
		phase.Status = StatusSuccess
		phase.Compromised = false
		phase.CanContinue = false
	}

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(startTime)

	return phase
}

// executeEscalationPhase exécute la phase d'escalade
func (ao *AttackOrchestrator) executeEscalationPhase(ctx context.Context) PhaseResult {
	startTime := time.Now()

	phase := PhaseResult{
		Phase:     PhaseEscalation,
		Status:    StatusRunning,
		StartTime: startTime,
		Findings:  make([]Finding, 0),
	}

	ao.printColor(ColorYellow, "  [*] Analyse des vulnérabilités pour escalade potentielle...\n")

	// Analyser les vulnérabilités trouvées pour identifier les opportunités d'escalade
	// Cette phase est conceptuelle pour l'instant - elle documente les chemins d'escalade possibles

	escalationPaths := ao.identifyEscalationPaths()

	for _, path := range escalationPaths {
		phase.Findings = append(phase.Findings, Finding{
			Type:        "escalation_path",
			Severity:    path.Severity,
			Title:       path.Title,
			Description: path.Description,
			Evidence:    path.Evidence,
			Remediation: path.Remediation,
		})
	}

	phase.VulnCount = len(phase.Findings)
	phase.Status = StatusSuccess
	phase.CanContinue = false

	phase.EndTime = time.Now()
	phase.Duration = phase.EndTime.Sub(startTime)

	return phase
}

// identifyEscalationPaths identifie les chemins d'escalade basés sur les vulnérabilités trouvées
func (ao *AttackOrchestrator) identifyEscalationPaths() []Finding {
	paths := make([]Finding, 0)

	// Analyser le kill chain state pour les opportunités d'escalade
	for _, phaseResult := range ao.killChainState.Phases {
		for _, finding := range phaseResult.Findings {
			// JWT vulnérabilités → accès admin potentiel
			if strings.Contains(finding.Type, "jwt") && finding.Severity == "critical" {
				paths = append(paths, Finding{
					Type:        "privilege_escalation",
					Severity:    "critical",
					Title:       "JWT Exploitation → Privilege Escalation",
					Description: fmt.Sprintf("JWT vulnerability (%s) may allow privilege escalation to admin", finding.Title),
					Evidence:    finding.Evidence,
					Remediation: "Fix JWT vulnerability and implement proper authorization checks",
				})
			}

			// Injection → Data exfiltration
			if strings.Contains(finding.Type, "injection") && finding.Severity == "critical" {
				paths = append(paths, Finding{
					Type:        "data_exfiltration",
					Severity:    "critical",
					Title:       "Injection → Data Exfiltration",
					Description: fmt.Sprintf("Injection vulnerability (%s) may allow database access and data exfiltration", finding.Title),
					Evidence:    finding.Evidence,
					Remediation: "Fix injection vulnerability and implement input validation",
				})
			}

			// API vulnérabilités → Lateral movement
			if strings.Contains(finding.Type, "api") && (finding.Severity == "high" || finding.Severity == "critical") {
				paths = append(paths, Finding{
					Type:        "lateral_movement",
					Severity:    "high",
					Title:       "API Vulnerability → Lateral Movement",
					Description: fmt.Sprintf("API vulnerability (%s) may allow access to internal services", finding.Title),
					Evidence:    finding.Evidence,
					Remediation: "Implement proper API authentication and authorization",
				})
			}
		}
	}

	return paths
}

// Helper methods pour accéder aux résultats des modules
func (ao *AttackOrchestrator) getAPIResult() *api.EnumerationResult {
	return nil // Sera implémenté quand on stocke les résultats
}

func (ao *AttackOrchestrator) getJWTResult() *jwt.JWTTestResult {
	return nil
}

func (ao *AttackOrchestrator) getInjectionResult() *injection.InjectionTestResult {
	return nil
}

func (ao *AttackOrchestrator) getHMACResult() *hmac.HMACTestResult {
	return nil
}

func (ao *AttackOrchestrator) getDoSResult() *dos.DoSTestResult {
	return nil
}

func (ao *AttackOrchestrator) getTLSResult() *tls.TLSTestResult {
	return nil
}

// calculateKillChainStats calcule les statistiques du kill chain
func (ao *AttackOrchestrator) calculateKillChainStats(result *KillChainResult) {
	for _, phase := range result.Phases {
		for _, finding := range phase.Findings {
			result.TotalVulnerabilities++
			switch strings.ToLower(finding.Severity) {
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

// ============================================================
// KILL CHAIN OUTPUT FORMATTING
// ============================================================

func (ao *AttackOrchestrator) printKillChainHeader() {
	ao.printColor(ColorBold+ColorPurple, "\n")
	ao.printColor(ColorBold+ColorPurple, "╔══════════════════════════════════════════════════════════════╗\n")
	ao.printColor(ColorBold+ColorPurple, "║          CYBERRAVEN - KILL CHAIN ATTACK MODE                 ║\n")
	ao.printColor(ColorBold+ColorPurple, "╠══════════════════════════════════════════════════════════════╣\n")
	ao.printColor(ColorBold+ColorPurple, "║  Phase 1: TLS Exploitation   → Break through TLS protection  ║\n")
	ao.printColor(ColorBold+ColorPurple, "║  Phase 2: App Attacks        → Attack via compromised channel║\n")
	ao.printColor(ColorBold+ColorPurple, "║  Phase 3: Escalation         → Privilege escalation attempts ║\n")
	ao.printColor(ColorBold+ColorPurple, "╚══════════════════════════════════════════════════════════════╝\n\n")
}

func (ao *AttackOrchestrator) printPhaseStart(phase KillChainPhase, description string) {
	ao.printColor(ColorBold+ColorBlue, "\n┌────────────────────────────────────────────────────────────────┐\n")
	ao.printColor(ColorBold+ColorBlue, "│ PHASE: %-55s│\n", string(phase))
	ao.printColor(ColorBold+ColorBlue, "│ %s\n", description)
	ao.printColor(ColorBold+ColorBlue, "└────────────────────────────────────────────────────────────────┘\n")
}

func (ao *AttackOrchestrator) printPhaseResult(phase KillChainPhase, result *PhaseResult) {
	statusColor := ColorGreen
	statusIcon := "✓"

	if result.Status == StatusFailed {
		statusColor = ColorRed
		statusIcon = "✗"
	} else if result.TLSCompromised || result.Compromised {
		statusColor = ColorRed
		statusIcon = "!"
	}

	ao.printColor(statusColor, "\n  [%s] Phase %s: %s\n", statusIcon, phase, result.Status)
	ao.printColor(ColorCyan, "      Duration: %s | Findings: %d\n", result.Duration, result.VulnCount)

	if result.TLSCompromised {
		ao.printColor(ColorRed, "      TLS COMPROMISED: %s\n", result.CompromiseMethod)
	}

	if result.SkipReason != "" {
		ao.printColor(ColorYellow, "      Note: %s\n", result.SkipReason)
	}
}

func (ao *AttackOrchestrator) printKillChainConclusion(result *KillChainResult) {
	ao.printColor(ColorBold+ColorPurple, "\n")
	ao.printColor(ColorBold+ColorPurple, "╔══════════════════════════════════════════════════════════════╗\n")
	ao.printColor(ColorBold+ColorPurple, "║                    KILL CHAIN COMPLETE                       ║\n")
	ao.printColor(ColorBold+ColorPurple, "╠══════════════════════════════════════════════════════════════╣\n")

	if result.TLSStatus == "compromised" {
		ao.printColor(ColorRed, "║  TLS Status: COMPROMISED %-36s║\n", "")
		ao.printColor(ColorRed, "║  Method: %-51s║\n", result.CompromiseMethod)
	} else {
		ao.printColor(ColorGreen, "║  TLS Status: SECURE %-40s║\n", "")
	}

	ao.printColor(ColorCyan, "║  Progression: %-46s║\n", result.Progression)
	ao.printColor(ColorCyan, "║  Final Phase: %-46s║\n", result.FinalPhase)
	ao.printColor(ColorBold+ColorPurple, "╚══════════════════════════════════════════════════════════════╝\n")
}

func (ao *AttackOrchestrator) printColor(color, format string, args ...interface{}) {
	if ao.noColor {
		fmt.Printf(format, args...)
	} else {
		fmt.Printf(color+format+ColorReset, args...)
	}
}
