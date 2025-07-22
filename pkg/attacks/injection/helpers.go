package injection

import (
	"strings"

	"github.com/ajkula/cyberraven/pkg/utils"
)

// calculateSeverity - fonction unifiée pour calculer la sévérité
func (it *InjectionTester) calculateSeverity(injectionType string, resp *utils.HTTPResponse, payload string) string {
	responseBody := strings.ToLower(resp.BodyPreview)

	// Indicateurs critiques communs
	criticalIndicators := []string{"root:x:", "windows registry", "/etc/shadow"}
	for _, indicator := range criticalIndicators {
		if strings.Contains(responseBody, indicator) {
			return "critical"
		}
	}

	// Sévérité basée sur le status code
	if resp.StatusCode == 500 {
		return "high"
	}

	// Sévérité par défaut selon le type
	defaultSeverities := map[string]string{
		"sql":   "medium",
		"nosql": "high",
		"json":  "medium",
		"path":  "high",
	}

	if severity, exists := defaultSeverities[injectionType]; exists {
		return severity
	}

	return "medium"
}

// calculateRiskScore - fonction unifiée pour calculer le score de risque
func (it *InjectionTester) calculateRiskScore(injectionType string, resp *utils.HTTPResponse, payload string, defaultScore int) int {
	responseBody := strings.ToLower(resp.BodyPreview)

	// Score maximal pour les indicateurs critiques
	criticalIndicators := []string{"root:x:", "windows registry", "/etc/shadow"}
	for _, indicator := range criticalIndicators {
		if strings.Contains(responseBody, indicator) {
			return 95
		}
	}

	// Score élevé pour erreur 500
	if resp.StatusCode == 500 {
		return 80
	}

	// Ajustements spécifiques par type
	switch injectionType {
	case "sql":
		if strings.Contains(responseBody, "sql") || strings.Contains(responseBody, "database") {
			return 70
		}
	case "nosql":
		if strings.Contains(responseBody, "mongodb") || strings.Contains(responseBody, "$") {
			return 85
		}
	}

	return defaultScore
}

// extractEvidence - fonction unifiée pour extraire les preuves
func (it *InjectionTester) extractEvidence(injectionType string, resp *utils.HTTPResponse, payload string) string {
	responseBody := strings.ToLower(resp.BodyPreview)

	// Evidence spécifiques par type
	evidenceMap := map[string]map[string]string{
		"sql": {
			"sql syntax": "SQL syntax error detected in response",
			"mysql":      "MySQL database error exposed",
			"postgresql": "PostgreSQL database error exposed",
			"oracle":     "Oracle database error exposed",
			"500":        "Internal server error triggered by SQL payload",
			"default":    "SQL injection indicators detected",
		},
		"nosql": {
			"mongodb": "MongoDB error pattern detected",
			"$":       "NoSQL operator exposed in response",
			"default": "NoSQL database response pattern detected",
		},
		"json": {
			"json parse":       "JSON parsing error detected",
			"unexpected token": "JSON structure manipulation successful",
			"default":          "JSON structure injection successful",
		},
		"path": {
			"root:x:":          "System file /etc/passwd exposed",
			"windows registry": "Windows system files exposed",
			"[boot loader]":    "System configuration files exposed",
			"default":          "Path traversal successful",
		},
	}

	// Vérification du status code en premier
	if resp.StatusCode == 500 && injectionType == "sql" {
		return evidenceMap["sql"]["500"]
	}

	// Recherche d'evidence spécifique
	if typeEvidence, exists := evidenceMap[injectionType]; exists {
		for pattern, evidence := range typeEvidence {
			if pattern != "default" && strings.Contains(responseBody, pattern) {
				return evidence
			}
		}
		// Retour de l'evidence par défaut
		return typeEvidence["default"]
	}

	return "Injection vulnerability detected"
}

// getResponseSnippet returns a snippet of the response body
func (it *InjectionTester) getResponseSnippet(body string) string {
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

// abs returns the absolute value of x
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
