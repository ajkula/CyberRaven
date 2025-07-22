package injection

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/utils"
)

// testSQLPayload wrapper pour compatibilité
func (it *InjectionTester) testSQLPayload(ctx context.Context, endpoint, method, parameter, payload string) error {
	return it.testGenericPayload(ctx, "sql", endpoint, method, parameter, payload)
}

// testNoSQLPayload wrapper pour compatibilité
func (it *InjectionTester) testNoSQLPayload(ctx context.Context, endpoint, payload string) error {
	return it.testGenericPayload(ctx, "nosql", endpoint, "POST", "request_body", payload)
}

// testJSONPayload wrapper pour compatibilité
func (it *InjectionTester) testJSONPayload(ctx context.Context, endpoint, payload string) error {
	return it.testGenericPayload(ctx, "json", endpoint, "POST", "json_body", payload)
}

// testPathPayload wrapper pour compatibilité
func (it *InjectionTester) testPathPayload(ctx context.Context, endpoint, payload string) error {
	return it.testGenericPayload(ctx, "path", endpoint, "GET", "file", payload)
}

// testGenericPayload - fonction unifiée pour tous les tests de payload
func (it *InjectionTester) testGenericPayload(ctx context.Context, injectionType, endpoint, method, parameter, payload string) error {
	it.incrementTestCount()

	var resp *utils.HTTPResponse
	var baselineResp *utils.HTTPResponse
	var err error

	// SQL a besoin d'une baseline pour comparaison
	if injectionType == "sql" {
		baselineResp, err = it.sendBaselineRequest(ctx, endpoint, method, parameter)
		if err != nil {
			it.recordFailedTest()
			return err
		}
	}

	// Envoi du payload malveillant
	startTime := time.Now()
	resp, err = it.sendPayloadByType(ctx, injectionType, endpoint, method, parameter, payload)
	responseTime := time.Since(startTime)

	if err != nil {
		it.recordFailedTest()
		return err
	}
	defer resp.Body.Close()

	it.recordSuccessfulTest()

	// Enregistrement du test
	paramTest := ParameterTest{
		Endpoint:     endpoint,
		Method:       method,
		Parameter:    parameter,
		PayloadType:  injectionType,
		Vulnerable:   false,
		ResponseTime: responseTime,
	}

	// Détection unifiée
	if it.detectInjection(injectionType, baselineResp, resp, payload) {
		paramTest.Vulnerable = true

		// Création de la vulnérabilité avec les métadonnées spécifiques au type
		vuln := it.createVulnerability(injectionType, endpoint, method, parameter, payload, resp)
		it.recordVulnerability(vuln)
	}

	it.recordParameterTest(paramTest)
	return nil
}

// sendPayloadByType envoie le payload selon le type d'injection
func (it *InjectionTester) sendPayloadByType(ctx context.Context, injectionType, endpoint, method, parameter, payload string) (*utils.HTTPResponse, error) {
	switch injectionType {
	case "sql":
		if method == "GET" {
			fullURL := fmt.Sprintf("%s%s?%s=%s", it.target.BaseURL, endpoint, parameter, url.QueryEscape(payload))
			return it.httpClient.Get(ctx, fullURL)
		} else {
			body := fmt.Sprintf("%s=%s", parameter, url.QueryEscape(payload))
			headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			return it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(body), headers)
		}

	case "nosql", "json":
		headers := map[string]string{"Content-Type": "application/json"}
		return it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(payload), headers)

	case "path":
		testURL := fmt.Sprintf("%s%s?file=%s", it.target.BaseURL, endpoint, url.QueryEscape(payload))
		return it.httpClient.Get(ctx, testURL)

	default:
		return nil, fmt.Errorf("unknown injection type: %s", injectionType)
	}
}

// createVulnerability crée une vulnérabilité avec les métadonnées appropriées
func (it *InjectionTester) createVulnerability(injectionType, endpoint, method, parameter, payload string, resp *utils.HTTPResponse) InjectionVulnerability {
	// Métadonnées par type d'injection
	metadata := map[string]struct {
		description  string
		remediation  string
		attackVector string
		defaultRisk  int
	}{
		"sql": {
			description:  "SQL injection vulnerability in parameter '%s'",
			remediation:  "Use parameterized queries and input validation",
			attackVector: "%s parameter injection",
			defaultRisk:  50,
		},
		"nosql": {
			description:  "NoSQL injection vulnerability detected",
			remediation:  "Validate and sanitize NoSQL queries, use proper schema validation",
			attackVector: "JSON NoSQL injection",
			defaultRisk:  80,
		},
		"json": {
			description:  "JSON injection vulnerability detected",
			remediation:  "Implement proper JSON schema validation and input sanitization",
			attackVector: "JSON structure injection",
			defaultRisk:  60,
		},
		"path": {
			description:  "Path traversal vulnerability detected",
			remediation:  "Implement proper input validation and use whitelist for allowed files",
			attackVector: "File path traversal",
			defaultRisk:  75,
		},
	}

	meta := metadata[injectionType]

	return InjectionVulnerability{
		Type:            injectionType,
		Severity:        it.calculateSeverity(injectionType, resp, payload),
		Endpoint:        endpoint,
		Method:          method,
		Parameter:       parameter,
		Description:     fmt.Sprintf(meta.description, parameter),
		Evidence:        it.extractEvidence(injectionType, resp, payload),
		Remediation:     meta.remediation,
		RiskScore:       it.calculateRiskScore(injectionType, resp, payload, meta.defaultRisk),
		PayloadUsed:     payload,
		ResponseSnippet: it.getResponseSnippet(resp.BodyPreview),
		AttackVector:    fmt.Sprintf(meta.attackVector, method),
		DatabaseType:    it.detectDatabaseType(resp.BodyPreview),
	}
}

// sendBaselineRequest sends a baseline request for comparison
func (it *InjectionTester) sendBaselineRequest(ctx context.Context, endpoint, method, parameter string) (*utils.HTTPResponse, error) {
	if method == "GET" {
		fullURL := fmt.Sprintf("%s%s?%s=test", it.target.BaseURL, endpoint, parameter)
		return it.httpClient.Get(ctx, fullURL)
	} else {
		body := fmt.Sprintf("%s=test", parameter)
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		return it.httpClient.Post(ctx, it.target.BaseURL+endpoint, strings.NewReader(body), headers)
	}
}
