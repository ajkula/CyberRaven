package injection

import (
	"context"
	"fmt"
	"time"
)

// executeTestByType remplace les 4 méthodes de test originales
func (it *InjectionTester) executeTestByType(ctx context.Context, testType string, fallbackPayloads []string) error {
	// Configuration des limites selon le type
	maxEndpoints := 2
	maxPayloads := 3
	if testType == "sql" {
		maxEndpoints = 3
		maxPayloads = 5
	}

	// ✅ UTILISER getIntelligentEndpoints au lieu de it.testEndpoints
	var endpoints []string
	var usingIntelligence bool

	if it.discoveryCtx != nil && it.discoveryCtx.IsIntelligenceAvailable() {
		// Utiliser la méthode intelligente existante
		intelligentEndpoints := getIntelligentEndpoints(it.discoveryCtx)
		if len(intelligentEndpoints) > 0 {
			endpoints = intelligentEndpoints
			usingIntelligence = true
			fmt.Printf("[INFO] Using getIntelligentEndpoints(): %d targeted endpoints for %s injection\n",
				len(endpoints), testType)
		}
	}

	// Fallback si pas d'intelligence
	if !usingIntelligence {
		endpoints = it.testEndpoints
		fmt.Printf("[INFO] Standard testing mode: %d generic endpoints for %s injection\n",
			len(endpoints), testType)
	}

	// Limitation des endpoints
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	// ✅ UTILISER getAdaptivePayloads pour enrichir les payloads
	var payloads []string

	// Commencer par les payloads adaptatifs si intelligence disponible
	if it.discoveryCtx != nil {
		adaptivePayloads := getAdaptivePayloads(it.discoveryCtx)
		if typePayloads, exists := adaptivePayloads[testType]; exists && len(typePayloads) > 0 {
			payloads = append(payloads, typePayloads...)
			fmt.Printf("[INFO] Using getAdaptivePayloads(): %d adaptive payloads for %s based on tech stack\n",
				len(typePayloads), testType)
		}
	}

	// Compléter avec les payloads fallback si nécessaire
	if len(payloads) < maxPayloads {
		remaining := maxPayloads - len(payloads)
		if remaining > len(fallbackPayloads) {
			remaining = len(fallbackPayloads)
		}
		payloads = append(payloads, fallbackPayloads[:remaining]...)
	}

	// Limitation finale des payloads
	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	// Routage vers le bon helper avec les payloads intelligents
	if testType == "sql" {
		return it.executeWithParametersIntelligent(ctx, endpoints, payloads, maxEndpoints, maxPayloads, usingIntelligence)
	}
	return it.executeSimple(ctx, testType, endpoints, payloads, maxEndpoints, maxPayloads)
}

func (it *InjectionTester) executeWithParametersIntelligent(ctx context.Context, endpoints, basePayloads []string, maxEndpoints, maxPayloads int, usingIntelligence bool) error {
	maxParameters := 3

	// Choix intelligent des paramètres (existant)
	var parameters []string
	if usingIntelligence && it.discoveryCtx != nil {
		intelligentParams := it.getIntelligentParameters()
		if len(intelligentParams) > 0 {
			parameters = intelligentParams
			fmt.Printf("[INFO] Using %d discovered parameters for SQL injection\n", len(parameters))
		} else {
			parameters = []string{"id", "search", "q"}
		}
	} else {
		parameters = []string{"id", "search", "q"}
	}

	if len(parameters) > maxParameters {
		parameters = parameters[:maxParameters]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		// Si intelligence, récupérer les paramètres spécifiques à cet endpoint
		if usingIntelligence && it.discoveryCtx != nil {
			endpointParams := it.getParametersForEndpoint(endpoint)
			if len(endpointParams) > 0 {
				parameters = endpointParams
				if len(parameters) > maxParameters {
					parameters = parameters[:maxParameters]
				}
			}
		}

		for _, method := range []string{"GET"} {
			for j, param := range parameters {
				if j >= maxParameters {
					break
				}

				// ✅ UTILISER getContextualPayloads pour chaque combinaison endpoint/parameter
				var payloads []string

				// Commencer par les payloads contextuels
				contextualPayloads := getContextualPayloads(endpoint, param)
				if len(contextualPayloads) > 0 {
					payloads = append(payloads, contextualPayloads...)
					fmt.Printf("[DEBUG] Using %d contextual payloads for %s?%s\n",
						len(contextualPayloads), endpoint, param)
				}

				// Compléter avec les payloads de base si nécessaire
				remaining := maxPayloads - len(payloads)
				if remaining > 0 && remaining <= len(basePayloads) {
					payloads = append(payloads, basePayloads[:remaining]...)
				}

				// Limitation finale
				if len(payloads) > maxPayloads {
					payloads = payloads[:maxPayloads]
				}

				// Tester chaque payload contextuel/adaptatif
				for k, payload := range payloads {
					if k >= maxPayloads {
						break
					}

					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}

					if err := it.testSQLPayload(ctx, endpoint, method, param, payload); err != nil {
						continue
					}

					time.Sleep(300 * time.Millisecond)
				}
			}
		}
	}
	return nil
}

// executeSimple - pour NoSQL, JSON, Path (endpoints -> payloads)
func (it *InjectionTester) executeSimple(ctx context.Context, testType string, endpoints, payloads []string, maxEndpoints, maxPayloads int) error {
	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		for j, payload := range payloads {
			if j >= maxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Appel de la méthode appropriée
			var err error
			switch testType {
			case "nosql":
				err = it.testNoSQLPayload(ctx, endpoint, payload)
			case "json":
				err = it.testJSONPayload(ctx, endpoint, payload)
			case "path":
				err = it.testPathPayload(ctx, endpoint, payload)
			}

			if err != nil {
				continue
			}

			time.Sleep(300 * time.Millisecond)
		}
	}
	return nil
}

// executeWithParameters - pour SQL (endpoints -> methods -> parameters -> payloads)
func (it *InjectionTester) executeWithParameters(ctx context.Context, endpoints, payloads []string, maxEndpoints, maxPayloads int, usingIntelligence bool) error {
	maxParameters := 3

	// ✅ Choix intelligent des paramètres
	var parameters []string

	if usingIntelligence && it.discoveryCtx != nil {
		// Utiliser les paramètres découverts
		intelligentParams := it.getIntelligentParameters()
		if len(intelligentParams) > 0 {
			parameters = intelligentParams
			fmt.Printf("[INFO] Using %d discovered parameters for SQL injection\n", len(parameters))
		} else {
			// Fallback aux paramètres par défaut
			parameters = []string{"id", "search", "q"}
		}
	} else {
		// Mode standard
		parameters = []string{"id", "search", "q"}
	}

	// Limiter le nombre de paramètres
	if len(parameters) > maxParameters {
		parameters = parameters[:maxParameters]
	}

	for i, endpoint := range endpoints {
		if i >= maxEndpoints {
			break
		}

		// ✅ Si on a l'intelligence, récupérer les paramètres spécifiques à cet endpoint
		if usingIntelligence && it.discoveryCtx != nil {
			endpointParams := it.getParametersForEndpoint(endpoint)
			if len(endpointParams) > 0 {
				parameters = endpointParams
				if len(parameters) > maxParameters {
					parameters = parameters[:maxParameters]
				}
			}
		}

		for _, method := range []string{"GET"} {
			for j, param := range parameters {
				if j >= maxParameters {
					break
				}

				for k, payload := range payloads {
					if k >= maxPayloads {
						break
					}

					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}

					if err := it.testSQLPayload(ctx, endpoint, method, param, payload); err != nil {
						continue
					}

					time.Sleep(300 * time.Millisecond)
				}
			}
		}
	}
	return nil
}

// getParametersForEndpoint returns parameters specific to an endpoint
func (it *InjectionTester) getParametersForEndpoint(endpoint string) []string {
	if it.discoveryCtx == nil {
		return []string{}
	}

	for _, ep := range it.discoveryCtx.Endpoints {
		if ep.Path == endpoint {
			return ep.Parameters
		}
	}

	return []string{}
}
