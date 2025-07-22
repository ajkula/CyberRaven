package api

import (
	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
)

// EndpointStrategy handles the selection of endpoints to test
type EndpointStrategy struct {
	config       *config.APIAttackConfig
	target       *config.TargetConfig
	discoveryCtx *discovery.AttackContext
}

// NewEndpointStrategy creates a new endpoint selection strategy
func NewEndpointStrategy(apiConfig *config.APIAttackConfig, targetConfig *config.TargetConfig) *EndpointStrategy {
	return &EndpointStrategy{
		config: apiConfig,
		target: targetConfig,
	}
}

func NewEndpointStrategyWithDiscovery(apiConfig *config.APIAttackConfig, targetConfig *config.TargetConfig, discoveryCtx *discovery.AttackContext) *EndpointStrategy {
	return &EndpointStrategy{
		config:       apiConfig,
		target:       targetConfig,
		discoveryCtx: discoveryCtx,
	}
}

// GetEndpointsToTest returns the list of endpoints to enumerate
func (es *EndpointStrategy) GetEndpointsToTest() []string {
	if es.discoveryCtx != nil && es.discoveryCtx.IsIntelligenceAvailable() {
		return es.getIntelligentEndpoints()
	}
	return es.getStandardEndpoints()
}

func (es *EndpointStrategy) getIntelligentEndpoints() []string {
	targetEndpoints := es.discoveryCtx.GetTargetedEndpoints("api")

	endpoints := make([]string, 0, len(targetEndpoints))
	for _, endpoint := range targetEndpoints {
		endpoints = append(endpoints, endpoint.Path)

		// Add simple variations
		if endpoint.Priority == "high" {
			endpoints = append(endpoints, endpoint.Path+"/1", endpoint.Path+"/admin")
		}
	}

	// Add minimal fallback endpoints
	fallback := []string{"/api", "/docs", "/health"}
	for _, fb := range fallback {
		if !es.contains(endpoints, fb) {
			endpoints = append(endpoints, fb)
		}
	}

	return endpoints
}

func (es *EndpointStrategy) getStandardEndpoints() []string {
	var endpoints []string

	endpoints = append(endpoints, es.config.CommonEndpoints...)

	return endpoints
}

func (es *EndpointStrategy) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
