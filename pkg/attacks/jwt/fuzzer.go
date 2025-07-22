package jwt

import (
	"fmt"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
	"github.com/ajkula/cyberraven/pkg/utils"
)

// NewJWTFuzzer creates a new JWT security fuzzer
func NewJWTFuzzer(jwtConfig *config.JWTAttackConfig, targetConfig *config.TargetConfig) (*JWTFuzzer, error) {
	// Create default engine config for HTTP client
	engineConfig := &config.EngineConfig{
		MaxWorkers: 5,
		Timeout:    15 * time.Second,
		RateLimit:  5,
		MaxRetries: 2,
		RetryDelay: 1 * time.Second,
	}

	// Create enhanced HTTP client
	httpClient, err := utils.NewHTTPClient(targetConfig, engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	discoveryLoader := discovery.NewDiscoveryLoader()
	var attackContext *discovery.AttackContext

	if discoveryLoader.HasDiscoveries() {
		attackContext, err = discoveryLoader.LoadAttackContext()
		if err != nil {
			printWarning(fmt.Sprintf("Failed to load discovery intelligence: %v", err), false)
			printInfo("Falling back to standard JWT testing mode", false)
		} else {
			jwtTokens := attackContext.GetJWTTokens()
			printSuccess(fmt.Sprintf("Loaded discovery intelligence - found %d JWT tokens", len(jwtTokens)), false)
			age, _ := discoveryLoader.GetDiscoveryAge()
			printInfo(fmt.Sprintf("Discovery age: %v", age.Round(time.Second)), false)
		}
	} else {
		printInfo("No discovery file found - using standard JWT testing", false)
		printInfo("Run 'cyberraven sniff' first for intelligent targeting", false)
	}

	return &JWTFuzzer{
		config:        jwtConfig,
		target:        targetConfig,
		attackContext: attackContext,
		httpClient:    httpClient,
		discoveryCtx:  attackContext,
		testEndpoints: getDefaultJWTEndpoints(),
		weakSecrets:   getProWeakSecrets(),
	}, nil
}

// Close cleans up resources used by the fuzzer
func (jf *JWTFuzzer) Close() {
	if jf.httpClient != nil {
		jf.httpClient.Close()
	}
}
