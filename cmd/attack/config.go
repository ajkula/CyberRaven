package attack

import (
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/ajkula/cyberraven/pkg/config"
)

// Default configuration constants - Single source of truth
const (
	DefaultTargetURL     = "http://localhost:8080"
	DefaultTargetName    = "Default Target"
	DefaultTargetProfile = "webapp-generic"
	DefaultUserAgent     = "CyberRaven/1.0 Security Scanner"
)

// loadConfig loads and creates the default configuration
func loadConfig() (*config.Config, error) {
	// Create default configuration - Pen-testing oriented defaults
	cfg := &config.Config{
		Engine: config.EngineConfig{
			MaxWorkers: 10,
			Timeout:    30 * time.Second,
			RateLimit:  10,
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
		},
		Target: config.TargetConfig{
			Name:        DefaultTargetName,
			Description: "Target system for security assessment",
			BaseURL:     DefaultTargetURL,
			Profile:     DefaultTargetProfile,
			Headers:     make(map[string]string),
			Auth: config.AuthConfig{
				Type: "none",
				HMAC: config.HMACConfig{
					Secret:             "",
					Algorithm:          "sha256",
					SignatureHeader:    "X-Signature",
					TimestampHeader:    "X-Timestamp",
					TimestampTolerance: 5 * time.Minute,
				},
			},
			TLS: config.TLSConfig{
				InsecureSkipVerify: true,
				MinVersion:         "",
				MaxVersion:         "",
			},
		},
		Attacks: config.AttacksConfig{
			Enabled:    []string{},
			Aggressive: false,
			API: config.APIAttackConfig{
				Enable:                 true,
				EnableAutoDiscovery:    true,
				TestEnumeration:        true,
				TestMethodTampering:    true,
				TestParameterPollution: true,
				CommonEndpoints:        []string{},
				Wordlists:              []string{},
			},
			JWT: config.JWTAttackConfig{
				Enable:           true,
				TestAlgNone:      true,
				TestAlgConfusion: true,
				TestWeakSecrets:  true,
				WeakSecrets:      []string{},
				TestExpiration:   true,
			},
			Injection: config.InjectionAttackConfig{
				Enable:        true,
				TestSQL:       true,
				TestNoSQL:     true,
				TestJSON:      true,
				TestPath:      true,
				SQLPayloads:   []string{},
				NoSQLPayloads: []string{},
				JSONPayloads:  []string{},
				PathPayloads:  []string{},
			},
			HMAC: config.HMACAttackConfig{
				Enable:         true,
				TestReplay:     true,
				TestTiming:     true,
				ReplayWindow:   5 * time.Minute,
				TimingRequests: 50,
			},
			DoS: config.DoSAttackConfig{
				Enable:             true,
				TestFlooding:       true,
				TestLargePayloads:  true,
				TestConnExhaustion: true,
				FloodingDuration:   10 * time.Second,
				FloodingRate:       20,
				MaxPayloadSize:     5242880,
				MaxConnections:     10,
			},
			TLS: config.TLSAttackConfig{
				Enable:           true,
				TestCipherSuites: true,
				TestCertificates: true,
				TestDowngrade:    true,
				TestSelfSigned:   true,
				TestExpiredCerts: true,
				WeakCiphers:      []string{},
			},
		},
		Output: config.OutputConfig{
			Verbosity:    "normal",
			Colors:       true,
			ProgressBars: true,
			ShowBanner:   true,
		},
		Reports: config.ReportsConfig{
			Formats:        []string{"html", "json", "txt"},
			OutputDir:      "./reports",
			IncludeLogs:    true,
			IncludeRawData: false,
			SeverityLevels: []string{"low", "medium", "high", "critical"},
		},
	}

	// Override with viper configuration if available
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}

// detectProfileFromURL attempts to detect target profile from URL patterns
func detectProfileFromURL(url string) string {
	// Simple heuristics for profile detection
	switch {
	case containsAny(url, []string{"/api", "/v1", "/v2", "/swagger", "/openapi"}):
		return "api-rest"
	case containsAny(url, []string{"/chat", "/messages", "/ws", "/websocket"}):
		return "messaging-system"
	default:
		return "webapp-generic"
	}
}

// containsAny checks if string contains any of the patterns
func containsAny(s string, patterns []string) bool {
	for _, pattern := range patterns {
		if len(s) >= len(pattern) {
			for i := 0; i <= len(s)-len(pattern); i++ {
				if s[i:i+len(pattern)] == pattern {
					return true
				}
			}
		}
	}
	return false
}

// validateAttackConfig validates the attack configuration
func validateAttackConfig(cfg *config.Config) error {
	if cfg.Target.BaseURL == "" {
		return fmt.Errorf("target URL is required")
	}

	if cfg.Engine.MaxWorkers <= 0 {
		return fmt.Errorf("max workers must be positive")
	}

	if cfg.Engine.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	return nil
}

// applyTargetOverride applies target override from CLI --target flag
func applyTargetOverride(cfg *config.Config, targetURL string) error {
	if targetURL == "" {
		return nil // No override
	}

	// Update target configuration
	cfg.Target.BaseURL = targetURL
	cfg.Target.Name = fmt.Sprintf("CLI Target: %s", targetURL)

	// Auto-detect profile based on URL patterns if not explicitly set
	if cfg.Target.Profile == DefaultTargetProfile {
		cfg.Target.Profile = detectProfileFromURL(targetURL)
	}

	return nil
}
