package attack

import (
	"fmt"

	"github.com/ajkula/cyberraven/pkg/config"
)

const (
	DefaultTargetURL     = "http://localhost:8080"
	DefaultTargetName    = "Default Target"
	DefaultTargetProfile = "webapp-generic"
	DefaultUserAgent     = "CyberRaven/1.0 Security Scanner"
	Filename             = "cyberraven.yaml"
)

func LoadConfig() (*config.Config, error) {
	return config.LoadConfig(Filename)
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
func ApplyTargetOverride(cfg *config.Config, targetURL string) error {
	if targetURL == "" {
		return nil
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
