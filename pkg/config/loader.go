package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultConfigFilename = "cyberraven.yaml"

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	if filename == "" {
		filename = DefaultConfigFilename
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", filename)
	}

	yamlData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// LoadConfigOrCreateDefault loads config from file or returns default if not found
func LoadConfigOrCreateDefault(filename string) (*Config, error) {
	cfg, err := LoadConfig(filename)
	if err == nil {
		return cfg, nil
	}

	// If file doesn't exist, return default config
	if os.IsNotExist(err) {
		return CreateDefaultConfig(), nil
	}

	// Other errors (parsing, validation) should be reported
	return nil, err
}

// ValidateConfig validates the configuration for correctness
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate target configuration
	if err := validateTargetConfig(cfg.Target); err != nil {
		return fmt.Errorf("target configuration error: %w", err)
	}

	// Validate engine configuration
	if err := validateEngineConfig(cfg.Engine); err != nil {
		return fmt.Errorf("engine configuration error: %w", err)
	}

	// Validate reports configuration
	if err := validateReportsConfig(cfg.Reports); err != nil {
		return fmt.Errorf("reports configuration error: %w", err)
	}

	return nil
}

// validateTargetConfig validates target-specific configuration
func validateTargetConfig(target *TargetConfig) error {
	if target.BaseURL == "" {
		return fmt.Errorf("target URL is required")
	}

	if target.Name == "" {
		return fmt.Errorf("target name is required")
	}

	// Validate authentication configuration
	if target.Auth.Type != "none" && target.Auth.Type != "basic" &&
		target.Auth.Type != "bearer" && target.Auth.Type != "jwt" &&
		target.Auth.Type != "hmac" && target.Auth.Type != "custom" {
		return fmt.Errorf("invalid auth type: %s", target.Auth.Type)
	}

	// Validate HMAC configuration if using HMAC auth
	if target.Auth.Type == "hmac" {
		if target.Auth.HMAC.Secret == "" {
			return fmt.Errorf("HMAC secret is required when using HMAC authentication")
		}
		if target.Auth.HMAC.Algorithm == "" {
			return fmt.Errorf("HMAC algorithm is required when using HMAC authentication")
		}
	}

	return nil
}

// validateEngineConfig validates engine-specific configuration
func validateEngineConfig(engine *EngineConfig) error {
	if engine.MaxWorkers <= 0 {
		return fmt.Errorf("max workers must be positive, got: %d", engine.MaxWorkers)
	}

	if engine.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got: %v", engine.Timeout)
	}

	if engine.RateLimit < 0 {
		return fmt.Errorf("rate limit cannot be negative, got: %d", engine.RateLimit)
	}

	if engine.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative, got: %d", engine.MaxRetries)
	}

	if engine.RetryDelay < 0 {
		return fmt.Errorf("retry delay cannot be negative, got: %v", engine.RetryDelay)
	}

	return nil
}

// validateReportsConfig validates reports-specific configuration
func validateReportsConfig(reports *ReportsConfig) error {
	if reports.OutputDir == "" {
		return fmt.Errorf("reports output directory is required")
	}

	// Validate output formats
	validFormats := map[string]bool{
		"json": true,
		"html": true,
		"pdf":  true,
		"txt":  true,
	}

	for _, format := range reports.Formats {
		if !validFormats[format] {
			return fmt.Errorf("invalid report format: %s", format)
		}
	}

	// Validate severity levels
	validSeverities := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}

	for _, severity := range reports.SeverityLevels {
		if !validSeverities[severity] {
			return fmt.Errorf("invalid severity level: %s", severity)
		}
	}

	return nil
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(cfg *Config, filename string) error {
	if filename == "" {
		filename = DefaultConfigFilename
	}

	if err := ValidateConfig(cfg); err != nil {
		return fmt.Errorf("cannot save invalid configuration: %w", err)
	}

	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize configuration: %w", err)
	}

	if err := os.WriteFile(filename, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
