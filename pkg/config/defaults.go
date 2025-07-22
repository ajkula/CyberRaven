package config

import (
	"time"
)

// CreateDefaultConfig creates the complete default configuration
func CreateDefaultConfig() *Config {
	return &Config{
		Engine:  createDefaultEngineConfig(),
		Target:  createDefaultTargetConfig(),
		Attacks: createDefaultAttacksConfig(),
		Reports: createDefaultReportsConfig(),
		Output:  createDefaultOutputConfig(),
		Logging: createDefaultLoggingConfig(),
	}
}

func createDefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		MaxWorkers:     10,
		Timeout:        30 * time.Second,
		RateLimit:      10,
		EnableSniffing: false,
		EnableAttacks:  true,
		MaxRetries:     3,
		RetryDelay:     1 * time.Second,
	}
}

func createDefaultTargetConfig() *TargetConfig {
	return &TargetConfig{
		Name:        "Default Target",
		Description: "Target system for security assessment",
		BaseURL:     "http://localhost:8080",
		Profile:     "webapp-generic",
		Headers:     make(map[string]string),
		Auth: AuthConfig{
			Type: "none",
			HMAC: HMACConfig{
				Secret:             "",
				Algorithm:          "sha256",
				SignatureHeader:    "X-Signature",
				TimestampHeader:    "X-Timestamp",
				TimestampTolerance: 5 * time.Minute,
			},
		},
		TLS: TLSConfig{
			InsecureSkipVerify: true,
			MinVersion:         "",
			MaxVersion:         "",
		},
	}
}

func createDefaultAttacksConfig() *AttacksConfig {
	return &AttacksConfig{
		Enabled:    []string{},
		Aggressive: false,
		JWT:        createDefaultJWTConfig(),
		API:        createDefaultAPIConfig(),
		Injection:  createDefaultInjectionConfig(),
		HMAC:       createDefaultHMACConfig(),
		DoS:        createDefaultDoSConfig(),
		TLS:        createDefaultTLSConfig(),
	}
}

func createDefaultJWTConfig() *JWTAttackConfig {
	return &JWTAttackConfig{
		Enable:           true,
		TestAlgNone:      true,
		TestAlgConfusion: true,
		TestWeakSecrets:  true,
		WeakSecrets:      getDefaultJWTWeakSecrets(),
		TestExpiration:   true,
	}
}

func createDefaultAPIConfig() *APIAttackConfig {
	return &APIAttackConfig{
		Enable:                 true,
		EnableAutoDiscovery:    true,
		TestEnumeration:        true,
		TestMethodTampering:    true,
		TestParameterPollution: true,
		CommonEndpoints:        getDefaultAPIEndpoints(),
		Wordlists:              []string{},
	}
}

func createDefaultInjectionConfig() *InjectionAttackConfig {
	return &InjectionAttackConfig{
		Enable:        true,
		TestSQL:       true,
		TestNoSQL:     true,
		TestJSON:      true,
		TestPath:      true,
		SQLPayloads:   []string{},
		NoSQLPayloads: []string{},
		JSONPayloads:  []string{},
		PathPayloads:  []string{},
	}
}

func createDefaultHMACConfig() *HMACAttackConfig {
	return &HMACAttackConfig{
		Enable:         true,
		TestReplay:     true,
		TestTiming:     true,
		ReplayWindow:   5 * time.Minute,
		TimingRequests: 50,
	}
}

func createDefaultDoSConfig() *DoSAttackConfig {
	return &DoSAttackConfig{
		Enable:             true,
		TestFlooding:       true,
		TestLargePayloads:  true,
		TestConnExhaustion: true,
		FloodingDuration:   10 * time.Second,
		FloodingRate:       20,
		MaxPayloadSize:     5242880,
		MaxConnections:     10,
	}
}

func createDefaultTLSConfig() *TLSAttackConfig {
	return &TLSAttackConfig{
		Enable:           true,
		TestCipherSuites: true,
		TestCertificates: true,
		TestDowngrade:    true,
		TestSelfSigned:   true,
		TestExpiredCerts: true,
		WeakCiphers:      []string{},
	}
}

func createDefaultReportsConfig() *ReportsConfig {
	return &ReportsConfig{
		Formats:        []string{"html", "json", "txt"},
		OutputDir:      "./reports",
		IncludeLogs:    true,
		IncludeRawData: false,
		SeverityLevels: []string{"low", "medium", "high", "critical"},
	}
}

func createDefaultOutputConfig() *OutputConfig {
	return &OutputConfig{
		Verbosity:    "normal",
		Colors:       true,
		ProgressBars: true,
		ShowBanner:   true,
	}
}

func createDefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:      "info",
		Format:     "text",
		OutputFile: "",
		Rotation:   false,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     30,
	}
}

// getDefaultJWTWeakSecrets returns professional weak secrets for JWT testing
func getDefaultJWTWeakSecrets() []string {
	return []string{
		// Top JWT secrets from real breaches
		"secret", "secretkey", "secret123", "mysecret", "jwt_secret",
		"your-256-bit-secret", "your-secret-key", "mySecretKey",
		"jsonwebtoken", "jwt-key", "token-secret",

		// Common passwords from rockyou.txt
		"123456", "password", "123456789", "12345678", "12345",
		"1234567", "qwerty", "abc123", "password123", "admin",
		"letmein", "welcome", "monkey", "dragon", "master",

		// Default application secrets
		"defaultsecret", "default", "changeme", "temp", "test",
		"demo", "example", "sample", "placeholder", "dummy",

		// Framework defaults
		"rails_secret", "django_secret", "flask_secret", "express_secret",
		"spring_secret", "laravel_secret", "symfony_secret",

		// Single characters and common patterns
		"a", "1", "x", "key", "dev", "prod", "staging",
		"null", "undefined", "", " ",

		// Base64 encoded common secrets
		"c2VjcmV0", "cGFzc3dvcmQ=", "MTIzNDU2", // secret, password, 123456

		// Hex patterns
		"deadbeef", "cafebabe", "1234567890abcdef",

		// Company/product names (contextual)
		"company", "app", "api", "service", "backend",
	}
}

// getDefaultAPIEndpoints returns professional API endpoints for testing
func getDefaultAPIEndpoints() []string {
	return []string{
		// Authentication endpoints
		"/api/auth", "/api/auth/login", "/api/auth/register",
		"/rest/user/login", "/rest/user/register",
		"/auth", "/authentication", "/login", "/logout",
		"/tokens", "/sessions", "/signin", "/signup", "/register",

		// API documentation and discovery
		"/api", "/graphql", "/health", "/healthcheck",
		"/info", "/version", "/docs", "/documentation", "/swagger",
		"/openapi", "/api-docs", "/redoc", "/reports",

		// Users & Accounts
		"/api/users", "/api/user", "/users", "/user",
		"/accounts", "/account", "/profile", "/preferences",

		// Admin & Management
		"/api/admin", "/rest/admin/application-configuration",
		"/admin", "/management", "/dashboard", "/administrator",
		"/control", "/panel",

		// Data & Products
		"/api/Products", "/api/products", "/products",
		"/api/Quantitys", "/api/orders", "/orders",
		"/rest/products/search", "/api/search", "/search",
		"/query", "/filter",

		// Configuration and settings
		"/config", "/configuration", "/settings",
		"/assets", "/api/files", "/upload", "/download", "/files",

		// Monitoring and development
		"/metrics", "/stats", "/statistics",
		"/debug", "/test", "/dev", "/console", "/shell", "/terminal",

		// Messaging system endpoints
		"/messages", "/message", "/chat", "/channels",
		"/notifications", "/alerts", "/broadcast",
		"/contacts", "/groups", "/teams",
		"/presence", "/status", "/activity",
		"/media", "/attachments",
		"/stream", "/moderation",
		"/logs", "/events", "/audit",

		// Additional common endpoints
		"/export", "/import", "/backup",
		"/schema", "/metadata", "/endpoints",
		"/rest/chatbot/status", "/api/support",
		"/rest/deluxe-membership", "/rest/2fa/status",
	}
}
