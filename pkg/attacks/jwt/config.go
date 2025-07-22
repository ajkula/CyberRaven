package jwt

import "github.com/ajkula/cyberraven/pkg/config"

func getDefaultJWTEndpoints() []string {
	return []string{
		"/login", "/auth", "/authenticate",
		"/api/auth", "/api/login", "/api/token",
		"/oauth", "/oauth/token",
		"/user", "/profile", "/me",
		"/admin", "/dashboard",
		"/api/user", "/api/profile",
	}
}

func getProWeakSecrets() []string {
	return []string{
		// Top JWT secrets from real breaches
		"secret", "secretkey", "secret123", "mysecret", "jwt_secret",
		"your-256-bit-secret", "your-secret-key", "mySecretKey",
		"jsonwebtoken", "jwt-key", "token-secret",

		// Common passwords from rockyou.txt
		"123456", "password", "123456789", "12345678", "12345",
		"1234567", "qwerty", "abc123", "password123", "admin",
		"letmein", "welcome", "monkey", "dragon", "master",
		"sunshine", "password1", "123123", "football", "iloveyou",

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

func GetDefaultJWTConfig() *config.JWTAttackConfig {
	return &config.JWTAttackConfig{
		Enable:           true,
		TestAlgConfusion: true,
		TestAlgNone:      true,
		TestWeakSecrets:  true,
		TestExpiration:   true,
		WeakSecrets:      getProWeakSecrets(),
	}
}

func ValidateAndEnrichJWTConfig(config *config.JWTAttackConfig) *config.JWTAttackConfig {
	if config == nil {
		return GetDefaultJWTConfig()
	}

	if len(config.WeakSecrets) == 0 {
		config.WeakSecrets = getProWeakSecrets()
	}

	return config
}
