package api

import "github.com/ajkula/cyberraven/pkg/config"

// EndpointStrategy handles the selection of endpoints to test
type EndpointStrategy struct {
	config *config.APIAttackConfig
	target *config.TargetConfig
}

// NewEndpointStrategy creates a new endpoint selection strategy
func NewEndpointStrategy(apiConfig *config.APIAttackConfig, targetConfig *config.TargetConfig) *EndpointStrategy {
	return &EndpointStrategy{
		config: apiConfig,
		target: targetConfig,
	}
}

// GetEndpointsToTest returns the list of endpoints to enumerate
func (es *EndpointStrategy) GetEndpointsToTest() []string {
	var endpoints []string

	// Add configured common endpoints
	endpoints = append(endpoints, es.config.CommonEndpoints...)

	// Add default common API endpoints if none configured
	if len(es.config.CommonEndpoints) == 0 {
		endpoints = append(endpoints, es.getDefaultAPIEndpoints()...)
	}

	return endpoints
}

// getDefaultAPIEndpoints returns a list of endpoints based on target profile and configuration
func (es *EndpointStrategy) getDefaultAPIEndpoints() []string {
	var endpoints []string

	// Base endpoints for enumeration
	if es.config.TestEnumeration {
		endpoints = append(endpoints, es.getEnumerationEndpoints()...)
	}

	// Profile-specific endpoints
	switch es.target.Profile {
	case "api-rest":
		endpoints = append(endpoints, es.getRESTAPIEndpoints()...)
	case "webapp-generic":
		endpoints = append(endpoints, es.getWebAppEndpoints()...)
	case "messaging-system":
		endpoints = append(endpoints, es.getMessagingEndpoints()...)
	default:
		// Generic endpoints for unknown profiles
		endpoints = append(endpoints, es.getGenericEndpoints()...)
	}

	return endpoints
}

// getEnumerationEndpoints returns common discovery endpoints
func (es *EndpointStrategy) getEnumerationEndpoints() []string {
	return []string{
		"/api", "/v1", "/v2", // Generic API roots (no hardcoded versions)
		"/status", "/health", "/healthcheck",
		"/info", "/version", "/build",
		"/docs", "/documentation", "/swagger",
		"/openapi", "/api-docs", "/redoc",
	}
}

// getRESTAPIEndpoints returns REST API specific endpoints
func (es *EndpointStrategy) getRESTAPIEndpoints() []string {
	return []string{
		// Core REST resources
		"/users", "/user", "/accounts", "/account",
		"/auth", "/authentication", "/login", "/logout",
		"/tokens", "/sessions",

		// API management
		"/metrics", "/stats", "/statistics",
		"/admin", "/management",

		// Data operations
		"/search", "/query", "/filter",
		"/export", "/import", "/backup",

		// Documentation and discovery
		"/schema", "/metadata", "/endpoints",
	}
}

// getWebAppEndpoints returns web application specific endpoints
func (es *EndpointStrategy) getWebAppEndpoints() []string {
	return []string{
		// Authentication
		"/login", "/signin", "/signup", "/register",
		"/logout", "/auth", "/authentication",

		// Administrative
		"/admin", "/administrator", "/management",
		"/dashboard", "/panel", "/control",
		"/config", "/configuration", "/settings",

		// User interface
		"/profile", "/account", "/preferences",
		"/upload", "/download", "/files",

		// Debug and development
		"/debug", "/test", "/dev",
		"/console", "/shell", "/terminal",
	}
}

// getMessagingEndpoints returns messaging system specific endpoints
func (es *EndpointStrategy) getMessagingEndpoints() []string {
	return []string{
		// Messaging core
		"/messages", "/message", "/chat", "/channels",
		"/notifications", "/alerts", "/broadcast",

		// User management
		"/users", "/contacts", "/groups", "/teams",
		"/presence", "/status", "/activity",

		// Media and files
		"/files", "/media", "/attachments",
		"/upload", "/download", "/stream",

		// Administration
		"/admin", "/management", "/moderation",
		"/logs", "/events", "/audit",
	}
}

// getGenericEndpoints returns generic endpoints for unknown profiles
func (es *EndpointStrategy) getGenericEndpoints() []string {
	return []string{
		// Core endpoints
		"/api", "/v1", "/v2",
		"/status", "/health", "/info",
		"/users", "/auth", "/login",
		"/admin", "/config", "/docs",
		"/files", "/search", "/reports",
	}
}
