package api

import "github.com/ajkula/cyberraven/pkg/config"

func GetDefaultAPIConfig() *config.APIAttackConfig {
	return &config.APIAttackConfig{
		Enable:                 true,
		EnableAutoDiscovery:    true,
		TestEnumeration:        true,
		TestMethodTampering:    true,
		TestParameterPollution: true,
		CommonEndpoints:        getDefaultAPIEndpoints(),
		Wordlists:              []string{}, // TODO: Load from external file
	}
}

func getDefaultAPIEndpoints() []string {
	var endpoints []string

	endpoints = append(endpoints, getEnumerationEndpoints()...)
	endpoints = append(endpoints, getRESTAPIEndpoints()...)

	return endpoints
}

// Updated endpoint methods with cleaned lists

func getEnumerationEndpoints() []string {
	return []string{
		"/api", "/graphql",
		"/health", "/healthcheck",
		"/info", "/version",
		"/docs", "/documentation", "/swagger",
		"/openapi", "/api-docs", "/redoc",
		"/reports",
	}
}

func getRESTAPIEndpoints() []string {
	return []string{
		// Authentication
		"/api/auth", "/api/auth/login", "/api/auth/register",
		"/rest/user/login", "/rest/user/register",
		"/auth", "/authentication", "/login", "/logout",
		"/tokens", "/sessions",
		"/signin", "/signup", "/register",

		// Users & Accounts
		"/api/users", "/api/user", "/users", "/user",
		"/accounts", "/account", "/profile", "/preferences",

		// Admin & Management
		"/api/admin", "/rest/admin/application-configuration",
		"/admin", "/management", "/dashboard", "/administrator",
		"/control", "/panel",

		// Configuration
		"/config", "/configuration", "/settings",

		// Data & Products (based on Juice Shop discoveries)
		"/api/Products", "/api/products", "/products",
		"/api/Quantitys", "/api/orders", "/orders",

		// Chatbots & Support (based on Juice Shop)
		"/rest/chatbot/status", "/api/support",
		"/rest/deluxe-membership", "/rest/2fa/status",

		// Search & Filtering
		"/rest/products/search", "/api/search", "/search",
		"/query", "/filter",

		// Files & Assets
		"/assets", "/api/files", "/upload", "/download", "/files",

		// Monitoring & Stats
		"/metrics", "/stats", "/statistics",

		// Backup & Export
		"/export", "/import", "/backup",
		"/schema", "/metadata", "/endpoints",

		// REST endpoints
		"/rest/user/login", "/rest/user/register",
		"/rest/admin/application-configuration",

		// Development & Debug
		"/debug", "/test", "/dev",
		"/console", "/shell", "/terminal",

		// messaging
		"/messages", "/message", "/chat", "/channels",
		"/notifications", "/alerts", "/broadcast",
		"/contacts", "/groups", "/teams",
		"/presence", "/status", "/activity",
		"/media", "/attachments",
		"/stream", "/moderation",
		"/logs", "/events", "/audit",
	}
}
