package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ajkula/cyberraven/pkg/sniffer"
)

type AttackContext struct {
	SessionID          string                  `json:"session_id"`
	DiscoveryAge       time.Time               `json:"discovery_time"`
	IsStale            bool                    `json:"is_stale"`
	Endpoints          []TargetEndpoint        `json:"endpoints"`
	Tokens             []TargetToken           `json:"tokens"`
	Signatures         []TargetSignature       `json:"signatures"`
	Technology         TechnologyInfo          `json:"technology"`
	TLSIntelligence    sniffer.TLSIntelligence `json:"tls_intelligence"`
	RecommendedModules []string                `json:"recommended_modules"`
	TargetPriority     map[string]string       `json:"target_priority"`
}

type TargetEndpoint struct {
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	FullURL       string   `json:"full_url"`
	StatusCodes   []int    `json:"status_codes"`
	AuthRequired  bool     `json:"auth_required"`
	CSRFProtected bool     `json:"csrf_protected"`
	Parameters    []string `json:"parameters"`
	Priority      string   `json:"priority"`
}

type TargetToken struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	LocationKey string `json:"location_key"`
	Format      string `json:"format"`
	IsValid     bool   `json:"is_valid"`
	UsageCount  int    `json:"usage_count"`
}

type TargetSignature struct {
	Type           string `json:"type"`
	Algorithm      string `json:"algorithm"`
	HeaderName     string `json:"header_name"`
	SignatureValue string `json:"signature_value"`
}

type TechnologyInfo struct {
	WebServer  string `json:"web_server"`
	Framework  string `json:"framework"`
	Language   string `json:"language"`
	Database   string `json:"database"`
	WAF        string `json:"waf"`
	CDN        string `json:"cdn"`
	AuthSystem string `json:"auth_system"`
}

type DiscoveryLoader struct {
	discoveryFile string
	maxAge        time.Duration
}

func NewDiscoveryLoader() *DiscoveryLoader {
	return &DiscoveryLoader{
		discoveryFile: "discovery.json",
		maxAge:        7 * 24 * time.Hour,
	}
}

func NewDiscoveryLoaderWithFile(file string) *DiscoveryLoader {
	return &DiscoveryLoader{
		discoveryFile: file,
		maxAge:        7 * 24 * time.Hour,
	}
}

func (dl *DiscoveryLoader) LoadAttackContext() (*AttackContext, error) {
	if _, err := os.Stat(dl.discoveryFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("no discovery file found at %s - run 'cyberraven sniff' first", dl.discoveryFile)
	}

	data, err := os.ReadFile(dl.discoveryFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery file: %w", err)
	}

	var snifferResult sniffer.SnifferResult
	if err := json.Unmarshal(data, &snifferResult); err != nil {
		return nil, fmt.Errorf("failed to parse discovery file: %w", err)
	}

	attackContext := dl.convertToAttackContext(&snifferResult)
	return attackContext, nil
}

func (dl *DiscoveryLoader) HasDiscoveries() bool {
	stat, err := os.Stat(dl.discoveryFile)
	if err != nil {
		return false
	}

	age := time.Since(stat.ModTime())
	return age <= dl.maxAge
}

func (dl *DiscoveryLoader) GetDiscoveryAge() (time.Duration, error) {
	stat, err := os.Stat(dl.discoveryFile)
	if err != nil {
		return 0, err
	}
	return time.Since(stat.ModTime()), nil
}

func (dl *DiscoveryLoader) convertToAttackContext(result *sniffer.SnifferResult) *AttackContext {
	context := &AttackContext{
		SessionID:          result.SessionID,
		DiscoveryAge:       result.StartTime,
		IsStale:            time.Since(result.StartTime) > dl.maxAge,
		Endpoints:          make([]TargetEndpoint, 0),
		Tokens:             make([]TargetToken, 0),
		Signatures:         make([]TargetSignature, 0),
		RecommendedModules: make([]string, 0),
		TargetPriority:     make(map[string]string),
		TLSIntelligence:    result.TLSIntelligence,
	}

	for _, endpoint := range result.DiscoveredEndpoints {
		targetEndpoint := TargetEndpoint{
			Method:        endpoint.Method,
			Path:          endpoint.Path,
			FullURL:       endpoint.FullURL,
			StatusCodes:   endpoint.StatusCodes,
			AuthRequired:  endpoint.AuthRequired,
			CSRFProtected: endpoint.CSRFProtected,
			Parameters:    dl.extractParameterNames(endpoint.Parameters),
			Priority:      dl.calculateEndpointPriority(endpoint),
		}
		context.Endpoints = append(context.Endpoints, targetEndpoint)
		context.TargetPriority[endpoint.Path] = targetEndpoint.Priority
	}

	for _, token := range result.DiscoveredTokens {
		targetToken := TargetToken{
			Type:        token.Type,
			Location:    token.Location,
			LocationKey: token.LocationKey,
			Format:      token.Format,
			IsValid:     token.IsValid,
			UsageCount:  token.UsageCount,
		}
		context.Tokens = append(context.Tokens, targetToken)
	}

	for _, sig := range result.DiscoveredSignatures {
		targetSig := TargetSignature{
			Type:           sig.Type,
			Algorithm:      sig.Algorithm,
			HeaderName:     sig.HeaderName,
			SignatureValue: sig.SignatureValue,
		}
		context.Signatures = append(context.Signatures, targetSig)
	}

	context.Technology = TechnologyInfo{
		WebServer:  result.TechnologyProfile.WebServer,
		Framework:  result.TechnologyProfile.Framework,
		Language:   result.TechnologyProfile.Language,
		Database:   result.TechnologyProfile.Database,
		WAF:        result.TechnologyProfile.WAF,
		CDN:        result.TechnologyProfile.CDN,
		AuthSystem: result.TechnologyProfile.AuthSystem,
	}

	for _, rec := range result.AttackRecommendations {
		context.RecommendedModules = append(context.RecommendedModules, rec.Module)
	}

	return context
}

func (dl *DiscoveryLoader) extractParameterNames(params []sniffer.Parameter) []string {
	names := make([]string, 0, len(params))
	for _, param := range params {
		names = append(names, param.Name)
	}
	return names
}

func (dl *DiscoveryLoader) calculateEndpointPriority(endpoint sniffer.DiscoveredEndpoint) string {
	if endpoint.AuthRequired || endpoint.CSRFProtected {
		return "high"
	}

	adminPaths := []string{"admin", "manage", "dashboard", "config", "settings"}
	for _, adminPath := range adminPaths {
		if contains(endpoint.Path, adminPath) {
			return "high"
		}
	}

	if len(endpoint.Parameters) > 0 || contains(endpoint.Path, "api") {
		return "medium"
	}

	if endpoint.Method == "GET" && len(endpoint.Parameters) == 0 {
		return "low"
	}

	return "medium"
}

func (ac *AttackContext) GetTargetedEndpoints(module string) []TargetEndpoint {
	var targeted []TargetEndpoint

	switch module {
	case "api":
		for _, endpoint := range ac.Endpoints {
			targeted = append(targeted, endpoint)
		}
	case "jwt":
		for _, endpoint := range ac.Endpoints {
			if endpoint.AuthRequired || ac.hasJWTTokens() {
				targeted = append(targeted, endpoint)
			}
		}
	case "injection":
		for _, endpoint := range ac.Endpoints {
			if len(endpoint.Parameters) > 0 {
				targeted = append(targeted, endpoint)
			}
		}
	default:
		return ac.Endpoints
	}

	return targeted
}

func (ac *AttackContext) hasJWTTokens() bool {
	for _, token := range ac.Tokens {
		if token.Type == "jwt" || token.Type == "bearer" {
			return true
		}
	}
	return false
}

func (ac *AttackContext) GetRecommendedModules() []string {
	return ac.RecommendedModules
}

func (ac *AttackContext) IsIntelligenceAvailable() bool {
	return len(ac.Endpoints) > 0 || len(ac.Tokens) > 0 || len(ac.Signatures) > 0
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findInString(s, substr)
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (ac *AttackContext) GetJWTTokens() []TargetToken {
	var jwtTokens []TargetToken
	for _, token := range ac.Tokens {
		if token.Type == "jwt" || token.Type == "bearer" {
			jwtTokens = append(jwtTokens, token)
		}
	}
	return jwtTokens
}

func (ac *AttackContext) GetParameterizedEndpoints() []TargetEndpoint {
	var paramEndpoints []TargetEndpoint
	for _, endpoint := range ac.Endpoints {
		if len(endpoint.Parameters) > 0 {
			paramEndpoints = append(paramEndpoints, endpoint)
		}
	}
	return paramEndpoints
}

func (ac *AttackContext) GetHMACSignatures() []TargetSignature {
	var hmacSigs []TargetSignature
	for _, sig := range ac.Signatures {
		if sig.Type == "hmac" {
			hmacSigs = append(hmacSigs, sig)
		}
	}
	return hmacSigs
}

func (ac *AttackContext) GetHighPriorityEndpoints() []TargetEndpoint {
	var highPriority []TargetEndpoint
	for _, endpoint := range ac.Endpoints {
		if endpoint.Priority == "high" || endpoint.AuthRequired {
			highPriority = append(highPriority, endpoint)
		}
	}
	return highPriority
}
