package attack

import (
	"time"

	"github.com/ajkula/cyberraven/pkg/attacks/api"
	"github.com/ajkula/cyberraven/pkg/attacks/dos"
	"github.com/ajkula/cyberraven/pkg/attacks/hmac"
	"github.com/ajkula/cyberraven/pkg/attacks/injection"
	"github.com/ajkula/cyberraven/pkg/attacks/jwt"
	"github.com/ajkula/cyberraven/pkg/attacks/tls"
	"github.com/ajkula/cyberraven/pkg/config"
	"github.com/ajkula/cyberraven/pkg/discovery"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// AttackResult represents the complete result of an attack session
type AttackResult struct {
	// Session metadata
	SessionID string        `json:"session_id"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Target information
	Target config.TargetConfig `json:"target"`

	// Attack configuration
	EnabledModules []string `json:"enabled_modules"`
	AggressiveMode bool     `json:"aggressive_mode"`

	// Module results
	APIEnumeration   *api.EnumerationResult         `json:"api_enumeration,omitempty"`
	JWTTesting       *jwt.JWTTestResult             `json:"jwt_testing,omitempty"`
	InjectionTesting *injection.InjectionTestResult `json:"injection_testing,omitempty"`
	HMACTesting      *hmac.HMACTestResult           `json:"hmac_testing,omitempty"`
	DoSTesting       *dos.DoSTestResult             `json:"dos_testing,omitempty"`
	TLSTesting       *tls.TLSTestResult             `json:"tls_testing,omitempty"`

	// Summary statistics
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalCount        int `json:"critical_count"`
	HighCount            int `json:"high_count"`
	MediumCount          int `json:"medium_count"`
	LowCount             int `json:"low_count"`
}

// AttackOrchestrator manages the execution of multiple attack modules
type AttackOrchestrator struct {
	config        *config.Config
	target        *config.TargetConfig
	attackContext *discovery.AttackContext
	verbose       bool
	noColor       bool
	outputDir     string
}

// NewAttackOrchestrator creates a new attack orchestrator
func NewAttackOrchestrator(cfg *config.Config, verbose, noColor bool, outputDir string) *AttackOrchestrator {
	loader := discovery.NewDiscoveryLoader()
	attackContext, err := loader.LoadAttackContext()
	if err != nil {
		attackContext = nil
	}

	return &AttackOrchestrator{
		config:        cfg,
		target:        cfg.Target,
		attackContext: attackContext,
		verbose:       verbose,
		noColor:       noColor,
		outputDir:     outputDir,
	}
}
