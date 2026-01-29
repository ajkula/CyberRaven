package attack

import (
	"net/http"
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

	// Kill Chain state
	killChainState *KillChainState
}

// ============================================================
// KILL CHAIN TYPES - Progression conditionnelle des attaques
// ============================================================

// KillChainPhase représente une phase dans la chaîne d'attaque
type KillChainPhase string

const (
	PhaseRecon       KillChainPhase = "reconnaissance"
	PhaseTLSExploit  KillChainPhase = "tls_exploitation"
	PhaseAppAttacks  KillChainPhase = "application_attacks"
	PhaseEscalation  KillChainPhase = "escalation"
	PhaseComplete    KillChainPhase = "complete"
)

// PhaseStatus représente l'état d'une phase
type PhaseStatus string

const (
	StatusPending   PhaseStatus = "pending"
	StatusRunning   PhaseStatus = "running"
	StatusSuccess   PhaseStatus = "success"
	StatusFailed    PhaseStatus = "failed"
	StatusSkipped   PhaseStatus = "skipped"
)

// PhaseResult contient les résultats d'une phase du kill chain
type PhaseResult struct {
	Phase         KillChainPhase `json:"phase"`
	Status        PhaseStatus    `json:"status"`
	StartTime     time.Time      `json:"start_time"`
	EndTime       time.Time      `json:"end_time"`
	Duration      time.Duration  `json:"duration"`

	// Progression
	Compromised   bool           `json:"compromised"`
	CanContinue   bool           `json:"can_continue"`
	NextPhase     KillChainPhase `json:"next_phase,omitempty"`
	SkipReason    string         `json:"skip_reason,omitempty"`

	// Findings
	Findings      []Finding      `json:"findings"`
	VulnCount     int            `json:"vulnerability_count"`

	// TLS-specific (pour Phase TLS)
	TLSCompromised    bool       `json:"tls_compromised,omitempty"`
	CompromiseMethod  string     `json:"compromise_method,omitempty"`
	ProxyActive       bool       `json:"proxy_active,omitempty"`
}

// Finding représente une découverte générique
type Finding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// KillChainState contient l'état de progression du kill chain
type KillChainState struct {
	// État courant
	CurrentPhase   KillChainPhase        `json:"current_phase"`
	Phases         map[KillChainPhase]*PhaseResult `json:"phases"`

	// État TLS
	TLSCompromised    bool              `json:"tls_compromised"`
	CompromiseMethod  string            `json:"compromise_method,omitempty"`

	// Configuration proxy MITM (si TLS compromis)
	ProxyConfig    *ProxyConfig          `json:"proxy_config,omitempty"`
	ProxyClient    *http.Client          `json:"-"` // Client HTTP passant par le proxy

	// Métriques globales
	TotalFindings  int                   `json:"total_findings"`
	HighestSeverity string               `json:"highest_severity"`
}

// ProxyConfig contient la configuration du proxy MITM
type ProxyConfig struct {
	Enabled     bool   `json:"enabled"`
	ListenAddr  string `json:"listen_addr"`
	TargetHost  string `json:"target_host"`
	CertPath    string `json:"cert_path,omitempty"`
	KeyPath     string `json:"key_path,omitempty"`
}

// KillChainResult est le résultat final du kill chain
type KillChainResult struct {
	// Metadata
	SessionID   string        `json:"session_id"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`

	// Target
	Target      config.TargetConfig `json:"target"`

	// Kill Chain specifique
	Phases         []PhaseResult `json:"phases"`
	FinalPhase     KillChainPhase `json:"final_phase"`
	TLSStatus      string        `json:"tls_status"` // "compromised" | "secure"
	Progression    string        `json:"progression"` // "Phase 1 only" | "Full chain"

	// Si compromis
	CompromiseMethod string `json:"compromise_method,omitempty"`

	// Résumé
	Summary           string `json:"summary"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalCount     int    `json:"critical_count"`
	HighCount         int    `json:"high_count"`
	MediumCount       int    `json:"medium_count"`
	LowCount          int    `json:"low_count"`

	// Résultats des modules (compatibilité avec l'ancien format)
	APIEnumeration   *api.EnumerationResult         `json:"api_enumeration,omitempty"`
	JWTTesting       *jwt.JWTTestResult             `json:"jwt_testing,omitempty"`
	InjectionTesting *injection.InjectionTestResult `json:"injection_testing,omitempty"`
	HMACTesting      *hmac.HMACTestResult           `json:"hmac_testing,omitempty"`
	DoSTesting       *dos.DoSTestResult             `json:"dos_testing,omitempty"`
	TLSTesting       *tls.TLSTestResult             `json:"tls_testing,omitempty"`
}

// NewKillChainState crée un nouvel état de kill chain
func NewKillChainState() *KillChainState {
	return &KillChainState{
		CurrentPhase: PhaseRecon,
		Phases:       make(map[KillChainPhase]*PhaseResult),
	}
}

// AdvancePhase avance à la phase suivante du kill chain
func (kcs *KillChainState) AdvancePhase(phase KillChainPhase, result *PhaseResult) {
	kcs.Phases[phase] = result

	// Mettre à jour l'état TLS si compromis
	if result.TLSCompromised {
		kcs.TLSCompromised = true
		kcs.CompromiseMethod = result.CompromiseMethod
	}

	// Mettre à jour les métriques
	kcs.TotalFindings += len(result.Findings)

	// Déterminer la phase suivante
	if result.CanContinue {
		kcs.CurrentPhase = result.NextPhase
	} else {
		kcs.CurrentPhase = PhaseComplete
	}
}

// HasVulnerabilities retourne true si des vulnérabilités ont été trouvées
func (pr *PhaseResult) HasVulnerabilities() bool {
	return pr.VulnCount > 0
}

// ============================================================
// FIN KILL CHAIN TYPES
// ============================================================

// NewAttackOrchestrator creates a new attack orchestrator
func NewAttackOrchestrator(cfg *config.Config, verbose, noColor bool, outputDir string) *AttackOrchestrator {
	loader := discovery.NewDiscoveryLoader()
	attackContext, err := loader.LoadAttackContext()
	if err != nil {
		attackContext = nil
	}

	return &AttackOrchestrator{
		config:         cfg,
		target:         cfg.Target,
		attackContext:  attackContext,
		verbose:        verbose,
		noColor:        noColor,
		outputDir:      outputDir,
		killChainState: NewKillChainState(),
	}
}
