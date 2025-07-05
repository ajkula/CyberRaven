package config

import (
	"time"
)

// Config represents the main CyberRaven configuration
type Config struct {
	// Core engine settings
	Engine EngineConfig `yaml:"engine" json:"engine"`

	// Target configuration
	Target TargetConfig `yaml:"target" json:"target"`

	// Attack modules configuration
	Attacks AttacksConfig `yaml:"attacks" json:"attacks"`

	// Reporting configuration
	Reports ReportsConfig `yaml:"reports" json:"reports"`

	// Output and UI configuration
	Output OutputConfig `yaml:"output" json:"output"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`
}

// EngineConfig defines the core engine behavior
type EngineConfig struct {
	// Maximum concurrent workers for attacks
	MaxWorkers int `yaml:"max_workers" json:"max_workers"`

	// Timeout for individual attack operations
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Request rate limiting (requests per second)
	RateLimit int `yaml:"rate_limit" json:"rate_limit"`

	// Enable/disable modules
	EnableSniffing bool `yaml:"enable_sniffing" json:"enable_sniffing"`
	EnableAttacks  bool `yaml:"enable_attacks" json:"enable_attacks"`

	// Retry configuration
	MaxRetries int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

// TargetConfig defines the target system configuration
type TargetConfig struct {
	// Target identification
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`

	// Connection details
	BaseURL string            `yaml:"base_url" json:"base_url"`
	Headers map[string]string `yaml:"headers" json:"headers"`

	// Authentication
	Auth AuthConfig `yaml:"auth" json:"auth"`

	// TLS configuration
	TLS TLSConfig `yaml:"tls" json:"tls"`

	// Target profile (webapp-generic, api-rest, messaging-system)
	Profile string `yaml:"profile" json:"profile"`
}

// AuthConfig defines authentication parameters
type AuthConfig struct {
	// Authentication type (none, basic, bearer, jwt, hmac, custom)
	Type string `yaml:"type" json:"type"`

	// Credentials for basic auth
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`

	// Token for bearer/JWT auth
	Token string `yaml:"token" json:"token"`

	// HMAC configuration
	HMAC HMACConfig `yaml:"hmac" json:"hmac"`

	// Custom authentication headers
	CustomHeaders map[string]string `yaml:"custom_headers" json:"custom_headers"`
}

// HMACConfig defines HMAC authentication parameters
type HMACConfig struct {
	// Secret key for HMAC signing
	Secret string `yaml:"secret" json:"secret"`

	// Algorithm (sha256, sha512)
	Algorithm string `yaml:"algorithm" json:"algorithm"`

	// Header name for signature
	SignatureHeader string `yaml:"signature_header" json:"signature_header"`

	// Header name for timestamp
	TimestampHeader string `yaml:"timestamp_header" json:"timestamp_header"`

	// Timestamp tolerance for replay protection
	TimestampTolerance time.Duration `yaml:"timestamp_tolerance" json:"timestamp_tolerance"`
}

// TLSConfig defines TLS-specific testing parameters
type TLSConfig struct {
	// Skip certificate verification for testing
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// Custom CA certificate path
	CACertPath string `yaml:"ca_cert_path" json:"ca_cert_path"`

	// Client certificate for mutual TLS
	ClientCertPath string `yaml:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath  string `yaml:"client_key_path" json:"client_key_path"`

	// Minimum TLS version to test
	MinVersion string `yaml:"min_version" json:"min_version"`

	// Maximum TLS version to test
	MaxVersion string `yaml:"max_version" json:"max_version"`

	// Cipher suites to test
	CipherSuites []string `yaml:"cipher_suites" json:"cipher_suites"`
}

// AttacksConfig defines configuration for all attack modules
type AttacksConfig struct {
	// Global attack settings
	Enabled    []string `yaml:"enabled" json:"enabled"`       // List of enabled attack modules
	Disabled   []string `yaml:"disabled" json:"disabled"`     // List of disabled attack modules
	Aggressive bool     `yaml:"aggressive" json:"aggressive"` // Enable aggressive testing mode

	// Individual module configurations
	JWT       JWTAttackConfig       `yaml:"jwt" json:"jwt"`
	HMAC      HMACAttackConfig      `yaml:"hmac" json:"hmac"`
	API       APIAttackConfig       `yaml:"api" json:"api"`
	Injection InjectionAttackConfig `yaml:"injection" json:"injection"`
	DoS       DoSAttackConfig       `yaml:"dos" json:"dos"`
	TLS       TLSAttackConfig       `yaml:"tls" json:"tls"`
}

// JWTAttackConfig defines JWT-specific attack parameters
type JWTAttackConfig struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	TestAlgNone      bool     `yaml:"test_alg_none" json:"test_alg_none"`
	TestAlgConfusion bool     `yaml:"test_alg_confusion" json:"test_alg_confusion"`
	TestWeakSecrets  bool     `yaml:"test_weak_secrets" json:"test_weak_secrets"`
	WeakSecrets      []string `yaml:"weak_secrets" json:"weak_secrets"`
	TestExpiration   bool     `yaml:"test_expiration" json:"test_expiration"`
}

// HMACAttackConfig defines HMAC-specific attack parameters
type HMACAttackConfig struct {
	Enable         bool          `yaml:"enable" json:"enable"`
	TestReplay     bool          `yaml:"test_replay" json:"test_replay"`
	TestTiming     bool          `yaml:"test_timing" json:"test_timing"`
	ReplayWindow   time.Duration `yaml:"replay_window" json:"replay_window"`
	TimingRequests int           `yaml:"timing_requests" json:"timing_requests"`
}

// APIAttackConfig defines API-specific attack parameters
type APIAttackConfig struct {
	Enable                 bool     `yaml:"enable" json:"enable"`
	EnableAutoDiscovery    bool     `yaml:"enable_auto_discovery" json:"enable_auto_discovery"` // NEW: Auto-discover protocols
	TestEnumeration        bool     `yaml:"test_enumeration" json:"test_enumeration"`
	TestMethodTampering    bool     `yaml:"test_method_tampering" json:"test_method_tampering"`
	TestParameterPollution bool     `yaml:"test_parameter_pollution" json:"test_parameter_pollution"`
	CommonEndpoints        []string `yaml:"common_endpoints" json:"common_endpoints"`
	Wordlists              []string `yaml:"wordlists" json:"wordlists"`
}

// InjectionAttackConfig defines injection attack parameters
type InjectionAttackConfig struct {
	Enable        bool     `yaml:"enable" json:"enable"`
	TestSQL       bool     `yaml:"test_sql" json:"test_sql"`
	TestNoSQL     bool     `yaml:"test_nosql" json:"test_nosql"`
	TestJSON      bool     `yaml:"test_json" json:"test_json"`
	TestPath      bool     `yaml:"test_path" json:"test_path"`
	SQLPayloads   []string `yaml:"sql_payloads" json:"sql_payloads"`
	NoSQLPayloads []string `yaml:"nosql_payloads" json:"nosql_payloads"`
	JSONPayloads  []string `yaml:"json_payloads" json:"json_payloads"`
	PathPayloads  []string `yaml:"path_payloads" json:"path_payloads"`
}

// DoSAttackConfig defines DoS attack parameters
type DoSAttackConfig struct {
	Enable             bool          `yaml:"enable" json:"enable"`
	TestFlooding       bool          `yaml:"test_flooding" json:"test_flooding"`
	TestLargePayloads  bool          `yaml:"test_large_payloads" json:"test_large_payloads"`
	TestConnExhaustion bool          `yaml:"test_conn_exhaustion" json:"test_conn_exhaustion"`
	FloodingDuration   time.Duration `yaml:"flooding_duration" json:"flooding_duration"`
	FloodingRate       int           `yaml:"flooding_rate" json:"flooding_rate"`
	MaxPayloadSize     int           `yaml:"max_payload_size" json:"max_payload_size"`
	MaxConnections     int           `yaml:"max_connections" json:"max_connections"`
}

// TLSAttackConfig defines TLS-specific attack parameters
type TLSAttackConfig struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	TestCipherSuites bool     `yaml:"test_cipher_suites" json:"test_cipher_suites"`
	TestCertificates bool     `yaml:"test_certificates" json:"test_certificates"`
	TestDowngrade    bool     `yaml:"test_downgrade" json:"test_downgrade"`
	WeakCiphers      []string `yaml:"weak_ciphers" json:"weak_ciphers"`
	TestSelfSigned   bool     `yaml:"test_self_signed" json:"test_self_signed"`
	TestExpiredCerts bool     `yaml:"test_expired_certs" json:"test_expired_certs"`
}

// ReportsConfig defines reporting configuration
type ReportsConfig struct {
	// Output formats to generate (json, html, pdf, txt)
	Formats []string `yaml:"formats" json:"formats"`

	// Output directory for reports
	OutputDir string `yaml:"output_dir" json:"output_dir"`

	// Report template
	Template string `yaml:"template" json:"template"`

	// Include detailed logs in reports
	IncludeLogs bool `yaml:"include_logs" json:"include_logs"`

	// Include raw HTTP requests/responses
	IncludeRawData bool `yaml:"include_raw_data" json:"include_raw_data"`

	// Severity levels to include (low, medium, high, critical)
	SeverityLevels []string `yaml:"severity_levels" json:"severity_levels"`
}

// OutputConfig defines output and UI configuration
type OutputConfig struct {
	// Output verbosity level (silent, minimal, normal, verbose, debug)
	Verbosity string `yaml:"verbosity" json:"verbosity"`

	// Enable colored output
	Colors bool `yaml:"colors" json:"colors"`

	// Enable progress bars
	ProgressBars bool `yaml:"progress_bars" json:"progress_bars"`

	// Enable interactive mode
	Interactive bool `yaml:"interactive" json:"interactive"`

	// Real-time output during scanning
	RealTime bool `yaml:"real_time" json:"real_time"`

	// Show ASCII art banner
	ShowBanner bool `yaml:"show_banner" json:"show_banner"`
}

// LoggingConfig defines logging configuration
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `yaml:"level" json:"level"`

	// Log format (text, json)
	Format string `yaml:"format" json:"format"`

	// Log output file
	OutputFile string `yaml:"output_file" json:"output_file"`

	// Enable log rotation
	Rotation bool `yaml:"rotation" json:"rotation"`

	// Maximum log file size in MB
	MaxSize int `yaml:"max_size" json:"max_size"`

	// Maximum number of old log files to retain
	MaxBackups int `yaml:"max_backups" json:"max_backups"`

	// Maximum age of log files in days
	MaxAge int `yaml:"max_age" json:"max_age"`
}

// AttackProfile defines a reusable attack configuration profile
type AttackProfile struct {
	// Profile metadata
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Version     string `yaml:"version" json:"version"`
	Author      string `yaml:"author" json:"author"`

	// Profile-specific configurations
	Engine  EngineConfig  `yaml:"engine" json:"engine"`
	Attacks AttacksConfig `yaml:"attacks" json:"attacks"`
	Reports ReportsConfig `yaml:"reports" json:"reports"`

	// Tags for profile categorization
	Tags []string `yaml:"tags" json:"tags"`
}

// SnifferConfig defines the network sniffer configuration
type SnifferConfig struct {
	// Network capture settings
	Interface   string `yaml:"interface" json:"interface"`     // Network interface (eth0, wlan0, any)
	BPFFilter   string `yaml:"bpf_filter" json:"bpf_filter"`   // Berkeley Packet Filter
	SnapLength  int    `yaml:"snap_length" json:"snap_length"` // Maximum packet capture length
	Promiscuous bool   `yaml:"promiscuous" json:"promiscuous"` // Promiscuous mode

	// Capture behavior
	Duration       time.Duration `yaml:"duration" json:"duration"`               // Capture duration (0 = indefinite)
	PacketLimit    int           `yaml:"packet_limit" json:"packet_limit"`       // Max packets to capture (0 = unlimited)
	BufferSize     int           `yaml:"buffer_size" json:"buffer_size"`         // Capture buffer size
	CaptureTimeout time.Duration `yaml:"capture_timeout" json:"capture_timeout"` // Packet capture timeout

	// Protocol focus
	CaptureHTTP  bool `yaml:"capture_http" json:"capture_http"`   // Capture HTTP traffic
	CaptureHTTPS bool `yaml:"capture_https" json:"capture_https"` // Capture HTTPS traffic (headers only)
	CaptureOther bool `yaml:"capture_other" json:"capture_other"` // Capture other protocols

	// Analysis settings
	RealTimeAnalysis  bool          `yaml:"real_time_analysis" json:"real_time_analysis"` // Analyze packets in real-time
	DetectionInterval time.Duration `yaml:"detection_interval" json:"detection_interval"` // How often to run detection
	MinConfidence     float64       `yaml:"min_confidence" json:"min_confidence"`         // Minimum confidence for discoveries
	MaxEndpoints      int           `yaml:"max_endpoints" json:"max_endpoints"`           // Max endpoints to track
	MaxTokens         int           `yaml:"max_tokens" json:"max_tokens"`                 // Max tokens to track

	// Output settings
	OutputFormat      string `yaml:"output_format" json:"output_format"`           // json, yaml, text
	SaveConversations bool   `yaml:"save_conversations" json:"save_conversations"` // Save HTTP conversations
	SaveRawPackets    bool   `yaml:"save_raw_packets" json:"save_raw_packets"`     // Save raw packet data

	// Configurator settings
	AutoUpdateConfig     bool          `yaml:"auto_update_config" json:"auto_update_config"`         // Automatically update cyberraven.yaml
	ConfigUpdateInterval time.Duration `yaml:"config_update_interval" json:"config_update_interval"` // How often to update config
	BackupConfig         bool          `yaml:"backup_config" json:"backup_config"`                   // Backup config before updates
	DryRunUpdates        bool          `yaml:"dry_run_updates" json:"dry_run_updates"`               // Don't actually update, just report
}
