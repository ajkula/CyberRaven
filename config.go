package main

import (
	"time"
)

type Config struct {
	Engine  EngineConfig  `yaml:"engine" json:"engine"`
	Target  TargetConfig  `yaml:"target" json:"target"`
	Attacks AttacksConfig `yaml:"attacks" json:"attacks"`
	Reports ReportsConfig `yaml:"reports" json:"reports"`
	Output  OutputConfig  `yaml:"output" json:"output"`
	Logging LoggingConfig `yaml:"logging" json:"logging"`
}

type EngineConfig struct {
	MaxWorkers     int           `yaml:"max_workers" json:"max_workers"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	RateLimit      int           `yaml:"rate_limit" json:"rate_limit"`
	EnableSniffing bool          `yaml:"enable_sniffing" json:"enable_sniffing"`
	EnableAttacks  bool          `yaml:"enable_attacks" json:"enable_attacks"`
	MaxRetries     int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay     time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

type TargetConfig struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	BaseURL     string            `yaml:"base_url" json:"base_url"`
	Headers     map[string]string `yaml:"headers" json:"headers"`
	Auth        AuthConfig        `yaml:"auth" json:"auth"`
	TLS         TLSConfig         `yaml:"tls" json:"tls"`
	Profile     string            `yaml:"profile" json:"profile"`
}

type AuthConfig struct {
	Type          string            `yaml:"type" json:"type"`
	Username      string            `yaml:"username" json:"username"`
	Password      string            `yaml:"password" json:"password"`
	Token         string            `yaml:"token" json:"token"`
	HMAC          HMACConfig        `yaml:"hmac" json:"hmac"`
	CustomHeaders map[string]string `yaml:"custom_headers" json:"custom_headers"`
}

type HMACConfig struct {
	Secret             string        `yaml:"secret" json:"secret"`
	Algorithm          string        `yaml:"algorithm" json:"algorithm"`
	SignatureHeader    string        `yaml:"signature_header" json:"signature_header"`
	TimestampHeader    string        `yaml:"timestamp_header" json:"timestamp_header"`
	TimestampTolerance time.Duration `yaml:"timestamp_tolerance" json:"timestamp_tolerance"`
}

type TLSConfig struct {
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	CACertPath         string   `yaml:"ca_cert_path" json:"ca_cert_path"`
	ClientCertPath     string   `yaml:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath      string   `yaml:"client_key_path" json:"client_key_path"`
	MinVersion         string   `yaml:"min_version" json:"min_version"`
	MaxVersion         string   `yaml:"max_version" json:"max_version"`
	CipherSuites       []string `yaml:"cipher_suites" json:"cipher_suites"`
}

type AttacksConfig struct {
	Enabled    []string               `yaml:"enabled" json:"enabled"`
	Disabled   []string               `yaml:"disabled" json:"disabled"`
	Aggressive bool                   `yaml:"aggressive" json:"aggressive"`
	JWT        *JWTAttackConfig       `yaml:"jwt,omitempty" json:"jwt,omitempty"`
	API        *APIAttackConfig       `yaml:"api,omitempty" json:"api,omitempty"`
	HMAC       *HMACAttackConfig      `yaml:"hmac,omitempty" json:"hmac,omitempty"`
	Injection  *InjectionAttackConfig `yaml:"injection,omitempty" json:"injection,omitempty"`
	DoS        *DoSAttackConfig       `yaml:"dos,omitempty" json:"dos,omitempty"`
	TLS        *TLSAttackConfig       `yaml:"tls,omitempty" json:"tls,omitempty"`
}

type JWTAttackConfig struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	TestAlgNone      bool     `yaml:"test_alg_none" json:"test_alg_none"`
	TestAlgConfusion bool     `yaml:"test_alg_confusion" json:"test_alg_confusion"`
	TestWeakSecrets  bool     `yaml:"test_weak_secrets" json:"test_weak_secrets"`
	WeakSecrets      []string `yaml:"weak_secrets" json:"weak_secrets"`
	TestExpiration   bool     `yaml:"test_expiration" json:"test_expiration"`
}

type APIAttackConfig struct {
	Enable                 bool     `yaml:"enable" json:"enable"`
	EnableAutoDiscovery    bool     `yaml:"enable_auto_discovery" json:"enable_auto_discovery"`
	TestEnumeration        bool     `yaml:"test_enumeration" json:"test_enumeration"`
	TestMethodTampering    bool     `yaml:"test_method_tampering" json:"test_method_tampering"`
	TestParameterPollution bool     `yaml:"test_parameter_pollution" json:"test_parameter_pollution"`
	CommonEndpoints        []string `yaml:"common_endpoints" json:"common_endpoints"`
	Wordlists              []string `yaml:"wordlists" json:"wordlists"`
}

type HMACAttackConfig struct {
	Enable         bool          `yaml:"enable" json:"enable"`
	TestReplay     bool          `yaml:"test_replay" json:"test_replay"`
	TestTiming     bool          `yaml:"test_timing" json:"test_timing"`
	ReplayWindow   time.Duration `yaml:"replay_window" json:"replay_window"`
	TimingRequests int           `yaml:"timing_requests" json:"timing_requests"`
}

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

type TLSAttackConfig struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	TestCipherSuites bool     `yaml:"test_cipher_suites" json:"test_cipher_suites"`
	TestCertificates bool     `yaml:"test_certificates" json:"test_certificates"`
	TestDowngrade    bool     `yaml:"test_downgrade" json:"test_downgrade"`
	WeakCiphers      []string `yaml:"weak_ciphers" json:"weak_ciphers"`
	TestSelfSigned   bool     `yaml:"test_self_signed" json:"test_self_signed"`
	TestExpiredCerts bool     `yaml:"test_expired_certs" json:"test_expired_certs"`
}

type ReportsConfig struct {
	Formats        []string `yaml:"formats" json:"formats"`
	OutputDir      string   `yaml:"output_dir" json:"output_dir"`
	Template       string   `yaml:"template" json:"template"`
	IncludeLogs    bool     `yaml:"include_logs" json:"include_logs"`
	IncludeRawData bool     `yaml:"include_raw_data" json:"include_raw_data"`
	SeverityLevels []string `yaml:"severity_levels" json:"severity_levels"`
}

type OutputConfig struct {
	Verbosity    string `yaml:"verbosity" json:"verbosity"`
	Colors       bool   `yaml:"colors" json:"colors"`
	ProgressBars bool   `yaml:"progress_bars" json:"progress_bars"`
	Interactive  bool   `yaml:"interactive" json:"interactive"`
	RealTime     bool   `yaml:"real_time" json:"real_time"`
	ShowBanner   bool   `yaml:"show_banner" json:"show_banner"`
}

type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`
	Format     string `yaml:"format" json:"format"`
	OutputFile string `yaml:"output_file" json:"output_file"`
	Rotation   bool   `yaml:"rotation" json:"rotation"`
	MaxSize    int    `yaml:"max_size" json:"max_size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	MaxAge     int    `yaml:"max_age" json:"max_age"`
}
