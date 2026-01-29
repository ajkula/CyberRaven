# CyberRaven

[![Français](https://img.shields.io/badge/lang-Fran%C3%A7ais-blue)](README_FR.md)

**Automated penetration testing command-line tool.**

CyberRaven is a modular pen-testing framework written in Go. It adopts a **Sniffer-First** approach: capture network traffic to automatically discover targets, then configure and execute security tests in a targeted manner.

```
   ___       _              ___
  / __|_   _| |__  ___ _ __|  _ \ __ ___ _____ _ _
 | |  | | | | '_ \/ -_) '__| |_) / _` \ V / -_) ' \
 | |__ \__, |_.__/\___|_|  |_|_|_\__,_|\_/\___|_||_|
  \___||___/                                   v1.0.0
```

---

## Philosophy

The **Sniffer-First** approach differs from traditional pen-testing tools that require complete manual configuration. CyberRaven operates in 5 stages:

1. **Capture** — Listen to network traffic in real-time
2. **Analysis** — Automatically identify endpoints, tokens, and technologies
3. **Configuration** — Feed attack modules with discoveries
4. **Execution** — Launch targeted security tests
5. **Report** — Generate reports with evidence and recommendations

This approach reduces reconnaissance time and improves test relevance.

---

## Features

### Sniff — Intelligent Listening

The sniffer module captures network traffic and automatically extracts:

- **API endpoints** and their parameters
- **JWT tokens**, sessions, API keys
- **HMAC signatures** and timestamps
- **Technology fingerprint** (server, framework, language)
- **Sensitive data leaks** (credentials, secrets)
- **TLS/certificate** information

Everything is automatically injected into your configuration to fuel the attacks.

### Attack — 6 Specialized Attack Modules

| Module | Target | Tests Performed |
|--------|--------|-----------------|
| **JWT** | JSON Web Tokens | Algorithm confusion, "none" bypass, weak secrets, expiration bypass |
| **API** | REST Endpoints | Enumeration (220+ endpoints), method tampering, parameter pollution |
| **Injection** | Vulnerable Parameters | SQL, NoSQL, JSON, path traversal |
| **HMAC** | Signature Authentication | Replay attacks, timing side-channels, signature bypass |
| **DoS** | Service Availability | Flooding, large payloads, connection exhaustion |
| **TLS** | Transport Security | Cipher suites, certificates, downgrade attacks |

### Report — Actionable Reports

Generate actionable reports in multiple formats:

- **HTML** — Interactive, ready to share
- **JSON** — For integration with your tools
- **PDF** — For stakeholders
- **TXT** — Simple and direct

Each report includes: summary, detailed vulnerabilities, evidence, remediation recommendations.

---

## Installation

### Prerequisites

- **Go 1.24+**
- **libpcap** (for network sniffing)
  - Linux: `sudo apt install libpcap-dev`
  - macOS: `brew install libpcap`
  - Windows: [Npcap](https://npcap.com/) or WinPcap

### Build

```bash
# Clone the repo
git clone https://github.com/your-repo/cyberraven.git
cd cyberraven

# Standard build
go build -o cyberraven

# Windows
go build -o cyberraven.exe
```

---

## Quick Start

### 1. Initialize Configuration

```bash
cyberraven --init-config
```

Creates a `cyberraven.yaml` file with all default settings.

### 2. Listen to Network (Sniffer-First)

```bash
# Linux/macOS (requires sudo for raw socket)
sudo ./cyberraven sniff --duration 2m --verbose

# Windows (run as Administrator)
.\cyberraven.exe sniff --duration 2m --verbose
```

The sniffer automatically updates `cyberraven.yaml` with discoveries.

### 3. Launch Attacks

```bash
cyberraven attack --verbose
```

Results are stored in `./results/`.

### 4. Generate Report

```bash
cyberraven report --input ./results --format html,json
```

Reports are generated in `./reports/`.

---

## Detailed Commands

### `sniff` Command

Captures and analyzes network traffic.

```bash
cyberraven sniff [OPTIONS]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--interface` | `-i` | Network interface | Auto-detection |
| `--duration` | `-d` | Capture duration | `5m` |
| `--filter` | `-f` | BPF filter | Common web ports |
| `--output` | `-o` | Output file | `discovery.json` |
| `--verbose` | `-v` | Verbose mode | `false` |

**BPF Filter Examples:**

```bash
# Web traffic only
--filter "tcp port 80 or tcp port 443"

# Custom port application
--filter "tcp port 8080 or tcp port 3000"

# Specific host
--filter "host 192.168.1.100"

# Entire subnet
--filter "net 192.168.1.0/24"

# Combination
--filter "tcp port 80 and not host 127.0.0.1"
```

### `attack` Command

Executes attack modules.

```bash
cyberraven attack [OPTIONS]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-t` | Target URL (override) | YAML config |
| `--modules` | `-m` | Specific modules | All enabled |
| `--aggressive` | `-a` | Aggressive mode | `false` |
| `--output` | `-o` | Results folder | `./results` |
| `--verbose` | `-v` | Verbose mode | `false` |

**Examples:**

```bash
# All modules enabled
cyberraven attack

# Specific modules
cyberraven attack --modules jwt,api,injection

# Different target than config
cyberraven attack --target https://api.example.com

# Aggressive mode (more payloads, less delay)
cyberraven attack --aggressive --verbose
```

### `report` Command

Generates security reports.

```bash
cyberraven report [OPTIONS]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Results folder | **Required** |
| `--output` | `-o` | Output folder | `./reports` |
| `--format` | `-f` | Formats (html,json,pdf,txt) | `html` |
| `--template` | `-T` | Custom template | Built-in |
| `--verbose` | `-v` | Verbose mode | `false` |

**Examples:**

```bash
# Simple HTML report
cyberraven report --input ./results

# Multiple formats
cyberraven report --input ./results --format html,json,pdf

# Custom output folder
cyberraven report --input ./results --output ./audit_client_X
```

### Global Options

Available on all commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Config file path |
| `--verbose` | `-v` | Detailed output |
| `--quiet` | `-q` | Errors only |
| `--no-color` | | Disable colors |
| `--no-banner` | | Disable ASCII banner |

---

## Configuration

The `cyberraven.yaml` file centralizes all configuration. Here are the main sections:

### Target

```yaml
target:
  name: "My API"
  base_url: "https://api.example.com"
  headers:
    X-Custom-Header: "value"
  auth:
    type: bearer          # none, basic, bearer, jwt, hmac
    token: "eyJhbGciOiJI..."
```

### Attack Modules

```yaml
attacks:
  aggressive: false

  jwt:
    enable: true
    test_alg_none: true
    test_alg_confusion: true
    test_weak_secrets: true
    # 120+ secrets tested by default

  api:
    enable: true
    enable_auto_discovery: true
    test_enumeration: true
    test_method_tampering: true
    # 220+ endpoints in wordlist

  injection:
    enable: true
    test_sql: true
    test_nosql: true
    test_json: true
    test_path: true

  hmac:
    enable: true
    test_replay: true
    test_timing: true
    replay_window: 5m

  dos:
    enable: false          # Disabled by default (intrusive)
    flooding_rate: 20
    flooding_duration: 10s

  tls:
    enable: true
    test_cipher_suites: true
    test_certificates: true
    test_downgrade: true
```

### Sniffer

```yaml
sniffer:
  interface: ""            # Auto-detection
  duration: 5m
  capture_http: true
  capture_https: true
  auto_update_config: true # Automatically updates cyberraven.yaml
  min_confidence: 0.6
```

### Reports

```yaml
reports:
  formats: [html, json]
  output_dir: ./reports
  include_logs: true
  include_raw_data: false
  severity_levels: [low, medium, high, critical]
```

---

## Typical Workflow

### Scenario 1: Auditing an Unknown API

```bash
# 1. Generate traffic by using the app normally
#    (in another terminal, use the target application)

# 2. Capture and analyze
sudo cyberraven sniff --duration 5m --verbose

# 3. Check discoveries
cat discovery.json

# 4. Adjust config if needed
nano cyberraven.yaml

# 5. Launch attack
cyberraven attack --verbose

# 6. Report
cyberraven report --input ./results --format html,json
```

### Scenario 2: Targeted JWT Test

```bash
# Minimal config in cyberraven.yaml
# target.base_url + attacks.jwt.enable = true

cyberraven attack --modules jwt --verbose
```

### Scenario 3: Quick Enumeration Scan

```bash
cyberraven attack --modules api --target https://api.example.com
```

---

## Project Structure

```
cyberraven/
├── main.go                 # CLI entry point
├── config.go               # Configuration types
├── cyberraven.yaml         # Default configuration
│
├── cmd/                    # CLI commands
│   ├── sniff/              # Sniffing module
│   ├── attack/             # Attack module
│   └── report/             # Report module
│
├── pkg/                    # Business packages
│   ├── sniffer/            # Network capture engine
│   ├── attacks/            # Attack modules
│   │   ├── jwt/            # JWT attacks
│   │   ├── api/            # API enumeration
│   │   ├── injection/      # SQL/NoSQL/etc injections
│   │   ├── hmac/           # HMAC tests
│   │   ├── dos/            # DoS tests
│   │   └── tls/            # TLS tests
│   ├── reporting/          # Report generator
│   └── utils/              # Utilities
│
├── results/                # Attack results
├── reports/                # Generated reports
└── texts/                  # Additional documentation
```

---

## Legal Disclaimer

CyberRaven is a tool designed for **authorized security testing** only.

**You are responsible** for ensuring you have explicit authorization to test targeted systems. Using this tool against systems without authorization is **illegal** and **unethical**.

Legitimate use cases:
- Penetration testing under contract
- CTF challenges
- Security research on your own systems
- Lab environments and training

---

## Contributing

Contributions are welcome. Fork, branch, PR — you know the drill.

Key points:
- Respect the existing modular architecture
- Add tests for new features
- Document new attack modules

---

## Author

**Greg JEFTIC**

---

## License

This project is intended for educational and professional use in the context of authorized security testing.
