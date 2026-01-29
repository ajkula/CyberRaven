# CyberRaven

[![English](https://img.shields.io/badge/lang-English-blue)](README.md)

**Outil professionnel de test d'intrusion en ligne de commande.**

CyberRaven est un framework de pen-testing modulaire écrit en Go. Il adopte une approche **Sniffer-First** : capturer le trafic réseau pour découvrir automatiquement les cibles, puis configurer et exécuter les tests de sécurité de manière ciblée.

```
   ___       _              ___
  / __|_   _| |__  ___ _ __|  _ \ __ ___ _____ _ _
 | |  | | | | '_ \/ -_) '__| |_) / _` \ V / -_) ' \
 | |__ \__, |_.__/\___|_|  |_|_|_\__,_|\_/\___|_||_|
  \___||___/                                  v1.0.0
```

---

## Philosophie

L'approche **Sniffer-First** se distingue des outils de pen-testing classiques qui nécessitent une configuration manuelle complète. CyberRaven fonctionne en 5 étapes :

1. **Capture** — Écoute le trafic réseau en temps réel
2. **Analyse** — Identifie automatiquement les endpoints, tokens et technologies
3. **Configuration** — Alimente les modules d'attaque avec les découvertes
4. **Exécution** — Lance les tests de sécurité de manière ciblée
5. **Rapport** — Génère des rapports avec preuves et recommandations

Cette approche réduit le temps de reconnaissance et améliore la pertinence des tests.

---

## Fonctionnalités

### Sniff — L'écoute intelligente

Le module sniffer capture le trafic réseau et en extrait automatiquement :

- Les **endpoints API** et leurs paramètres
- Les **tokens JWT**, sessions, clés API
- Les **signatures HMAC** et timestamps
- L'**empreinte technologique** (serveur, framework, langage)
- Les **fuites de données sensibles** (credentials, secrets)
- Les informations **TLS/certificats**

Le tout est injecté automatiquement dans ta configuration pour alimenter les attaques.

### Attack — 6 modules d'attaque spécialisés

| Module | Cible | Tests effectués |
|--------|-------|-----------------|
| **JWT** | Tokens JSON Web | Algorithm confusion, bypass "none", secrets faibles, expiration bypass |
| **API** | Endpoints REST | Énumération (220+ endpoints), method tampering, parameter pollution |
| **Injection** | Paramètres vulnérables | SQL, NoSQL, JSON, path traversal |
| **HMAC** | Authentification par signature | Replay attacks, timing side-channels, bypass de signature |
| **DoS** | Disponibilité du service | Flooding, large payloads, épuisement de connexions |
| **TLS** | Sécurité transport | Cipher suites, certificats, downgrade attacks, exploitation |

### Mode Kill Chain — Chaîne d'attaque progressive

CyberRaven dispose d'un mode **Kill Chain** qui simule une progression d'attaque réelle :

```
┌─────────────────┐
│ Phase 1: TLS    │  ← Tentative de casser la protection TLS
│   Exploitation  │
└────────┬────────┘
         │
    ┌────┴────┐
    │ Succès? │
    └────┬────┘
    NON  │   OUI
    ▼    │    ▼
┌───────┐│┌──────────────────┐
│Rapport│││ Phase 2: Attaques│  ← Attaque via canal compromis
│"TLS   │││   Applicatives   │
│Secure"│││  (JWT, API, etc) │
└───────┘│└────────┬─────────┘
         │         ▼
         │  ┌─────────────────┐
         │  │ Phase 3: Escalade│  ← Tentatives d'escalade
         │  └─────────────────┘
         ▼
   ┌───────────┐
   │  RAPPORT  │  ← Progression documentée
   └───────────┘
```

**Fonctionnalités clés :**
- **Exécution conditionnelle** — Les attaques applicatives ne s'exécutent que si TLS est compromis
- **Exploitation réelle** — Tentatives de downgrade protocole, exploitation de ciphers faibles, attaques sur certificats
- **Capacité MITM** — Proxy intégré pour l'interception du trafic quand TLS est cassé
- **Reporting professionnel** — Documente chaque phase avec preuves et raisonnement

### Report — Des rapports qui parlent

Génère des rapports exploitables dans plusieurs formats :

- **HTML** — Interactif, prêt à partager
- **JSON** — Pour l'intégration dans tes outils
- **PDF** — Pour les stakeholders
- **TXT** — Simple et direct

Chaque rapport inclut : synthèse, vulnérabilités détaillées, preuves, recommandations de remédiation.

---

## Installation

### Prérequis

- **Go 1.21+**
- **libpcap** (pour le sniffing réseau)
  - Linux : `sudo apt install libpcap-dev`
  - macOS : `brew install libpcap`
  - Windows : [Npcap](https://npcap.com/) ou WinPcap

### Build

```bash
# Cloner le repo
git clone https://github.com/ajkula/cyberraven.git
cd cyberraven

# Build standard
go build -o cyberraven

# Windows
go build -o cyberraven.exe
```

---

## Démarrage rapide

### 1. Initialiser la configuration

```bash
cyberraven --init-config
```

Crée un fichier `cyberraven.yaml` avec tous les paramètres par défaut.

### 2. Écouter le réseau (Sniffer-First)

```bash
# Linux/macOS (nécessite sudo pour le raw socket)
sudo ./cyberraven sniff --duration 2m --verbose

# Windows (exécuter en tant qu'Administrateur)
.\cyberraven.exe sniff --duration 2m --verbose
```

Le sniffer met à jour automatiquement `cyberraven.yaml` avec les découvertes.

### 3. Lancer les attaques

```bash
# Mode traditionnel - tous les modules séquentiellement
cyberraven attack --verbose

# Mode Kill Chain - attaques progressives conditionnelles
cyberraven attack --kill-chain --verbose
```

Les résultats sont stockés dans `./results/`.

### 4. Générer le rapport

```bash
cyberraven report --input ./results --format html,json
```

Les rapports sont générés dans `./reports/`.

---

## Commandes détaillées

### Commande `sniff`

Capture et analyse le trafic réseau.

```bash
cyberraven sniff [OPTIONS]
```

| Option | Court | Description | Défaut |
|--------|-------|-------------|--------|
| `--interface` | `-i` | Interface réseau | Auto-détection |
| `--duration` | `-d` | Durée de capture | `5m` |
| `--filter` | `-f` | Filtre BPF | Ports web courants |
| `--output` | `-o` | Fichier de sortie | `discovery.json` |
| `--verbose` | `-v` | Mode verbeux | `false` |

**Exemples de filtres BPF :**

```bash
# Trafic web uniquement
--filter "tcp port 80 or tcp port 443"

# Application sur port custom
--filter "tcp port 8080 or tcp port 3000"

# Hôte spécifique
--filter "host 192.168.1.100"

# Subnet entier
--filter "net 192.168.1.0/24"

# Combinaison
--filter "tcp port 80 and not host 127.0.0.1"
```

### Commande `attack`

Exécute les modules d'attaque.

```bash
cyberraven attack [OPTIONS]
```

| Option | Court | Description | Défaut |
|--------|-------|-------------|--------|
| `--target` | `-t` | URL cible (override) | Config YAML |
| `--modules` | `-m` | Modules spécifiques | Tous activés |
| `--aggressive` | `-a` | Mode agressif | `false` |
| `--kill-chain` | `-k` | Mode kill chain | `false` |
| `--output` | `-o` | Dossier de résultats | `./results` |
| `--verbose` | `-v` | Mode verbeux | `false` |

**Exemples :**

```bash
# Tous les modules activés (mode traditionnel)
cyberraven attack

# Mode Kill Chain - TLS d'abord, puis attaques app si compromis
cyberraven attack --kill-chain --verbose

# Modules spécifiques
cyberraven attack --modules jwt,api,injection

# Cible différente de la config
cyberraven attack --target https://api.example.com

# Mode agressif (plus de payloads, moins de délai)
cyberraven attack --aggressive --verbose

# Kill chain contre une cible spécifique
cyberraven attack --kill-chain --target https://legacy.example.com
```

### Commande `report`

Génère les rapports de sécurité.

```bash
cyberraven report [OPTIONS]
```

| Option | Court | Description | Défaut |
|--------|-------|-------------|--------|
| `--input` | `-i` | Dossier des résultats | **Requis** |
| `--output` | `-o` | Dossier de sortie | `./reports` |
| `--format` | `-f` | Formats (html,json,pdf,txt) | `html` |
| `--template` | `-T` | Template custom | Built-in |
| `--verbose` | `-v` | Mode verbeux | `false` |

**Exemples :**

```bash
# Rapport HTML simple
cyberraven report --input ./results

# Multiples formats
cyberraven report --input ./results --format html,json,pdf

# Dossier de sortie personnalisé
cyberraven report --input ./results --output ./audit_client_X
```

### Options globales

Disponibles sur toutes les commandes :

| Option | Court | Description |
|--------|-------|-------------|
| `--config` | `-c` | Chemin du fichier config |
| `--verbose` | `-v` | Sortie détaillée |
| `--quiet` | `-q` | Erreurs uniquement |
| `--no-color` | | Désactive les couleurs |
| `--no-banner` | | Désactive la bannière ASCII |

---

## Mode Kill Chain

Le mode Kill Chain (`--kill-chain` ou `-k`) implémente une progression d'attaque professionnelle qui reflète la méthodologie réelle de test d'intrusion.

### Comment ça fonctionne

1. **Phase 1 : Exploitation TLS**
   - Analyse la configuration TLS pour détecter les faiblesses
   - Tente le downgrade de protocole (SSL3, TLS 1.0)
   - Teste l'exploitation de ciphers faibles (RC4, DES, Export)
   - Vérifie les vulnérabilités de certificats (auto-signé, expiré, clés faibles)
   - Tente l'exploitation de la renégociation non sécurisée

2. **Phase 2 : Attaques Applicatives** (uniquement si TLS compromis)
   - Route les attaques via le canal TLS compromis
   - Exécute : énumération API, test JWT, test injection, test HMAC, test DoS
   - Tout le trafic bénéficie de l'interception TLS

3. **Phase 3 : Escalade** (uniquement si vulnérabilités trouvées)
   - Analyse les vulnérabilités découvertes pour les chemins d'escalade
   - Identifie les opportunités d'escalade de privilèges
   - Cartographie les possibilités de mouvement latéral
   - Documente les risques d'exfiltration de données

### Quand utiliser le mode Kill Chain

- **Tests d'intrusion professionnels** — Démontre une vraie progression d'attaque
- **Évaluations de sécurité** — Montre l'exploitabilité réelle, pas juste la détection
- **Audits de conformité** — Prouve l'efficacité de la protection TLS
- **Exercices Red Team** — Simule le comportement d'un adversaire

### Exemple de sortie

```
╔══════════════════════════════════════════════════════════════╗
║          CYBERRAVEN - KILL CHAIN ATTACK MODE                 ║
╠══════════════════════════════════════════════════════════════╣
║  Phase 1: TLS Exploitation   → Casser la protection TLS      ║
║  Phase 2: App Attacks        → Attaque via canal compromis   ║
║  Phase 3: Escalation         → Tentatives d'escalade         ║
╚══════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────────┐
│ PHASE: tls_exploitation                                        │
│ Tentative d'exploitation TLS                                   │
└────────────────────────────────────────────────────────────────┘
  [*] Analyse TLS et tentative d'exploitation...
  [+] TLS Secure - Aucune faiblesse exploitable

╔══════════════════════════════════════════════════════════════╗
║                    KILL CHAIN COMPLETE                       ║
╠══════════════════════════════════════════════════════════════╣
║  TLS Status: SECURE                                          ║
║  Progression: Phase 1 uniquement - TLS sécurisé              ║
║  Phase finale: tls_exploitation                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Configuration

Le fichier `cyberraven.yaml` centralise toute la configuration. Voici les sections principales :

### Cible

```yaml
target:
  name: "Mon API"
  base_url: "https://api.example.com"
  headers:
    X-Custom-Header: "value"
  auth:
    type: bearer          # none, basic, bearer, jwt, hmac
    token: "eyJhbGciOiJI..."
```

### Modules d'attaque

```yaml
attacks:
  aggressive: false

  jwt:
    enable: true
    test_alg_none: true
    test_alg_confusion: true
    test_weak_secrets: true
    # 120+ secrets testés par défaut

  api:
    enable: true
    enable_auto_discovery: true
    test_enumeration: true
    test_method_tampering: true
    # 220+ endpoints dans la wordlist

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
    enable: false          # Désactivé par défaut (intrusif)
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
  interface: ""            # Auto-détection
  duration: 5m
  capture_http: true
  capture_https: true
  auto_update_config: true # Met à jour cyberraven.yaml automatiquement
  min_confidence: 0.6
```

### Rapports

```yaml
reports:
  formats: [html, json]
  output_dir: ./reports
  include_logs: true
  include_raw_data: false
  severity_levels: [low, medium, high, critical]
```

---

## Workflow typique

### Scénario 1 : Évaluation Kill Chain complète

```bash
# 1. Initialiser
cyberraven --init-config

# 2. Capturer le trafic (optionnel, pour la découverte)
sudo cyberraven sniff --duration 5m --verbose

# 3. Attaque Kill Chain
cyberraven attack --kill-chain --target https://api.example.com --verbose

# 4. Générer le rapport
cyberraven report --input ./results --format html,json
```

### Scénario 2 : Audit d'une API inconnue

```bash
# 1. Générer le trafic en utilisant l'app normalement
#    (dans un autre terminal, utilise l'application cible)

# 2. Capturer et analyser
sudo cyberraven sniff --duration 5m --verbose

# 3. Vérifier les découvertes
cat discovery.json

# 4. Ajuster la config si nécessaire
nano cyberraven.yaml

# 5. Lancer l'attaque
cyberraven attack --verbose

# 6. Rapport
cyberraven report --input ./results --format html,json
```

### Scénario 3 : Test ciblé JWT

```bash
# Config minimale dans cyberraven.yaml
# target.base_url + attacks.jwt.enable = true

cyberraven attack --modules jwt --verbose
```

### Scénario 4 : Scan rapide d'énumération

```bash
cyberraven attack --modules api --target https://api.example.com
```

---

## Structure du projet

```
cyberraven/
├── main.go                 # Point d'entrée CLI
├── cyberraven.yaml         # Configuration par défaut
│
├── cmd/                    # Commandes CLI
│   ├── sniff/              # Module sniffing
│   ├── attack/             # Orchestrateur d'attaque & kill chain
│   │   ├── attack.go       # Handler CLI
│   │   ├── orchestrator.go # Orchestration attaque & kill chain
│   │   └── types.go        # Types kill chain
│   └── report/             # Module rapport
│
├── pkg/                    # Packages métier
│   ├── sniffer/            # Moteur de capture réseau
│   ├── attacks/            # Modules d'attaque
│   │   ├── jwt/            # Attaques JWT
│   │   ├── api/            # Énumération API
│   │   ├── injection/      # Injections SQL/NoSQL/etc
│   │   ├── hmac/           # Tests HMAC
│   │   ├── dos/            # Tests DoS
│   │   └── tls/            # Tests TLS & exploitation
│   │       ├── tls.go      # Testeur TLS principal
│   │       ├── exploiter.go# Moteur d'exploitation TLS
│   │       └── downgrade.go# Attaques downgrade
│   ├── proxy/              # Proxy MITM pour interception TLS
│   │   ├── mitm.go         # Implémentation proxy MITM
│   │   └── certgen.go      # Génération dynamique de certificats
│   ├── discovery/          # Intelligence de découverte
│   ├── reporting/          # Générateur de rapports
│   ├── config/             # Gestion de configuration
│   └── utils/              # Utilitaires
│
├── results/                # Résultats des attaques
├── reports/                # Rapports générés
└── discovery.json          # Découvertes du sniffer
```

---

## Avertissement légal

CyberRaven est un outil conçu pour les **tests de sécurité autorisés** uniquement.

**Tu es responsable** de t'assurer que tu as l'autorisation explicite de tester les systèmes ciblés. L'utilisation de cet outil contre des systèmes sans autorisation est **illégale** et **contraire à l'éthique**.

Cas d'usage légitimes :
- Tests d'intrusion dans le cadre d'un contrat
- Challenges CTF
- Recherche en sécurité sur tes propres systèmes
- Environnements de lab et formations

---

## Contribuer

Les contributions sont les bienvenues. Fork, branche, PR — tu connais la musique.

Points d'attention :
- Respecter l'architecture modulaire existante
- Ajouter des tests pour les nouvelles fonctionnalités
- Documenter les nouveaux modules d'attaque

---

## Auteur

**Greg JEFTIC**

---

## Licence

Ce projet est destiné à un usage éducatif et professionnel dans le cadre de tests de sécurité autorisés.
