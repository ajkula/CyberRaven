Ambitions initiales 🎯

6 modules d'attaque (JWT, HMAC, API, Injection, DoS, TLS)
Architecture modulaire avec SRP strict
Rapports détaillés avec métriques
Tests automatisés pour chaque vulnérabilité

cyberraven/
├── go.mod
├── go.sum                              (généré par go mod tidy)
├── main.go                             # CLI principal avec sous-commandes
├── cmd/
│   ├── sniff/
│   │   └── sniff.go                    # Commande sniffing
│   ├── attack/
│   │   └── attack.go                   # Commande pen-testing
│   ├── report/
│   │   └── report.go                   # Commande génération rapports
│   └── demo/
│       └── demo.go                     # Commande démo automatisée
├── pkg/
│   ├── sniffer/                        # Module sniffing réseau
│   │   ├── engine.go                   # Engine capture TCP
│   │   ├── analyzer.go                 # Analyse paquets
│   │   ├── detector.go                 # Détection données sensibles
│   │   └── formatter.go                # Formatage output
│   ├── attacks/                        # Modules d'attaque (SRP)
│   │   ├── jwt/
│   │   │   ├── fuzzer.go               # JWT fuzzing
│   │   │   ├── manipulator.go          # Token manipulation
│   │   │   └── validator.go            # Validation bypass
│   │   ├── hmac/
│   │   │   ├── replay.go               # Replay attacks
│   │   │   ├── signature.go            # Signature bypass
│   │   │   └── timing.go               # Timing attacks
│   │   ├── api/
│   │   │   ├── enumeration.go          # Endpoint discovery
│   │   │   ├── methods.go              # HTTP method tampering
│   │   │   └── parameters.go           # Parameter pollution
│   │   ├── injection/
│   │   │   ├── sql.go                  # SQL injection tests
│   │   │   ├── nosql.go                # NoSQL injection
│   │   │   ├── json.go                 # JSON injection
│   │   │   └── path.go                 # Path traversal
│   │   ├── dos/
│   │   │   ├── flooding.go             # Request flooding
│   │   │   ├── payload.go              # Large payload attacks
│   │   │   └── connection.go           # Connection exhaustion
│   │   └── tls/
│   │       ├── cipher.go               # Cipher suite analysis
│   │       ├── certificate.go          # Certificate validation
│   │       └── downgrade.go            # Protocol downgrade
│   ├── scanner/                        # Engine principal
│   │   ├── orchestrator.go             # Orchestration attaques
│   │   ├── scheduler.go                # Planification tests
│   │   ├── executor.go                 # Exécution parallèle
│   │   └── aggregator.go               # Agrégation résultats
│   ├── reporting/                      # Génération rapports
│   │   ├── generator.go                # Générateur principal
│   │   ├── templates.go                # Templates rapports
│   │   ├── exporters.go                # Export JSON/HTML/PDF
│   │   └── metrics.go                  # Calcul métriques
│   ├── config/                         # Configuration
│   │   ├── types.go                    # Types configuration
│   │   ├── loader.go                   # Chargement config
│   │   ├── validator.go                # Validation config
│   │   └── profiles.go                 # Profils d'attaque
│   ├── ui/                             # Interface utilisateur
│   │   ├── colors.go                   # Couleurs terminal
│   │   ├── progress.go                 # Barres progression
│   │   ├── tables.go                   # Tableaux formatés
│   │   └── interactive.go              # Mode interactif
│   └── utils/                          # Utilitaires
│       ├── http.go                     # Clients HTTP
│       ├── crypto.go                   # Utilitaires crypto
│       ├── network.go                  # Utilitaires réseau
│       └── strings.go                  # Manipulation strings
├── configs/
│   ├── default.yaml                    # Configuration par défaut
│   ├── attack-profiles.yaml            # Profils d'attaque
│   └── targets/
│       ├── webapp-generic.yaml         # Profil app web générique
│       ├── api-rest.yaml               # Profil API REST
│       └── messaging-system.yaml       # Profil système messaging
├── scripts/
│   ├── build.ps1                       # Build automation Windows
│   └── demo.ps1                        # Démo automatisée
├── examples/
│   ├── basic-scan.yaml                 # Exemple scan basique
│   ├── advanced-pentest.yaml           # Exemple pentest avancé
│   └── custom-payload.json             # Exemple payload personnalisé
├── docs/
│   ├── README.md                       # Documentation principale
│   ├── ARCHITECTURE.md                 # Documentation architecture
│   ├── ATTACKS.md                      # Documentation modules attaque
│   └── API.md                          # Documentation API
└── tests/
    ├── integration/                    # Tests intégration
    ├── unit/                           # Tests unitaires
    └── fixtures/                       # Données de test

arborescence du projet exacte et à jour:

.
│   cyberraven.yaml
│   go.mod
│   go.sum
│   idea.md
│   main.go
│   session_state_accumulator_design.md
│   SNIFFER.md
│
├───backups
├───cmd
│   ├───attack
│   │       attack.go
│   │       config.go
│   │       display.go
│   │       orchestrator.go
│   │       types.go
│   │
│   ├───report
│   │       report.go
│   │
│   └───sniff
│           sniff.go
│
├───pkg
│   ├───attacks
│   │   ├───api
│   │   │       analyzer.go
│   │   │       detector.go
│   │   │       enumeration.go
│   │   │       executor.go
│   │   │       print.go
│   │   │       result_collector.go
│   │   │       strategy.go
│   │   │       types.go
│   │   │
│   │   ├───dos
│   │   │       flooding.go
│   │   │
│   │   ├───hmac
│   │   │       replay.go
│   │   │
│   │   ├───injection
│   │   │       sql.go
│   │   │
│   │   ├───jwt
│   │   │       fuzzer.go
│   │   │
│   │   └───tls
│   │           certificate.go
│   │           cipher.go
│   │           downgrade.go
│   │           tls.go
│   │           types.go
│   │
│   ├───config
│   │       types.go
│   │
│   ├───reporting
│   │       exporters.go
│   │       generator.go
│   │
│   ├───sniffer
│   │       analyzer.go
│   │       configurator.go
│   │       detector.go
│   │       engine.go
│   │       parser.go
│   │       types.go
│   │
│   └───utils
│           http.go
│
├───reports
└───results

