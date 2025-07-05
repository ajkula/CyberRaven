# 🔍 CyberRaven Sniffer Documentation

## Vue d'ensemble

Le **CyberRaven Sniffer** implémente l'approche révolutionnaire **Sniffer-First** : découvrir automatiquement les cibles d'attaque en analysant le trafic réseau réel, puis configurer automatiquement les modules d'attaque avec des données pertinentes.

### Concept Sniffer-First

```
1. 📡 Capture du trafic réseau
2. 🔍 Analyse intelligente (tokens, endpoints, technologies)
3. ⚙️  Mise à jour automatique de cyberraven.yaml
4. 🎯 Recommandations d'attaque prioritaires
5. ⚔️  Attaques ciblées avec vraies données
```

---

## Installation et Prérequis

### Permissions Administrateur

Le sniffer nécessite des **privilèges élevés** pour capturer le trafic réseau :

```bash
# Linux/macOS
sudo ./cyberraven sniff [options]

# Windows (PowerShell en tant qu'administrateur)
.\cyberraven.exe sniff [options]
```

### Dépendances Système

**Linux :**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

**macOS :**
```bash
# Avec Homebrew
brew install libpcap
```

**Windows :**
- Installer [WinPcap](https://www.winpcap.org/) ou [Npcap](https://nmap.org/npcap/)

---

## Utilisation

### Syntaxe de Base

```bash
cyberraven sniff [FLAGS] [OPTIONS]
```

### Flags Disponibles

| Flag | Abrév. | Description | Défaut |
|------|--------|-------------|---------|
| `--interface` | `-i` | Interface réseau à monitorer | auto-detect |
| `--duration` | `-d` | Durée de capture | 5m |
| `--filter` | `-f` | Filtre BPF personnalisé | port 80,443,DNS |
| `--output` | `-o` | Fichier de sortie JSON | aucun |
| `--verbose` | `-v` | Mode verbeux | false |
| `--no-color` | | Désactiver les couleurs | false |
| `--config` | `-c` | Fichier de configuration | cyberraven.yaml |

---

## Exemples d'Utilisation

### 1. Scan Basique (5 minutes)

```bash
sudo cyberraven sniff
```

**Résultat :**
- Capture 5 minutes de trafic sur l'interface par défaut
- Analyse automatique des tokens, endpoints, technologies
- Mise à jour de `cyberraven.yaml`

### 2. Scan avec Interface Spécifique

```bash
sudo cyberraven sniff --interface eth0 --duration 10m
```

**Utilisation :**
- Interface réseau spécifique (eth0, wlan0, en0, etc.)
- Durée personnalisée (10 minutes)

### 3. Scan avec Filtre Personnalisé

```bash
sudo cyberraven sniff --filter "tcp port 8080 or tcp port 3000" --duration 2m
```

**Filtre BPF :**
- Capture uniquement le trafic sur les ports 8080 et 3000
- Utile pour des applications non-standard

### 4. Scan avec Sauvegarde

```bash
sudo cyberraven sniff --duration 30s --output ./captures/scan_$(date +%Y%m%d_%H%M%S).json --verbose
```

**Fonctionnalités :**
- Sauvegarde des résultats en JSON
- Mode verbeux pour détails complets
- Horodatage automatique

### 5. Scan Rapide pour Tests

```bash
sudo cyberraven sniff --duration 30s --verbose
```

**Usage :**
- Test rapide pendant 30 secondes
- Parfait pour validation/debugging

---

## Filtres BPF Avancés

### Filtres Prédéfinis

```bash
# Trafic web seulement
--filter "tcp port 80 or tcp port 443"

# Applications spécifiques
--filter "tcp port 8080 or tcp port 3000 or tcp port 8000"

# Trafic complet (attention : volume élevé)
--filter "tcp"

# Exclure le trafic SSH
--filter "tcp and not port 22"
```

### Filtres par Host

```bash
# Cibler un serveur spécifique
--filter "host 192.168.1.100"

# Cibler un sous-réseau
--filter "net 192.168.1.0/24"

# Exclure le trafic local
--filter "not host 127.0.0.1"
```

### Filtres Complexes

```bash
# Applications web sur réseau local
--filter "(tcp port 80 or tcp port 443 or tcp port 8080) and net 192.168.0.0/16"

# Debugging d'API spécifique
--filter "tcp port 3000 and host api.example.com"
```

---

## Interprétation des Résultats

### Affichage Terminal

```
🔍 NETWORK TRAFFIC ANALYSIS SESSION

Interface: eth0
Duration: 5m0s
Protocols: [HTTP, HTTPS, DNS]
Real-time Analysis: true

📊 TRAFFIC ANALYSIS RESULTS

Session Duration: 5m12s
Packets Captured: 15,247
Bytes Analyzed: 45.2 MB
HTTP Conversations: 342
HTTPS Conversations: 158

Endpoints Discovered: 23
Tokens Found: 5
Signatures Detected: 2
Sensitive Data Leaks: 0

🔧 TECHNOLOGY PROFILE

Web Server: nginx/1.18.0
Framework: express
Language: javascript
Database: mongodb

🎯 ATTACK RECOMMENDATIONS

[HIGH] JWT Module (Confidence: 85.2%)
  Reason: JWT tokens detected in Authorization headers
  Targets: 5 discovered

[MEDIUM] API Module (Confidence: 73.8%)
  Reason: REST API endpoints discovered
  Targets: 23 discovered

✅ SNIFFING SESSION COMPLETE

Configuration file updated with discovered targets and tokens
Run 'cyberraven attack' to start penetration testing
```

### Fichier de Sortie JSON

```json
{
  "session_id": "sniff_1673528400",
  "start_time": "2024-01-12T10:00:00Z",
  "end_time": "2024-01-12T10:05:00Z",
  "duration": "5m0s",
  "packets_captured": 15247,
  "bytes_captured": 47447040,
  "http_conversations": 342,
  "https_conversations": 158,
  "discovered_endpoints": [
    {
      "method": "GET",
      "path": "/api/users",
      "request_count": 45,
      "auth_required": true,
      "security_level": "medium"
    }
  ],
  "discovered_tokens": [
    {
      "type": "jwt",
      "location": "header",
      "location_key": "Authorization",
      "usage_count": 23,
      "is_valid": true
    }
  ],
  "technology_profile": {
    "web_server": "nginx",
    "framework": "express",
    "language": "javascript"
  },
  "attack_recommendations": [
    {
      "module": "jwt",
      "priority": "high",
      "confidence": 0.852,
      "description": "JWT tokens detected in Authorization headers"
    }
  ]
}
```

---

## Workflow Sniffer-First

### Étape 1 : Découverte

```bash
# Analyse du trafic pendant 5 minutes
sudo cyberraven sniff --duration 5m --verbose

# Vérifier les découvertes
cat cyberraven.yaml | grep -A5 "discovered"
```

### Étape 2 : Configuration Automatique

Le sniffer met automatiquement à jour `cyberraven.yaml` :

```yaml
# Exemples de mises à jour automatiques
target:
  base_url: "https://api.example.com"  # ✅ Détecté automatiquement
  headers:
    Authorization: "Bearer JWT_TOKEN_PLACEHOLDER"  # ✅ Token trouvé

attacks:
  api:
    common_endpoints:  # ✅ Endpoints découverts
      - "/api/users"
      - "/api/products"
      - "/admin/dashboard"
  
  jwt:
    enable: true  # ✅ Activé car tokens détectés
```

### Étape 3 : Attaques Ciblées

```bash
# Lancer les attaques avec configuration enrichie
cyberraven attack --verbose

# Ou modules spécifiques basés sur recommandations
cyberraven attack --modules jwt,api --verbose
```

---

## Dépannage

### Problèmes Courants

**❌ Permission denied**
```bash
# Solution : Utiliser sudo
sudo cyberraven sniff
```

**❌ No suitable interface found**
```bash
# Lister les interfaces disponibles
ip link show        # Linux
ifconfig -a         # macOS/BSD
ipconfig /all       # Windows

# Spécifier interface manuellement
sudo cyberraven sniff --interface eth0
```

**❌ No packets captured**
```bash
# Vérifier le filtre BPF
sudo cyberraven sniff --filter "tcp" --duration 30s

# Tester sans filtre
sudo cyberraven sniff --duration 30s --verbose
```

**❌ Capture timeout**
```bash
# Réduire la durée pour test
sudo cyberraven sniff --duration 10s

# Vérifier l'activité réseau
sudo tcpdump -i any -c 10
```

### Debugging

**Mode verbeux complet :**
```bash
sudo cyberraven sniff --duration 30s --verbose --no-color > debug.log 2>&1
```

**Test de connectivité :**
```bash
# Générer du trafic pendant le scan
curl -H "Authorization: Bearer test123" http://localhost:8080/api/test
```

**Validation des filtres :**
```bash
# Tester le filtre BPF avec tcpdump
sudo tcpdump -i eth0 "tcp port 80 or tcp port 443" -c 5
```

---

## Intégration dans un Workflow

### 1. Découverte Automatisée

```bash
#!/bin/bash
echo "🔍 Phase 1: Network Discovery"
sudo cyberraven sniff --duration 5m --output discovery_$(date +%Y%m%d).json

echo "⚔️ Phase 2: Targeted Attacks"  
cyberraven attack --verbose

echo "📊 Phase 3: Report Generation"
cyberraven report --input ./results --format html,json
```

### 2. Monitoring Continu

```bash
#!/bin/bash
# Monitoring en boucle avec sauvegarde
while true; do
    timestamp=$(date +%Y%m%d_%H%M%S)
    sudo cyberraven sniff --duration 10m --output "./monitoring/scan_$timestamp.json"
    sleep 300  # Pause de 5 minutes
done
```

### 3. Intégration CI/CD

```yaml
# .github/workflows/security-scan.yml
- name: Network Discovery
  run: |
    sudo cyberraven sniff --duration 2m --output discovery.json
    
- name: Security Testing
  run: |
    cyberraven attack --target ${{ env.TARGET_URL }} --output results/
    
- name: Generate Report
  run: |
    cyberraven report --input results/ --format html
```

---

## Optimisation et Performance

### Réglages de Performance

```bash
# Capture haute performance (attention à l'espace disque)
sudo cyberraven sniff --duration 1m --filter "tcp port 80"

# Capture légère (headers seulement)
sudo cyberraven sniff --duration 10m --filter "tcp[13:1] & 2 = 2"
```

### Limitation de la Capture

```bash
# Limiter la taille des paquets
sudo cyberraven sniff --duration 5m  # snap-length automatique

# Capture sélective par méthode HTTP
sudo cyberraven sniff --filter "tcp port 80 and (tcp[20:4] = 0x47455420 or tcp[20:4] = 0x504f5354)"
```

---

## Sécurité et Considérations Légales

### ⚠️ Avertissements Importants

1. **Permissions Légales :** N'utilisez le sniffer QUE sur vos propres systèmes ou avec autorisation écrite
2. **Données Sensibles :** Le sniffer masque automatiquement les tokens/passwords dans les logs
3. **Conformité :** Respectez les réglementations locales (RGPD, etc.)
4. **Environnement de Test :** Privilégiez les environnements de développement/test

### 🛡️ Bonnes Pratiques

```bash
# Sauvegarde sécurisée
sudo cyberraven sniff --output /secure/path/scan.json
chmod 600 /secure/path/scan.json

# Nettoyage automatique
find ./captures -name "*.json" -mtime +7 -delete
```

---

## Support et Contributions

### Signaler un Bug

1. Exécuter avec `--verbose`
2. Sauvegarder les logs complets
3. Fournir la version et l'OS
4. Inclure la commande exacte utilisée

### Améliorer la Documentation

Cette documentation est maintenue dans le projet CyberRaven. Les contributions sont les bienvenues !

---

**🎯 Le sniffer CyberRaven transforme vos tests de pénétration : découverte intelligente → attaques ciblées → résultats pertinents !**
