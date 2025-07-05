# Session State Accumulator - Design Document

## 🎯 Objectif

Créer un accumulateur d'état de session qui :

- Collecte les découvertes pendant l'exécution des modules
- Synthétise et teste les combinaisons exploitables en fin de session
- Enrichit les tests avec le contexte accumulé

## 🏗️ Architecture Proposée

### Structure de l'État de Session

```go
type SessionState struct {
    mu          sync.RWMutex
    discoveries map[string][]Discovery
    startTime   time.Time
    sessionID   string
}

type Discovery struct {
    Type      string      // "endpoint", "jwt_token", "hmac_signature", "api_key", etc.
    Value     interface{} // Valeur découverte
    Context   string      // Contexte de découverte (module, endpoint, etc.)
    Timestamp time.Time   // Moment de la découverte
    Metadata  map[string]interface{} // Données supplémentaires
}
```

### Interface Publique

```go
// Ajouter une découverte
state.AddDiscovery("jwt_token", token, "/auth/login", metadata)
state.AddDiscovery("protected_endpoint", "/admin/users", "api_module", nil)
state.AddDiscovery("hmac_header", "X-Signature", "/api/data", headerData)

// Récupérer des découvertes
tokens := state.GetDiscoveries("jwt_token")
endpoints := state.GetDiscoveries("protected_endpoint")

// Tests de synthèse
state.RunCombinedTests(ctx, httpClient)
```

## 🔬 Types de Découvertes Ciblées

### Authentification

- **JWT Tokens** - Découverts dans réponses, headers, cookies
- **API Keys** - Trouvés dans headers, query params, réponses
- **HMAC Signatures** - Headers de signature détectés
- **Session Cookies** - Cookies d'authentification identifiés

### Endpoints & Ressources

- **Protected Endpoints** - Endpoints retournant 401/403
- **Resource Patterns** - Patterns REST détectés (`/users/{id}`, `/orders/{uuid}`)
- **File Endpoints** - Endpoints de téléchargement/upload
- **Admin Endpoints** - Zones d'administration découvertes

### Données Techniques

- **Error Patterns** - Messages d'erreur révélateurs
- **Technology Stack** - Frameworks, versions détectés
- **Security Headers** - Headers de sécurité manquants/présents
- **Rate Limiting** - Patterns de limitation détectés

## 🎯 Tests de Synthèse en Fin de Session

### Scénarios de Tests Combinés

1. **Token + Protected Endpoints**

   ```go
   for each token in discoveries["jwt_token"] {
       for each endpoint in discoveries["protected_endpoint"] {
           testTokenAccess(token, endpoint)
       }
   }
   ```

2. **HMAC + Resource Patterns**

   ```go
   if hasHMACHeaders() && hasResourcePatterns() {
       testHMACBypass(hmacHeaders, resourcePatterns)
   }
   ```

3. **Admin Endpoints + All Auth Methods**

   ```go
   for each adminEndpoint in discoveries["admin_endpoint"] {
       testWithAllTokens(adminEndpoint, allDiscoveredTokens)
       testParameterBypass(adminEndpoint)
   }
   ```

4. **Cross-Module Vulnerability Testing**

   ```go
   // Test injection sur endpoints découverts avec tokens valides
   // Test IDOR avec tous les patterns de ressources
   // Test privilege escalation sur endpoints admin
   ```

## 🚀 Intégration dans l'Architecture Existante

### Modification des Modules

Chaque module devient "state-aware" :

```go
// Dans analyzer.go
func (ra *ResponseAnalyzer) AnalyzeResponse(path, method string, resp *utils.HTTPResponse, state *SessionState) {
    // Analyse normale...
    
    // Enrichissement de l'état
    if authToken := extractJWTFromResponse(resp); authToken != "" {
        state.AddDiscovery("jwt_token", authToken, path, map[string]interface{}{
            "source": "response_body",
            "method": method,
        })
    }
    
    if resp.StatusCode == 403 {
        state.AddDiscovery("protected_endpoint", path, "api_module", map[string]interface{}{
            "status_code": resp.StatusCode,
            "method": method,
        })
    }
}
```

### Orchestrateur Enrichi

```go
// Dans orchestrator.go
func (ao *AttackOrchestrator) ExecuteAttacks(ctx context.Context) (*AttackResult, error) {
    // Créer l'état de session
    sessionState := NewSessionState(sessionID)
    
    // Exécuter les modules normalement avec état partagé
    // ...
    
    // Tests de synthèse en fin de session
    combinedResults := sessionState.RunCombinedTests(ctx, ao.httpClient)
    result.CombinedFindings = combinedResults
    
    return result, nil
}
```

## 📊 Nouvelles Capacités de Détection

### Vulnérabilités Cross-Module

- **Token Reuse** - Même token utilisable sur plusieurs services
- **Privilege Context** - Token user qui accède aux endpoints admin
- **HMAC Chain Attacks** - Signatures valides réutilisées ailleurs
- **Session Fixation** - Sessions découvertes exploitables

### Analyses de Patterns

- **Resource Enumeration** - Pattern `/users/1` → tester `/users/2`, `/users/admin`
- **Parameter Discovery** - Paramètres découverts sur un endpoint testés sur d'autres
- **Technology Correlation** - Framework détecté → vulnérabilités spécifiques

## 🔧 Implémentation Recommandée

### Phase 1 : Infrastructure de Base

- Créer `SessionState` et `Discovery` structs
- Intégrer dans l'orchestrateur
- Modifier le module API pour alimenter l'état

### Phase 2 : Enrichissement des Modules

- JWT module → découverte de tokens
- HMAC module → découverte de signatures
- Injection module → découverte de paramètres vulnérables

### Phase 3 : Tests de Synthèse

- Implémentation des scénarios combinés
- Intégration dans les rapports
- Métriques de valeur ajoutée

## 🎯 Avantages Attendus

- **Détection améliorée** - Vulnérabilités nécessitant plusieurs modules
- **Contexte enrichi** - Tests plus intelligents avec données accumulées
- **ROI immédiat** - Découvertes supplémentaires sans complexité excessive
- **Évolutivité** - Base pour futures améliorations d'intelligence

## 📝 Notes d'Implémentation

- **Thread Safety** - État partagé entre goroutines
- **Memory Management** - Nettoyer l'état en fin de session
- **Performance** - Éviter la sur-accumulation de données
- **Debugging** - Logs clairs des découvertes et synthèses

------

*Document créé pour implémentation future - Architecture CyberRaven Session State*