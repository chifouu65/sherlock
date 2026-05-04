# Sherlock - Security Audit Agent CLI

> Un agent de cybersécurité CLI dopé à l'IA, déployable sur Windows/Linux/Mac.

## Concept

Sherlock est un agent CLI qu'on lance pour auditer un système : code, réseau, OS, dépendances, config. Il utilise un LLM (cloud de préférence) pour analyser les résultats, proposer des fixes, et les appliquer automatiquement si on lui dit `--auto-fix`.

## Architecture

```
┌─────────────────────────────────────────────┐
│                  CLI (Cobra)                  │
│  sherlock scan [--code|--network|--os|--all] │
│  sherlock vulndb update                      │
│  sherlock vulndb search <cve>                │
│  sherlock report generate                    │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│              Scanner Engine                  │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Code    │ │ Network  │ │ OS       │      │
│  │ Scanner │ │ Scanner  │ │ Scanner  │      │
│  └────┬────┘ └────┬─────┘ └────┬─────┘      │
│       │           │            │             │
│  ┌────▼───────────▼────────────▼─────┐       │
│  │      Analyse Engine (LLM)         │       │
│  │  - Analyse des vulnérabilités     │       │
│  │  - Suggère des fixes              │       │
│  │  - Génère des patches             │       │
│  └────────────────┬──────────────────┘       │
└───────────────────┬──────────────────────────┘
                    │
┌───────────────────▼──────────────────────────┐
│            VulnDB (Cloud/SQLite)              │
│  - Base de vulnérabilités communautaire      │
│  - Mise à jour automatique par les agents    │
│  - Recherche par CVE, package, pattern       │
└──────────────────────────────────────────────┘
```

## Pourquoi Go ?

- **Binaire unique** : un seul executable, pas de dépendances runtime
- **Cross-platform** : Windows/Linux/Mac en un `go build`
- **Performant** : les scans réseau et fichiers sont rapides
- **Rich ecosystem** : Cobra (CLI), go-ole (Windows), ssh (remote)
- **Idéal pour les agents** : déploiement facile, pas de VM requise

## Structure du projet

```
sherlock/
├── cmd/                    # Entrypoints Cobra
│   ├── root.go            # Commande parente
│   ├── scan.go            # sherlock scan
│   ├── vulndb.go          # sherlock vulndb
│   └── report.go          # sherlock report
├── internal/
│   ├── scanner/           # Moteurs de scan
│   │   ├── code/          # Analyse de code
│   │   ├── network/       # Scan réseau
│   │   └── os/            # Scan OS/config
│   ├── analyzer/          # Analyse LLM
│   │   ├── llm.go         # Interface LLM (OpenAI/Ollama compat)
│   │   └── prompts.go     # Templates de prompts
│   ├── vulndb/            # Base de vulnérabilités
│   │   ├── db.go          # Interface DB (SQLite locale + cloud)
│   │   ├── cloud.go       # Sync cloud
│   │   └── models.go      # Structs CVE/Vuln
│   ├── fixer/             # Application des correctifs
│   │   ├── auto.go        # Mode auto-fix
│   │   └── backup.go      # Rollback/snapshots
│   └── reporter/          # Génération de rapports
│       ├── markdown.go
│       └── json.go
├── pkg/
│   └── sherlock/          # API publique si lib réutilisable
├── go.mod
├── main.go
└── config.yaml            # Config utilisateur (LLM endpoint, API keys...)
```

## Commandes CLI (premier jet)

```bash
# Scan complet
sherlock scan --all --auto-fix

# Scan spécifique
sherlock scan --code ./mon-projet --auto-fix
sherlock scan --network --ports 1-1000
sherlock scan --os --hardening

# Base de vulnérabilités
sherlock vulndb update
sherlock vulndb search CVE-2026-1234
sherlock vulndb stats

# Rapports
sherlock report generate --format markdown --output rapport.md

# Mode watch (scan périodique)
sherlock watch --interval 24h --auto-fix
```

## Scanners prévus

### Code Scanner
- Dépendances obsolètes (go.mod, package.json, requirements.txt...)
- Secrets exposés (API keys, tokens hardcodés)
- Patterns de vulnérabilités (SQLi, XSS, command injection)
- Fichiers de config sensibles (.env, credentials)

### Network Scanner
- Ports ouverts non attendus
- Services exposés avec versions
- Certificats SSL/TLS expirés
- Tests de base (pas un nmap, mais un check rapide)

### OS Scanner
- Permissions fichier anormales
- Services non sécurisés
- Updates manquantes
- User/group configs douteuses
- Firewall status

## VulnDB Cloud

Base de données communautaire :
- Chaque agent peut soumettre une vulnérabilité trouvée
- Stockée avec : hash du fichier, pattern, CVE associé, fix proposé
- Les autres agents peuvent la consulter avant de lancer un scan
- Système de confiance (vérification croisée)
- API REST simple (PocketBase / Supabase / fait-maison Go)

## LLM Integration

Le LLM est utilisé pour :
1. Analyser les résultats bruts des scanners
2. Suggérer des priorités (critique, high, medium, low)
3. Proposer des correctifs (commande shell, patch, config change)
4. Générer les rapports en langage naturel

Support OpenAI-compatible (Ollama, OpenAI, Anthropic via proxy).

## Auto-Fix

```bash
sherlock scan --code . --auto-fix --dry-run   # Montre ce qui sera fait
sherlock scan --code . --auto-fix              # Applique les fixes
```

L'auto-fix :
- Backup automatique avant chaque modification
- Rollback possible (`sherlock fix rollback <id>`)
- Mode `--dry-run` pour review avant apply
- Chaque fix est signé et horodaté

## Idées futures

- [ ] Mode watch daemon (scan périodique, notifie si régression)
- [ ] Plugins scanner (communauté écrit ses scanners)
- [ ] Dashboard web pour les rapports
- [ ] Intégration CI/CD (GitHub Action, GitLab CI)
- [ ] Agent OpenClaw qui pilote Sherlock
