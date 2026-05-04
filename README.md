# Sherlock

> **AI-Powered Security Audit Agent for Code, Network & OS**

Sherlock est un agent CLI de cybersécurité qui audite vos systèmes (code, réseau, OS) et propose des corrections automatiques via l'IA.

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🚀 Fonctionnalités

- **🔍 Scan multi-cibles** : Code, réseau, OS — séparément ou ensemble
- **🧠 Analyse IA** : LLM intégré pour analyser les vulnérabilités et suggérer des correctifs
- **🔧 Auto-fix** : Application automatique des corrections avec backup/rollback
- **📊 Rapports** : Export Markdown, JSON — lisibles et exploitables
- **🗄️ VulnDB** : Base de vulnérabilités locale (SQLite) avec mise à jour
- **⚡ Performant** : Binaire unique en Go, cross-platform (Windows/Linux/macOS)

---

## 📦 Installation

### Depuis les releases (recommandé)

```bash
# Télécharger la dernière release
wget https://github.com/noah/sherlock/releases/latest/download/sherlock-linux-amd64
chmod +x sherlock-linux-amd64
mv sherlock-linux-amd64 /usr/local/bin/sherlock
```

### Depuis le source

```bash
git clone https://github.com/noah/sherlock.git
cd sherlock
go build -o sherlock .
```

### Configuration

Copiez et adaptez le fichier de configuration :

```bash
cp config.yaml config.local.yaml
```

```yaml
# config.local.yaml
llm:
  provider: ollama
  base_url: http://localhost:11434/v1
  api_key: ""
  model: llama3

scanner:
  network:
    timeout_ms: 2000
    concurrency: 100
    default_ports: "1-1000"
  code:
    secrets_patterns:
      - "password"
      - "secret"
      - "api_key"
      - "token"
      - "private_key"
    ignore_paths:
      - ".git"
      - "node_modules"
      - "vendor"
      - "dist"
      - "build"

reporter:
  default_format: markdown
  output_dir: "./reports"

vulndb:
  local_db_path: "./sherlock.db"
  auto_update: true
```

---

## 🛠️ Utilisation

### Scan complet

```bash
# Scan tout (code + réseau + OS)
sherlock scan --all --config config.local.yaml

# Avec analyse LLM
sherlock scan --all --llm

# Avec correction automatique (dry-run d'abord !)
sherlock scan --all --auto-fix --dry-run
sherlock scan --all --auto-fix
```

### Scan spécifique

```bash
# Code uniquement
sherlock scan --code ./mon-projet --llm

# Réseau
sherlock scan --network --ports 1-1000,8080,9000

# OS et hardening
sherlock scan --os --hardening
```

### Base de vulnérabilités

```bash
# Mettre à jour la base
sherlock vulndb update

# Rechercher une CVE
sherlock vulndb search CVE-2026-1234

# Statistiques
sherlock vulndb stats
```

### Rapports

```bash
# Générer un rapport
sherlock report generate --format markdown --output rapport.md

# JSON (pour CI/CD)
sherlock report generate --format json --output rapport.json
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│                  CLI (Cobra)                  │
│  sherlock scan [--code|--network|--os|--all] │
│  sherlock vulndb update                      │
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
│            VulnDB (SQLite)                    │
│  - Base de vulnérabilités locale             │
│  - Mise à jour automatique                   │
│  - Recherche par CVE, package, pattern       │
└──────────────────────────────────────────────┘
```

### Structure du projet

```
sherlock/
├── cmd/                    # Entrypoints CLI (Cobra)
│   ├── root.go            
│   ├── scan.go            
│   ├── vulndb.go          
│   └── report.go          
├── internal/
│   ├── scanner/           # Moteurs de scan
│   │   ├── code/          # Analyse de code (secrets, deps, patterns)
│   │   ├── network/       # Scan réseau (ports, services, certs)
│   │   └── os/            # Scan OS (perms, services, updates)
│   ├── analyzer/          # Analyse LLM
│   ├── vulndb/            # Base de vulnérabilités SQLite
│   ├── fixer/             # Application des correctifs + backup
│   └── reporter/          # Génération de rapports
├── pkg/sherlock/          # API publique (config)
├── main.go
├── go.mod
└── config.yaml            # Config par défaut
```

---

## 🔒 Sécurité

- **Backup automatique** : chaque fix crée une sauvegarde avant modification
- **Rollback** : `sherlock fix rollback <id>` pour annuler un changement
- **Dry-run** : `--dry-run` pour visualiser les changements avant application
- **LLM optionnel** : `--llm` pour l'analyse IA, sinon analyse heuristique pure

---

## 📋 Roadmap

- [ ] Mode watch daemon (scan périodique)
- [ ] Plugins scanner (communauté)
- [ ] Dashboard web
- [ ] Intégration CI/CD (GitHub Actions, GitLab CI)
- [ ] Agent OpenClaw natif

---

## 🤝 Contribution

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines.

---

## 📄 License

[MIT](LICENSE) © Noah

---

> _"Le jeu, Watson, c'est afoot !"_ — 🕵️‍♂️
