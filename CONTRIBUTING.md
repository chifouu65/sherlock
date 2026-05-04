# Contributing to Sherlock

Merci de l'intérêt pour Sherlock ! 🕵️‍♂️

## 🚀 Comment contribuer

### Signaler un bug

1. Vérifiez qu'il n'existe pas déjà dans les [Issues](https://github.com/noah/sherlock/issues)
2. Ouvrez une issue avec :
   - Version de Sherlock (`sherlock --version`)
   - OS et architecture
   - Commande exécutée
   - Output / logs d'erreur
   - Comportement attendu vs réel

### Proposer une fonctionnalité

1. Ouvrez une issue avec le label `enhancement`
2. Décrivez le use case
3. Si possible, proposez une implémentation

### Pull Requests

1. Forkez le repo
2. Créez une branche (`git checkout -b feature/amazing-feature`)
3. Commitez (`git commit -m 'feat: add amazing feature'`)
4. Pushez (`git push origin feature/amazing-feature`)
5. Ouvrez une PR

### Style de code

- Go fmt obligatoire (`go fmt ./...`)
- Tests pour les nouvelles fonctionnalités
- Pas de dépendances inutiles
- Documentez les fonctions exportées

### Tests

```bash
go test ./...
go vet ./...
```

### Commit messages

Format : `type(scope): description`

Types : `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Exemple : `feat(scanner): add support for Python requirements.txt`

---

## 📋 Checklist PR

- [ ] Code formatté (`go fmt`)
- [ ] Tests passent (`go test ./...`)
- [ ] Pas de régression
- [ ] README mis à jour si nécessaire
- [ ] CHANGELOG mis à jour

Merci ! 🎉
