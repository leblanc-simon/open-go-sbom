# Leçons et pièges connus

À lire avant chaque lot ; à compléter à la fin de chaque lot avec les erreurs commises et
les pièges découverts, pour ne pas les reproduire. Une entrée = le constat, puis la règle.

## Environnement et outillage

- **Chaîne Go** : `go.mod` fixe `toolchain go1.26.10`. Une machine avec un Go plus ancien
  télécharge la bonne chaîne d'elle-même (`GOTOOLCHAIN=auto`) ; ne pas modifier la ligne
  `toolchain` pour s'adapter à la machine.
- **PostgreSQL local** : sans Docker, un PostgreSQL 16 natif convient ; le mot de passe du
  rôle `postgres` doit valoir `postgres` pour le DSN par défaut du Makefile.
- **Proxy réseau** : un téléchargement de module peut échouer ponctuellement
  (`ws_closed_mid_exchange`) ; relancer la commande, ne pas changer de version pour autant.

## Anchore

- `syft.GetSource(ctx, "dir:/chemin", nil)` interprète le préfixe comme un registre
  d'images : passer le chemin nu et `syft.DefaultGetSourceConfig().WithSources("dir")`.
- Syft échoue sur les bases RPM récentes sans pilote SQLite enregistré : importer
  `_ "modernc.org/sqlite"` dans tout binaire qui catalogue (agents, tests).
- La base Grype v6 fait environ 3,2 Gio décompressée et met plusieurs minutes à
  télécharger : jamais dans les tests unitaires ; tests réels sous l'étiquette `grypedb`,
  avec un répertoire de base fourni par variable d'environnement.
- Les identifiants de vulnérabilité de Grype sont ceux de la source (GHSA pour Java…) ;
  le rattachement aux CVE passe par les alias ou `NormalizeByCVE`.

## Git et intégration

- Ne pas réécrire une branche déjà poussée (force-push refusé) : préférer un commit
  correctif, ou une fusion « squash » de la PR.
- Commits signés « Simon Leblanc <contact@leblanc-simon.eu> », avec la ligne
  `Co-Authored-By` de Claude.
