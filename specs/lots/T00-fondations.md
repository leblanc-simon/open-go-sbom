# T00 — Fondations du dépôt et outillage qualité

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | — | Terminé |

## Objectif

Rendre le dépôt prêt à recevoir du code de qualité : module, arborescence, outillage,
intégration continue, décisions initiales écrites et dépendances validées par l'utilisateur.
Aucun code métier.

## Périmètre

**Inclus**

- `go.mod` : module `leblanc.io/open-go-sbom`, `go 1.26`, directives `tool`
  pour `staticcheck`, `govulncheck`, `oapi-codegen` (et `sqlc` si retenu).
- Arborescence de [`architecture.md` § 3](../architecture.md) avec un `doc.go` par paquet
  prévu au lot 1, et les trois `cmd/*/main.go` réduits à `--version`.
- `Makefile` : `build`, `run`, `fmt`, `fmt-check`, `vet`, `lint` (staticcheck), `vuln`
  (govulncheck), `generate`, `generate-check`, `test`, `test-race`, `test-integration`,
  `ci`, `clean`. Version injectée par `-ldflags "-X 'main.version=…'"`.
- `deploy/compose.yaml` : PostgreSQL de développement et base de test jetable.
- `.github/workflows/ci.yml` : l'ordre « ce qui échoue le plus vite d'abord », service
  PostgreSQL pour les tests d'intégration, construction des trois binaires.
- `internal/archtest` : règles du § 4 de l'architecture (imports directs), actives dès
  maintenant.
- `docs/adr/` : gabarit et ADR initiaux (voir Conception).
- `docs/security/threat-model.md` : première version (actifs, acteurs, frontières de
  confiance, menaces principales par composant).
- `LICENSE` (WTFPL), `README.md` court, `.gitignore`, `.editorconfig`.
- Explorations techniques jetables (voir Conception), dont les conclusions vont dans les ADR.

**Exclu** : tout code métier, toute migration, toute page web.

## Conception

ADR à écrire et faire valider :

1. Format des ADR et règle « une décision structurante = un ADR ».
2. PostgreSQL seul, pilote `pgx/v5/stdlib` derrière `database/sql`.
3. Routeur chi.
4. Requêtes SQL : `sqlc` en directive `tool` ou requêtes écrites à la main. Critères :
   sûreté de typage, lisibilité des requêtes dynamiques (recherche), outillage.
5. File de traitements maison sur PostgreSQL plutôt qu'une bibliothèque (River…).
6. API conçue d'abord en OpenAPI, code généré par oapi-codegen.
7. Isolement des bibliothèques d'Anchore derrière des adaptateurs.
8. Interface sans chaîne de construction front (CSS natif imbriqué, modules ES natifs).

Explorations à mener, chacune dans un programme jetable hors `main`, résultat consigné :

- Syft décode-t-il CycloneDX 1.7 à la version épinglée ? Sinon, quelle conséquence ?
- API de Grype utilisable en bibliothèque à la version épinglée : chargement d'une base
  depuis un répertoire, correspondance d'un SBOM décodé par Syft, lecture d'EPSS, KEV et du
  score de risque, rattachement de chaque résultat à son purl.
- Le client Docker est-il déjà dans le graphe de dépendances de stereoscope ?
- Taille d'un binaire `ogsbom-host-agent` qui importe Syft, en `CGO_ENABLED=0`, amd64 et arm64.
- sqlc en mode `database/sql` avec le pilote pgx : comment sont passés les tableaux
  d'`unnest` (sqlc génère `pq.Array`, donc une dépendance à lib/pq) ?
- oapi-codegen à la version retenue gère-t-il OpenAPI 3.1 ? Sinon, l'API est écrite en 3.0.

## Livrables

Les fichiers listés ci-dessus, les ADR 0001 à 0008, le modèle de menace, la liste des
dépendances validées (avec version) dans le Journal.

## Critères d'acceptation

- [x] `make ci` passe sur le squelette, en local et en CI.
- [x] Un import interdit volontaire (par exemple Grype dans `web`) fait échouer `archtest`.
- [x] `ogsbom-server --version`, `ogsbom-host-agent --version`, `ogsbom-repo-agent --version`
      affichent la version injectée.
- [x] Les dépendances du § 5 « À valider en T00 » sont validées ou remplacées par
      l'utilisateur, et le tableau de l'architecture est mis à jour.
- [x] Les six explorations ont une conclusion écrite.
- [x] `CLAUDE.md` reflète les commandes réelles du `Makefile`.

## Tests attendus

Tests de `archtest` (cas conforme et cas fautif construits dans `testdata`).

## Décisions

Prises le 31 octobre 2026 :

- Chemin du module : `leblanc.io/open-go-sbom`. Le domaine doit servir la balise
  `go-import` pour que d'autres puissent faire `go get` ; sans effet sur le développement.
- Versions minimales : Go 1.26, PostgreSQL 16.
- Dépendances du § 5 de l'architecture validées.
- sqlc ou SQL écrit à la main : tranché par l'exploration de ce lot (sqlc si les tableaux
  passent sans lib/pq avec le pilote pgx, sinon SQL écrit à la main), consigné dans l'ADR 4.
- Intégration : une PR par lot, fusionnée dès que la CI est verte et les critères cochés.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T00-fondations`.

### Livré

- Module `leblanc.io/open-go-sbom`, `go 1.26`, `toolchain go1.26.10` (dernière corrective
  de la 1.26 : govulncheck juge la bibliothèque standard de la chaîne utilisée).
- 30 paquets du lot 1 avec leur `doc.go` ; paquets des lots 2 et 3 non créés.
- `Makefile` (cibles de la fiche + `help`), `deploy/compose.yaml` et `deploy/initdb/`,
  `.github/workflows/ci.yml`, `internal/archtest`, ADR 0001 à 0008, modèle de menace,
  `LICENSE`, `README.md`, `.gitignore`, `.editorconfig`.

### Explorations (programmes jetables, hors dépôt)

| Question | Conclusion | ADR |
| --- | --- | --- |
| Syft et CycloneDX 1.7 | Syft v1.55.0 encode et décode CycloneDX JSON 1.7 (version par défaut), ainsi que SPDX 2.3 et Syft JSON, sans perte de distribution. | 0007 |
| Grype en bibliothèque | Grype v0.121.0 : `LoadVulnerabilityDB` sur un répertoire, `pkg.ProvideFromReader` sur le SBOM brut, `VulnerabilityMatcher` ; même résultat pour les trois formats ; purl d'origine, EPSS, KEV et `RiskScore()` disponibles par correspondance. Base v6 : 3,2 Gio décompressée. | 0007 |
| Client Docker | Déjà dans le graphe de stereoscope : `github.com/moby/moby/client` v0.6.0 et le client containerd v2. | 0007 |
| Taille de l'agent | Binaire important Syft, `CGO_ENABLED=0 -trimpath -s -w` : 82 Mo amd64, 77 Mo arm64. | 0007 |
| sqlc et tableaux | En `database/sql`, sqlc v1.31.1 génère `pq.Array` (dépendance `lib/pq`) : SQL écrit à la main. | 0004 |
| oapi-codegen et 3.1 | v2.8.1 gère OpenAPI 3.1 (nullabilité par tableau de types) : l'API est écrite en 3.1.0. | 0006 |

### Décisions et écarts

- Constat imprévu : Syft exige un pilote SQLite enregistré pour les bases RPM récentes ;
  `modernc.org/sqlite` (pur Go, déjà dans le graphe d'open-go-base) est ajouté au § 5
  (décision prise en autonomie, l'utilisateur ayant délégué les choix du lot 1).
- `archtest` applique les règles aux imports de test aussi ; il ne vérifie pas
  « `cmd` sans logique » ni « pas de variable globale mutable » (relecture), ce que le
  § 4 dit désormais.
- Les tests d'intégration utilisent `OGSBOM_TEST_DATABASE_DSN`, connexion
  d'administration où chaque test créera sa base et ses rôles jetables (helper en T01).
- `generate-check` ne regarde que les répertoires générés (`internal/api/gen`,
  `internal/agentclient/gen`), pour ne pas échouer sur un arbre de travail modifié.
- Critère « quatre explorations » corrigé en « six » : la fiche en listait six.

### ADR créés

0001 à 0008.
