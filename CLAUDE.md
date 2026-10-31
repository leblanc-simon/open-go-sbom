# CLAUDE.md

Ce fichier guide Claude Code lorsqu'il travaille sur ce dépôt.

## Projet

**open-go-sbom** : plateforme open source de gestion de SBOM par projet (dépôt git ou
serveur). Deux agents produisent les SBOM (agent dépôt avec enrichissement IA, agent serveur
en Go sans IA) ; un serveur central les historise, les analyse chaque jour avec Grype, et
offre recherche transverse, triage et tableaux de bord. Multi-organisation, en Go, sur
[`leblanc.io/open-go-base`](../open-go-base) et PostgreSQL. Licence WTFPL.

## Documents de référence, dans cet ordre

1. [`docs/cahier-des-charges.md`](docs/cahier-des-charges.md) — le besoin et les décisions
   produit.
2. [`specs/architecture.md`](specs/architecture.md) — **fait autorité** sur l'architecture,
   les noms et les conventions.
3. [`specs/README.md`](specs/README.md) — les 27 lots techniques, leur ordre, leur statut,
   la façon de travailler et la définition de « terminé ».
4. [`specs/lecons.md`](specs/lecons.md) — erreurs déjà commises et pièges connus : à lire
   avant chaque lot, à compléter à la fin.
5. `specs/lots/Txx-*.md` — la fiche du lot en cours, et le Journal des lots dont il dépend.
6. [`docs/adr/`](docs/adr/) — décisions d'architecture.

## État actuel

T00 et T01 terminés : `ogsbom-server` démarre, migre, sert une page d'accueil traduite,
ses sondes et ses métriques. Prochains lots, en parallèle :
[T02 — File de traitements](specs/lots/T02-file-de-traitements.md) et
[T03 — Comptes et organisations](specs/lots/T03-comptes-organisations.md). Le socle
réutilisable (config, `db.InOrg`, `dbtest`, rendu, i18n, problèmes RFC 9457, pagination,
`webtest`) est décrit dans les `doc.go` et dans le Journal de T01.
T02 terminé : file de traitements `internal/jobs` (`Enqueue` dans la transaction de
l'appelant, `Runner`, `Scheduler`, horloge injectable), voir son `doc.go` et l'ADR 0011.
T03 terminé : comptes (`internal/account`), TOTP obligatoire, organisations
(`internal/org`), garde `/o/{slug}`, journal d'audit (`internal/audit`), fonctions
`crossorg` (ADR 0012, 0013), harnais d'isolement SQL et par route.
T04 terminé : projets (`internal/project`), agents et jetons (`internal/agent`, ADR 0014),
API des agents générée (`internal/api`, `internal/api/gen`, `internal/agentclient/gen`),
limitation par jeton (`ratelimit.WithKeyFunc` d'open-go-base).
T05 terminé : modèle SBOM, purl canoniques et empreinte (`internal/sbom`), schémas
embarqués (`sbom/schema`), adaptateur Syft (`sbom/syft`), inventaire
(`internal/inventory`), réception et job `ingest.decode` (`internal/ingest`, ADR 0015,
0016), écrans des instantanés ; jeux d'essai dans `testdata/sbom/`. Prochains lots, en
parallèle : [T06](specs/lots/T06-analyse-vulnerabilites.md),
[T07](specs/lots/T07-agent-serveur.md) et [T08](specs/lots/T08-agent-depot.md).
T08 terminé : forges (`internal/forge` : GitHub App, GitLab par compte de service,
webhooks vérifiés), agent dépôt (`internal/repoagent` : récepteur de webhooks,
rattrapage, file en mémoire, git sous environnement maîtrisé, Syft hors ligne, SBOM
déterministe), `ogsbom-repo-agent` et `deploy/ogsbom-repo-agent/` (ADR 0023).
T06 terminé : base Grype commune (`internal/vuln`, `internal/vuln/grype`, ADR 0017 :
archives en blocs dans PostgreSQL, cible, copie locale par instance, `/readyz` des
workers), analyse et constats (`internal/finding`, ADR 0018), téléchargements par
`internal/download`, écrans des constats, des vulnérabilités et des composants, jeu de
mesure `internal/benchdata` et `docs/benchmarks.md` (ADR 0019), autoanalyse des binaires
en CI (`make selfscan`).
T07 terminé : agent serveur `ogsbom-host-agent` (`internal/hostagent`, ADR 0020, 0021),
client commun des agents `internal/agentclient` (réessais, mTLS, envoi gzip, suivi d'une
ingestion : voir son `doc.go`, à adopter par l'agent dépôt), compte rendu d'inventaire et
demande de scan par le signal de vie, mTLS exigé sur l'API des agents avec
`tls.client_ca_file`, unités systemd et paquets deb et rpm (`make packages`).
T09 terminé : recherche transverse (`internal/search`, ADR 0024 : fonctions de recherche
par nom et empreinte dans `crossorg`, pagination par projet, export en flux), comparaison
de versions et plages vers (`internal/version`, `version/grypeversion`, ADR 0026), jetons
d'accès personnels (`internal/account`, format commun `internal/token`, ADR 0025), API
utilisateur `GET /api/v1/orgs/{org}/search` (`internal/api/gen/userapi`), écran
`/o/{slug}/search`, guide d'utilisation `docs/utilisation.md`, `make bench-search`.
T10 terminé : tableau de bord d'organisation et en-tête de la fiche projet
(`internal/dashboard`, statistiques quotidiennes réécrites toutes les heures, ADR 0027),
graphiques SVG serveur (`internal/render/chart.go`, `partials/charts.html`), agent muet
au-delà de 7 jours (`agent.Silent`), contrôle des SVG par `webtest`.
T11 en cours, partie 1 livrée : écrans d'administration d'instance (traitements en échec
`/admin/jobs`, version de la base chargée par chaque instance, import manuel d'une archive
installée par le job `vulndb.import`, purge des archives non cibles ; ADR 0028). Partie 2 :
revue de sécurité, audit RGAA, mesures, parc pilote, préversion.

## Règles de travail

- **La qualité prime sur la vitesse.** Pas de raccourci, pas de dette reportée.
- Un lot à la fois, sur une branche `lot/<id>-<sujet>` poussée sur GitHub ; PR vers `main`
  fusionnée dès que la CI est verte et les critères cochés (l'utilisateur relit a posteriori).
- Avant d'écrire du code : proposer un plan, et faire valider par l'utilisateur toute
  nouvelle dépendance tierce, tout écart à `architecture.md` et tout « point à trancher ».
- Toute décision structurante donne un ADR dans `docs/adr/` et, si besoin, une mise à jour
  d'`architecture.md` dans le même commit.
- En fin de lot : critères cochés, Journal de la fiche rempli, statut mis à jour dans
  `specs/README.md`, `make ci` vert.
- open-go-base est un autre dépôt (`../open-go-base`). Les évolutions du § 23 de
  l'architecture y sont autorisées : branche, PR fusionnée quand la CI est verte, étiquette
  semver, puis montée de version ici. Toute autre évolution demande l'accord de l'utilisateur.
- Décisions déjà prises pour le lot 1 : section « Décisions » de chaque fiche.

## Conventions qui reviennent sans cesse

- Code en anglais ; commentaires et documentation en français ; commentaires réservés au
  « pourquoi » non évident.
- Isolement des organisations (§ 9 de l'architecture) : RLS forcée sur toute table
  d'organisation, accès uniquement par `db.InOrg` (jamais `InTx`), `tenant.OrgID` en
  paramètre, clés étrangères composites, 404 pour une ressource d'une autre organisation,
  tests d'isolement par route et tests SQL de RLS. Les seules lectures
  inter-organisations passent par `internal/db/crossorg`.
- Deux rôles PostgreSQL : le propriétaire migre, l'application tourne avec un rôle qui ne
  peut pas contourner la RLS (vérifié au démarrage).
- Anchore (Syft, Grype, Grant) importé uniquement par ses adaptateurs (§ 4 de
  l'architecture, vérifié par `internal/archtest`).
- Traduction : aucune chaîne visible en dur ; clés anglaises `écran.élément` ; racines
  transverses `format.*`, `status.*`, `severity.*`, `validation.*`, `error.*` ; le JS reçoit
  ses libellés traduits via des attributs `data-`.
- Front sans npm ni bundler : `html/template`, modules ES natifs, CSS natif imbriqué
  (modificateur BEM `&.bloc--modificateur`, déclarations avant les règles imbriquées,
  `@media` imbriqués dans le composant). Aucun script ni style en ligne (CSP stricte).
- Migrations `internal/db/migrations/NNN_<sujet>.sql`, immuables une fois sur `main` : leur
  somme SHA-256 est vérifiée au démarrage.
- Comptes : authx ne fait que lire `users` ; c'est `internal/account` qui crée et modifie
  les comptes (`authx.HashPassword`, `must_change_pwd`).
- Évolutions attendues d'open-go-base : § 23 de l'architecture.
- TOTP obligatoire pour les comptes locaux : ne jamais utiliser
  `mfax.WithOptionalEnrollment()`.
- Jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux.
- Jobs idempotents ; mise en file dans la transaction qui produit la donnée.

## Commandes

```bash
make help               # liste des cibles
make ci                 # fmt-check, generate-check, vet, lint, test-race, test-integration, vuln, build, packages
make test-race          # tests unitaires
make test-integration   # tests étiquetés integration ; PostgreSQL : docker compose -f deploy/compose.yaml up -d
                        # (OGSBOM_TEST_DATABASE_DSN, par défaut postgres://postgres:postgres@localhost:5432/postgres)
make lint               # staticcheck (go tool)
make vuln               # govulncheck (go tool)
make generate           # code généré depuis api/openapi.yaml (à committer avant make ci)
make test-grypedb       # vraie base Grype (OGSBOM_TEST_GRYPEDB_DIR : base v6 installée)
make bench              # mesures sur le jeu de référence (docs/benchmarks.md)
make bench-search       # mesures de la recherche sur le jeu de référence, RLS active
make selfscan           # SBOM des binaires (Syft) et analyse (Grype) ; échec sur une KEV
make build              # bin/ogsbom-server, bin/ogsbom-host-agent, bin/ogsbom-repo-agent (CGO_ENABLED=0)
make packages           # ogsbom-host-agent amd64 et arm64, paquets deb et rpm dans dist/ (nfpm)
make run                # serveur avec config.yaml (cp config.example.yaml config.yaml)
```

Exploitation (configuration, rôles PostgreSQL, TLS, sondes) : [`docs/operations.md`](docs/operations.md).
