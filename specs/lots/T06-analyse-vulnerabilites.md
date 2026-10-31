# T06 — Analyse de vulnérabilités

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | Terminé |

## Objectif

Confronter l'inventaire courant de chaque référence à la base Grype à chaque changement,
puis tout le parc chaque fois que la base change, et tenir à jour des constats datés,
consultables par projet, par vulnérabilité et par composant.

## Périmètre

**Inclus**

- `internal/vuln/grype` : adaptateur qui implémente `vuln.Matcher.Match(ctx, blob)` : décodage
  du SBOM d'origine par Syft, correspondance Grype, rattachement de chaque résultat au
  composant par purl canonique, avec sévérité, CVSS, EPSS et percentile, KEV, score de
  risque, versions corrigées, type de correspondance.
- Base Grype commune aux instances (§ 12) : échéance `vulndb.check`, archives vérifiées dans
  `vulndb_archives`, version cible dans `vulndb_state`, synchronisation locale de chaque
  instance worker, bascule atomique ; alerte si la base dépasse un âge configurable.
- Handler `analysis.ref` (ensemble courant au moment de l'exécution, verrou de ligne sur la
  référence) et job `analysis.rescan_all` déclenché par un changement de cible.
- `internal/finding` : création, prolongation, résolution et réouverture des constats ;
  catalogue `vulnerabilities` mis à jour à chaque correspondance ; version de base notée.
- Écrans : onglet « Constats » de la fiche projet (tri par risque, filtres sévérité et KEV) ;
  fiche vulnérabilité (description, CVSS, EPSS, KEV, références, projets touchés de
  l'organisation, version présente et corrigée) ; fiche composant (projets qui l'utilisent,
  vulnérabilités par version).
- `docs/benchmarks.md` : machine de référence, protocole (95e centile, cache froid et
  chaud), et générateur de jeu de données synthétique (1 000 projets, 1 million de liens,
  constats réalistes), réutilisé par T09, T10, T11 et T21.
- CI : SBOM des trois binaires produits et analysés à chaque build ; échec sur une
  vulnérabilité KEV.

**Exclu** : triage (T14), politiques et alertes (T15), licences (T20), import manuel de la
base par écran (T11).

## Conception

- La base locale vit dans `vulndb.dir`. `/readyz` d'une instance worker échoue tant
  qu'aucune base n'est chargée ; une instance web seule n'en dépend pas.
- Un job d'analyse exige la version cible ; un worker en retard se synchronise avant de le
  traiter, si bien que deux workers ne produisent jamais de constats contradictoires.
- Un constat est identifié par (référence suivie, composant, vulnérabilité). Un couple
  résolu qui réapparaît est rouvert, l'historique est conservé.
- `rescan_all` met en file un `analysis.ref` par référence active avec une priorité
  inférieure aux ingestions ; la clé d'unicité et le relèvement de priorité de T02 font
  qu'une ingestion fraîche n'attend pas.
- Grype est piloté uniquement via l'adaptateur ; les tests unitaires utilisent un faux
  `Matcher`.

## Livrables

Paquets ci-dessus, migrations, écrans, `docs/benchmarks.md` et générateur, section
« Base de vulnérabilités » de `docs/operations.md` (en ligne, hors ligne, espace disque,
fréquence, plusieurs instances).

## Maquettes

Planches « 5 · Fiche vulnérabilité », « 7 · Fiche composant », onglet des constats de « 4a » et « 4b » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Un SBOM contenant `log4j-core 2.14.1` produit un constat CVE-2021-44228 marqué KEV.
- [x] Un SBOM d'hôte Debian d'exemple produit les constats attendus pour ses paquets dpkg
      (vérifie que distribution et paquets sources arrivent intacts jusqu'à Grype).
- [x] Une nouvelle cible déclenche une seule réanalyse par référence active.
- [x] Un composant mis à jour dans un nouvel instantané résout les constats correspondants.
- [x] Une archive corrompue ou dont la somme de contrôle diffère n'est jamais activée.
- [x] Avec deux instances worker, la seconde se synchronise sur la cible avant d'analyser.
- [x] Ingestion et analyse d'un SBOM de 5 000 composants en moins de 30 s au 95e centile
      selon `docs/benchmarks.md` (mesure consignée).
- [x] Les écrans passent le harnais d'isolement et l'assistant d'accessibilité.

## Tests attendus

Unitaires avec faux `Matcher` pour tout le cycle de vie des constats et pour l'idempotence
de `analysis.ref`. Intégration étiquetée `grypedb` avec une vraie base sur un jeu de SBOM
connus. Test de la bascule concurrente (analyses en cours pendant le changement de base).

## Décisions

Prises le 31 octobre 2026 :

- Alerte si la base Grype a plus de 5 jours.
- Machine de référence des mesures : le poste de développement actuel (16 cœurs, 30 Go de
  RAM) ; sa configuration exacte est consignée dans `docs/benchmarks.md`.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T06-analyse-vulnerabilites`.

### Livré

- **Dépendance** (validée au § 5) : `github.com/anchore/grype` v0.121.0, premier import
  direct (avec `github.com/anchore/clio`, déjà dans le graphe de Syft) ; `go-jose/v4`
  monte en v4.1.6 (CVE signalée par l'autoanalyse, indirecte).
- `internal/vuln` : types du domaine (`Vulnerability`, `Match`, `Severity`, `Version`,
  `Result`), interfaces `Matcher`, `Engine`, `Database`, `Source`, `Fetcher` ; `Checker`
  (job `vulndb.check`, `Import`) ; archives par blocs, cible, état (`ReadState`,
  `TargetVersion`, `ListArchives`) ; `Manager` (copie locale, bascule sous verrou
  lecture/écriture, `Ensure`, `Ready`, `Run`) ; catalogue (`UpsertCatalog`,
  `GetVulnerability` par identifiant ou alias) ; `ParseCVSS3` ; métriques
  `lotor_vulndb_*`. `internal/vuln/vulntest` : fausse base pour les tests.
- `internal/vuln/grype` : `Engine` (installation par le curateur de Grype, hydratation,
  ouverture validée), correspondance du SBOM d'origine (décodeurs de Syft,
  `NormalizeByCVE`, matchers par défaut de la commande grype), rattachement par
  `sbom.ComponentPURL`, fiche NVD d'un CVE, sévérité, CVSS, EPSS et centile, KEV
  (dates, rançongiciel), risque, versions corrigées, type de correspondance ; `Source`
  (liste `latest.json`, adresse de l'archive). `grypetest.TinyArchive` : vraie archive v6
  vide pour les tests.
- `internal/download` : `Fetcher` HTTP(S) du serveur (hors métier).
- `internal/finding` : `Analyzer` (`analysis.ref`, `analysis.rescan_all`,
  `analysis.rescan_org`), cycle de vie (création, prolongation, résolution avec motif,
  réouverture, historique), `Service` des écrans.
- Migrations **009** (catalogue `vulnerabilities`, `vulndb_archives`,
  `vulndb_archive_chunks`, `vulndb_state`, globales) et **010** (`findings`,
  `finding_events`, `ref_analyses`, RLS standard, clés composites) ; harnais d'isolement
  SQL étendu.
- `internal/inventory` : `GetComponent`, `ComponentUsage`, `Service.Component`.
- Configuration : fragment `vulndb` (liste, répertoire, hors ligne, vérification 6 h,
  synchronisation 1 min, âge 120 h, délais, archive 2 Gio, analyse 10 min) ; `main.go`
  enregistre les quatre jobs (analyse avec `WithOrgLimit` et `WithTimeout`), l'échéance
  (sauf hors ligne) et la synchronisation de fond ; `/readyz` d'une instance worker exige
  une base chargée.
- Écrans (fr, en, clair, sombre) : onglet « Constats » de la fiche projet (références et
  pastilles par sévérité, tri par risque, filtres sévérité et KEV, ouverts et résolus avec
  motif, pagination), fiche vulnérabilité (résumé, CVSS détaillé, autres scores, EPSS,
  KEV, CWE, références http(s), projets touchés ouverts ou résolus), fiche composant
  (répartition des versions, vulnérabilités par version, projets qui l'utilisent),
  administration de la base (cible, vérification, archives) et alerte d'âge sur chaque page
  d'administration. Composants CSS portés : `sev`, `sevcounts`, `kev`, `epss`, `risk`,
  `segmented`, `matrix-hit`, `bars`, `legend-inline` ; jauges en SVG (attributs, pas de
  style en ligne) ; fonctions de gabarit `decimal`, `percent`, `barWidth`.
- `internal/benchdata` et `docs/benchmarks.md` : jeu de référence (1 000 projets,
  1 million de liens, 75 000 constats) généré en SQL, SBOM synthétique, protocole et
  mesures.
- CI : `make sbom`, `make selfscan` (Syft et Grype aux versions de `go.mod`, échec sur KEV),
  job `selfscan` ; `make test-grypedb`, `make bench`.
- Docs : ADR 0017, 0018, 0019 ; `architecture.md` (§ 3, 4, 6, 8, 9, 12) ;
  `docs/operations.md` (« Base de vulnérabilités », sondes, métriques) ; modèle de menace ;
  `config.example.yaml` ; `testdata/sbom/log4shell.cdx16.json`.

### Tests

- Unitaires : conversion des correspondances de Grype, liste de distribution, installation
  d'une vraie archive v6 vide et refus d'archives corrompues, fusion et cycle de vie des
  constats (règles nommées), CVSS, sévérités, configuration.
- Intégration (faux `Engine`) : vérification, somme différente, archive illisible, bloc
  altéré en base jamais installé ; seconde instance synchronisée avant toute
  correspondance ; bascule pendant des correspondances en cours (attente, ancienne base
  fermée ensuite) ; import ; catalogue (rang de source, alias) ; log4j marqué KEV et
  idempotence ; mise à jour → résolu, retour → rouvert ; fiche retirée → résolu ; une
  seule réanalyse par référence active (fusion avec une analyse en attente, priorité haute
  gardée) ; worker en retard ; cible ou inventaire changés pendant la correspondance ;
  lectures et RLS ; écrans, accessibilité, absence de code en ligne, isolement par route ;
  bout en bout du binaire (deux instances prêtes après import d'une vraie base).
- `grypedb` (vraie base v6.1.10 du 30 octobre 2026) : log4j-core 2.14.1 → CVE-2021-44228
  KEV, critique, CVSS 10, fiche NVD ; hôte Debian 12 → 236 constats dpkg, tous rattachés
  (CVE-2024-5535 sur openssl et libssl3 par le paquet source) ; correspondances
  concurrentes ; mesure 5 000 composants.

### Décisions

- **ADR 0017** **[à relire]** : archives par blocs de 8 Mio dans PostgreSQL ; téléchargement
  par `vuln.Fetcher` implémenté par `internal/download` (le client de Grype décompresse au
  vol et ne prend pas de contexte) ; validation par installation complète ; un répertoire
  par archive, bascule sous verrou lecture/écriture ; alerte sur chaque page
  d'administration et par métrique ; lecture de la fiche NVD par une API marquée dépréciée
  par Grype (`//lint:ignore SA1019` justifié).
- **ADR 0018** **[à relire]** : correspondance **hors transaction**, écriture sous verrou
  de ligne de la référence avec contrôle de l'ensemble et de la cible (écart de lettre au
  « sous verrou de ligne » du § 12 : le verrou couvre l'écriture, pas le calcul) ;
  identifiants ramenés au CVE (`--by-cve`) ; fiche NVD prioritaire au catalogue ;
  sévérité du constat = celle de la source de la correspondance ; motifs de résolution
  `component_removed` et `not_matched` ; historique `finding_events` ; réanalyse par
  organisation **sans nouvelle fonction `crossorg`** (réutilise
  `lotor_list_organizations`) ; sans base, une analyse se termine sans rien écrire.
- **ADR 0019** **[à relire]** : jeu synthétique en SQL (`internal/benchdata`) ;
  autoanalyse par les commandes Syft et Grype lancées par `go run …@version` plutôt que par
  des actions GitHub tierces ; SBOM non publiés comme artefacts avant T26.
- Valeurs par défaut **[à relire]** : vérification toutes les 6 h, synchronisation chaque
  minute, archive 2 Gio au plus, analyse 10 min, téléchargement 30 min, répertoire
  `/var/lib/lotor/vulndb`.
- Fiche vulnérabilité visible pour tout identifiant du catalogue (public), constats limités
  à l'organisation ; fil d'Ariane vers la vue d'ensemble (pas encore de listes
  « Vulnérabilités » ni « Composants » : T09, T10).
- Fiche composant adressée par l'identifiant d'un composant, affichant sa famille
  (`purl_base`) ; versions triées lexicalement (la comparaison par écosystème arrive avec
  `internal/version`, T09).

### Écarts

- Import manuel par écran : la fonction (`vuln.Checker.Import`) est livrée et testée,
  l'écran reste à T11 (exclu de la fiche) ; d'ici là un site isolé passe par un miroir de
  la liste.
- Purge des anciennes archives : non livrée (T11, avec l'écran d'import).
- Mesures faites dans l'environnement de réalisation (4 cœurs, 15 Gio), pas sur la
  machine de référence (16 cœurs, 30 Go) : la cible tient ici, donc a fortiori sur la
  référence **[à relire]**.
- `internal/vuln/vulntest` et `internal/vuln/grype/grypetest` : paquets d'aide aux tests
  (comme `dbtest`), non couverts par eux-mêmes.

### ADR créés

0017, 0018, 0019.

### Mesures

- **Ingestion et analyse d'un SBOM de 5 000 composants** (vraie base, bout en bout) :
  froid 6,26 s, chaud p50 6,06 s, **p95 6,45 s** (cible 30 s), dont ingestion 0,70 s ;
  ouverture de la base 2 à 4 s.
- Jeu de référence (1 000 projets, 1 million de liens) généré en 51 s ; onglet Constats
  p95 5,4 ms, fiche vulnérabilité p95 13,6 ms, fiche composant p95 3,4 ms.
- Couverture (unitaires et intégration) : `vuln` 82,0 %, `vuln/grype` 89,3 %, `finding`
  84,9 %, `inventory` 86,3 %, `download` 91,3 %, `benchdata` 87,0 %, `web` 81,6 %, `config`
  97,6 %.
- Autoanalyse des binaires (base du 30 octobre 2026) : aucune KEV ; `lotor-server` :
  go-jose v4.1.5 (corrigée par la montée en v4.1.6) et GO-2026-5932 sur `x/crypto`
  v0.58.0 (sans correctif publié, non atteinte selon govulncheck).

### Pour les lots suivants

- **T09 (recherche)** : `vulnerabilities.aliases` indexé (GIN) pour `GHSA-…` ;
  `findings (org_id, vuln_id, status)` et `(org_id, component_id, status)` indexés ; jeu de
  référence : `benchdata.Generate(ctx, pool, org, slug, benchdata.Reference())` puis
  `ANALYZE` par le propriétaire (`dbtest.Owner`), voir `TestReferenceDataset`. La fiche
  composant trie les versions lexicalement : la brancher sur `internal/version`.
- **T10 (tableau de bord)** : décomptes par sévérité et KEV prêts (`finding.RefCounts`,
  `finding.Sum`) ; `findings.first_seen_at`, `resolved_at` et `finding_events` donnent les
  évolutions ; `lotor_vulndb_*` pour l'âge de la base.
- **T11 (recette)** : écran d'import (`vuln.Checker.Import`, dans une requête bornée par
  `vulndb.max_archive_mib`, l'installation prend plusieurs minutes : à faire en job) et
  purge des archives non cibles ; vérifier sur la machine de référence les mesures de
  `docs/benchmarks.md`.
- **T14 (triage)** : les constats ont un état `open`/`resolved` ; le triage s'ajoute en
  table séparée, l'analyse ne touche pas aux décisions.
- **T17 (rétention)** : `findings.snapshot_id`, `finding_events.snapshot_id` et
  `ref_analyses.snapshot_id` référencent `snapshots` (clés composites, sans cascade).
