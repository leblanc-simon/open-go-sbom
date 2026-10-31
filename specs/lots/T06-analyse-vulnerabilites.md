# T06 — Analyse de vulnérabilités

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | À faire |

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

- [ ] Un SBOM contenant `log4j-core 2.14.1` produit un constat CVE-2021-44228 marqué KEV.
- [ ] Un SBOM d'hôte Debian d'exemple produit les constats attendus pour ses paquets dpkg
      (vérifie que distribution et paquets sources arrivent intacts jusqu'à Grype).
- [ ] Une nouvelle cible déclenche une seule réanalyse par référence active.
- [ ] Un composant mis à jour dans un nouvel instantané résout les constats correspondants.
- [ ] Une archive corrompue ou dont la somme de contrôle diffère n'est jamais activée.
- [ ] Avec deux instances worker, la seconde se synchronise sur la cible avant d'analyser.
- [ ] Ingestion et analyse d'un SBOM de 5 000 composants en moins de 30 s au 95e centile
      selon `docs/benchmarks.md` (mesure consignée).
- [ ] Les écrans passent le harnais d'isolement et l'assistant d'accessibilité.

## Tests attendus

Unitaires avec faux `Matcher` pour tout le cycle de vie des constats et pour l'idempotence
de `analysis.ref`. Intégration étiquetée `grypedb` avec une vraie base sur un jeu de SBOM
connus. Test de la bascule concurrente (analyses en cours pendant le changement de base).

## Points à trancher

- Âge maximal de la base avant alerte (5 jours proposé).
- Machine de référence des mesures.

## Journal

_À remplir pendant la réalisation._
