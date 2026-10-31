# 0018 — Analyse et constats : correspondance hors transaction, écriture sous verrou, identifiants CVE

- Statut : Accepté
- Date : 2026-10-31
- Lot : T06

## Contexte

`analysis.ref` analyse l'ensemble courant d'une référence « sous verrou de ligne sur la
référence » (§ 12). Une correspondance Grype dure de quelques centaines de millisecondes
à plusieurs secondes (5 000 composants : environ 5 s). Le catalogue `vulnerabilities` est
global et partagé par toutes les analyses de toutes les organisations. Grype identifie une
vulnérabilité par l'identifiant de sa source (GHSA pour Java, CVE pour le NVD et les
distributions), si bien qu'un même problème change d'identifiant selon l'écosystème.

## Décision

- **Correspondance hors transaction, écriture sous verrou.** Une analyse : (1) `Ensure`
  synchronise la base locale sur la cible ; (2) lecture en lecture seule de l'ensemble
  courant, de son SBOM d'origine et de la dernière analyse — même ensemble et même base :
  rien à faire ; (3) correspondance, sans transaction ouverte ; (4) catalogue mis à jour
  dans une transaction courte ; (5) transaction d'organisation qui verrouille la ligne de
  la référence (`tracked_refs … FOR UPDATE`, le verrou que prend l'ingestion), relit
  l'ensemble courant (changé : l'analyse s'efface, l'ingestion a mis en file la suivante)
  et la cible (changée : l'analyse recommence avec la nouvelle base, trois fois au plus),
  puis écrit les constats et `ref_analyses`. Deux analyses d'une même référence ne mêlent
  jamais leurs écritures, et un worker en retard n'écrase jamais un résultat plus récent.
- **Identifiant** : celui de Grype ramené au CVE quand la source n'en cite qu'un
  (`NormalizeByCVE`, comme `grype --by-cve`) ; l'identifiant d'origine devient un alias.
  La fiche du catalogue d'un CVE est celle du NVD quand la base l'a, sinon celle de la
  première correspondance ; une fiche n'est remplacée que par une fiche de source au moins
  aussi fiable (NVD d'abord, `source_rank`) et d'une base au moins aussi récente.
- **Un constat par (référence, composant, vulnérabilité)** ; plusieurs correspondances
  du même couple (sources différentes) sont fusionnées : la plus sûre (exact direct,
  exact indirect, CPE), puis la plus grave, union des versions corrigées.
- **Attributs copiés sur le constat** à chaque analyse : sévérité de la source qui a
  produit la correspondance (une distribution peut juger moins grave que le NVD ; à
  défaut, celle du catalogue), score CVSS, EPSS, KEV et risque (score de Grype : sévérité,
  EPSS, KEV), versions corrigées, type de correspondance, dernier instantané, base. Filtrer
  et trier par risque se fait sans jointure.
- **Cycle de vie** : couple nouveau → `open` ; revu → prolongé (`last_seen_at`) ; absent
  → `resolved`, motif `component_removed` (le composant a quitté l'inventaire) ou
  `not_matched` (la base ne le juge plus vulnérable) ; résolu qui réapparaît → rouvert sur
  la même ligne. `finding_events` garde l'historique (`opened`, `resolved`, `reopened`,
  avec instantané et base).
- **Rattachement** : purl canonique de chaque paquet Grype (`sbom.ComponentPURL`) contre
  `components.purl` des composants de l'ensemble ; une correspondance sur un paquet absent
  de l'inventaire (composant écarté à l'ingestion, composant décrit par le document) est
  comptée (`unmatched_count`) et ignorée.
- **Réanalyse du parc** : `analysis.rescan_all` liste les organisations actives par la
  fonction `crossorg` existante `ogsbom_list_organizations` et met en file un
  `analysis.rescan_org` par organisation ; celui-ci, dans `InOrg`, met en file un
  `analysis.ref` par référence active (non retirée, projet non archivé, avec inventaire),
  en priorité basse, par pages de 500. **Aucune nouvelle fonction `crossorg`.** La clé
  d'unicité fond la réanalyse avec une analyse en attente (dont la priorité haute est
  gardée) ; l'idempotence d'`analysis.ref` (même ensemble, même base) fait qu'une référence
  n'est réanalysée qu'une fois par cible.
- **Sans base** (aucune cible encore) : `analysis.ref` se termine sans rien écrire ; la
  première cible réanalysera tout.

## Conséquences

- Une correspondance peut être calculée deux fois pour une même référence quand une
  ingestion arrive pendant une analyse : coût en calcul, jamais en cohérence.
- Les écrans affichent la sévérité de la source et le score CVSS du catalogue (NVD) :
  « Faible · 9,8 » est possible pour un paquet de distribution, et voulu.
- Les constats d'une référence retirée ou d'un projet archivé restent tels quels (non
  réanalysés) ; la rétention (T17) décidera de leur sort.

## Alternatives écartées

- **Correspondance dans la transaction verrouillée** : une connexion tenue plusieurs
  secondes par analyse, l'ingestion de la même référence bloquée pendant ce temps, et les
  lignes du catalogue verrouillées jusqu'à la fin (contention entre organisations).
- **Verrou consultatif par référence** : sans lien avec le verrou de l'ingestion, et le §
  12 demande un verrou de ligne.
- **Identifiants de Grype tels quels** : log4j donnerait GHSA-jfh8-c2jp-5v3q, Debian
  CVE-2021-44228 pour le même problème ; la recherche par CVE (T09) passerait par les alias.
- **Nouvelle fonction `crossorg` listant les références actives de tout le parc** : plus de
  données exposées hors RLS que nécessaire, alors que la liste des organisations suffit.
