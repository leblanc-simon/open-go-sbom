# T10 — Tableau de bord d'organisation

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T06 | Terminé |

## Objectif

Une page d'accueil d'organisation qui montre en un coup d'œil l'exposition, sa tendance et
ce qui demande une action.

## Périmètre

**Inclus**

- Job quotidien qui alimente `org_daily_stats` : constats ouverts par sévérité, KEV ouverts,
  projets, agents muets, délais de correction.
- Indicateurs : constats ouverts par sévérité, KEV ouverts, tendance sur 90 jours, projets
  les plus exposés, composants vulnérables les plus répandus, agents muets, délai médian de
  correction par sévérité.
- `internal/render` : graphiques SVG côté serveur (ligne, barres) avec titre, description et
  tableau de données équivalent.
- Fiche projet : en-tête avec les mêmes indicateurs à l'échelle du projet.

**Exclu** : tableau de bord global à l'instance (non demandé).

## Conception

- Les indicateurs « instantanés » se calculent sur les tables courantes ; seules les séries
  temporelles lisent `org_daily_stats`. Le premier jour, la courbe ne montre qu'un point
  plutôt qu'une série inventée.
- Délai de correction = `resolved_at − first_seen_at` des constats résolus sur la période.
- Les graphiques n'ont pas de JavaScript ; les valeurs exactes sont lisibles au survol via
  `<title>` et dans le tableau équivalent.
- Couleurs tirées de `tokens.css` ; la sévérité n'est jamais portée par la seule couleur.

## Livrables

Job, écrans, assistants SVG, tests.

## Maquettes

Planches « 2 · Tableau de bord », ses variantes en thème sombre et mobile du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Chaque indicateur est vérifié contre un jeu de données construit à la main.
- [x] La page se charge en moins d'1 s au 95e centile sur le jeu de données de T06, selon
      `docs/benchmarks.md`.
- [x] Les graphiques sont lisibles en thème clair et sombre et passent l'assistant
      d'accessibilité.

## Tests attendus

Fichiers SVG attendus (« golden ») pour les graphiques ; intégration des agrégats ;
isolement.

## Décisions

Prises le 31 octobre 2026 :

- Agent muet au-delà de 7 jours.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T10-tableau-de-bord`.

### Livré

- Migration **012** : `org_daily_stats`, `project_daily_stats` (RLS standard, clé
  composite vers `projects`), index `findings_resolved_idx` ; harnais d'isolement SQL
  étendu.
- `internal/dashboard` : `Service.Org` et `Service.Project` (instantanés en une
  transaction `REPEATABLE READ` en lecture seule, séries, variation sur 7 jours, délai
  médian de correction par sévérité, projets exposés, composants répandus, agents muets) ;
  `Service.Record` et les jobs `dashboard.stats_all` (échéance horaire) et
  `dashboard.stats_org` ; périodes 30, 90 et 365 jours.
- `internal/agent` : seuil `SilentAfter` porté à **7 jours** ; `agent.Silent` (décompte
  par pages et plus anciens silences, règle `Agent.StateAt`) et `Agent.SilentSince`
  (`Activity.Since` de T07).
- `internal/render/chart.go` et `partials/charts.html` : courbe SVG (titre, description,
  zones de survol, point final marqué) et barres en tableau ; fichiers attendus
  `internal/render/testdata/chart_*` (fr, en, série complète, point unique, barres).
- Écrans : tableau de bord sur `/o/{slug}/` (remplace la vue d'ensemble provisoire) ;
  en-tête de la fiche projet (tuiles, tendance, délai) ; sélecteur de période sans
  JavaScript ; composants CSS `chart`, `bar-chart`, `stat`, `trend`, `period-form` ;
  menu « Tableau de bord ».
- `webtest` : SVG décoratif ou image nommée, références `aria-labelledby` /
  `aria-describedby` existantes (vérifié sur toutes les pages des tests).
- Docs : ADR 0027 ; `architecture.md` (§ 8, § 14, § 17) ; `docs/operations.md`
  (« Tableau de bord », seuil muet) ; `docs/benchmarks.md` (mesures T10) ; `make bench`
  couvre `internal/web`.

### Tests

- Intégration, jeu construit à la main (`internal/dashboard`) : chaque indicateur
  (ouverts par sévérité, KEV, références retirées et projets archivés exclus, délais
  médians sur 90 et 365 jours, projets exposés, familles de composants, agents muets,
  dernière analyse, premier jour à un point) ; mêmes indicateurs par projet ; ligne du jour,
  réécriture idempotente, lignes par projet, purge ; séries et pas hebdomadaire ; jobs
  (organisations archivées ignorées, clé d'unicité, job sans organisation) ; organisation
  étrangère vide.
- `internal/agent` : seuil de 7 jours, décompte sur plus de 500 agents, ordre des silences.
- `internal/render` : géométrie et fichiers SVG attendus ; `webtest` : nouvelles règles.
- `internal/web` : écrans en fr et en, thèmes clair et sombre, trois périodes et une
  période invalide, accessibilité et absence de code en ligne, variation et agent muet après
  une semaine, isolement (B ne voit rien de A ; 404 sur les pages de A) ; route couverte par
  le harnais d'isolement.
- Captures (clair, sombre, mobile 390 px) relues ; la grille de tendance a été corrigée en
  mobile.

### Décisions

- **ADR 0027** **[à relire]** : constats comptés sur les références actives des projets
  actifs (un constat par branche) ; délai sur les constats résolus pendant la période ;
  statistiques **réécrites toutes les heures** sous la date du jour plutôt qu'un passage
  quotidien unique ; table `project_daily_stats` en plus de `org_daily_stats` (série de
  la fiche projet) ; purge des lignes par projet au-delà de 400 jours ; pas de nouvelle
  fonction `crossorg` (`ogsbom_list_organizations`, comme la réanalyse).
- **Seuil « muet » de 7 jours pour toute l'interface** (liste des agents, fiche projet,
  tableau de bord) plutôt qu'un seuil propre au tableau de bord **[à relire]**.
- Périodes 30/90/365 jours (sélecteur de la maquette), un point par semaine sur 12 mois ;
  dates en ISO comme le reste de l'interface **[à relire]**.
- Tuiles sans lien : l'onglet « Constats » n'affiche qu'une référence à la fois et il n'y a
  pas encore de liste transverse des constats (T09) **[à relire]**.
- Rôle du visiteur retiré de la page d'accueil de l'organisation (visible dans les
  membres).

### Écarts

- Section « Alertes » de la maquette et objectifs de délai par sévérité : non livrés
  (alertes et politiques en T15) ; le délai est affiché sans objectif.
- Liens « Tous les composants » et filtres des tuiles vers une liste transverse : à
  brancher sur la recherche (T09).
- Mesures sur l'environnement de réalisation (4 cœurs partagés), pas sur la machine de
  référence **[à relire]**.

### ADR créés

0027.

### Mesures

- Tableau de bord, jeu de référence + un an de statistiques : p95 **594 ms** (90 jours),
  603 ms (12 mois) ; fiche projet p95 32 ms ; enregistrement du jour 0,34 s.
- Couverture (unitaires et intégration) : `dashboard` 86,9 %, `agent` 85,8 %, `render`
  91,4 %, `webtest` 90,6 %.

### Pour les lots suivants

- **T09** : brancher les tuiles et « composants répandus » sur la recherche (filtres
  sévérité, KEV, `purl_base`).
- **T11** : vérifier les mesures sur la machine de référence ; l'audit manuel doit couvrir
  les graphiques (lecteur d'écran : nom et description de chaque courbe).
- **T15** : alertes et objectifs de délai (section « Alertes », repères sur les barres).
- **T16** : restreindre les agrégats aux projets visibles de l'équipe.
- **T17** : `project_daily_stats` a sa propre purge (400 jours).
