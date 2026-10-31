# 0027 — Tableau de bord : indicateurs instantanés, statistiques quotidiennes, graphiques SVG

- Statut : Accepté
- Date : 2026-10-31
- Lot : T10

## Contexte

Le tableau de bord d'organisation (T10) montre l'exposition, sa tendance et ce qui demande
une action ; la fiche projet reprend les mêmes indicateurs à son échelle. La fiche du lot
impose : instantanés sur les tables courantes, séries sur `org_daily_stats`, un seul point
le premier jour plutôt qu'une série inventée, délai de correction = `resolved_at −
first_seen_at`, graphiques sans JavaScript, sévérité jamais portée par la seule couleur,
page en moins d'1 s au 95e centile sur le jeu de T06. Décision validée : agent muet au-delà
de 7 jours.

## Décision

- **Périmètre des décomptes.** Un constat ouvert compte s'il est sur une référence active
  (`removed_at` nul) d'un projet actif (`archived_at` nul) ; à l'échelle d'un projet, ses
  références actives, même archivé. Un constat présent sur deux branches compte deux fois
  (les constats sont par référence, comme l'onglet « Constats »). Le délai médian de
  correction porte sur les constats `resolved` dont `resolved_at` tombe dans la période,
  des projets actifs ; un constat rouvert sort du calcul (son `resolved_at` est effacé).
- **Statistiques quotidiennes** (migration 012) : `org_daily_stats` (ouverts par sévérité,
  KEV ouverts et vulnérabilités KEV distinctes, projets actifs, agents muets, résolus du
  jour et délai médian par sévérité) et `project_daily_stats` (ouverts par sévérité et
  KEV de chaque projet actif) — la fiche projet a besoin de sa propre série. Une ligne par
  jour UTC, **réécrite à chaque passage** : l'échéance `dashboard.stats_all` passe toutes
  les heures et met en file un `dashboard.stats_org` par organisation active, si bien qu'un
  arrêt pendant le passage du soir ne laisse pas de trou ; la ligne d'un jour écoulé est
  l'état de sa fin de journée. Historique par projet purgé au-delà de 400 jours ;
  historique d'organisation conservé (une ligne par jour).
- **Pas de nouvelle fonction `crossorg`** : la liste des organisations vient de
  `lotor_list_organizations`, comme la réanalyse (ADR 0018).
- **Séries.** Lecture des lignes de la période (un jour sur sept au-delà de 90 jours),
  plus l'état courant comme dernier point ; abscisse proportionnelle au temps (un jour
  manquant reste visible). Variation « en 7 jours » : état courant moins la ligne d'il y a
  exactement 7 jours, « pas encore d'historique » sinon.
- **Lecture d'une page** dans une transaction en lecture seule `REPEATABLE READ` : tous les
  chiffres viennent du même état. Les constats ouverts se lisent en un seul passage
  groupé par projet et sévérité (décomptes, projets exposés, projets KEV) ; les familles de
  composants sont réduites à des couples (composant, projet) avant regroupement, et leurs
  versions ne se lisent que pour les cinq retenues.
- **Agents muets** : la règle des écrans des agents (`agent.Activity`, T07 : dernier
  inventaire d'un agent serveur, dernier contact d'un agent dépôt), seuil
  `agent.SilentAfter` porté de 72 h à 7 jours pour toute l'interface ; `agent.Silent`
  parcourt les agents par pages et garde les cinq plus anciens silences.
- **Graphiques** : `internal/render/chart.go` calcule la géométrie, `partials/charts.html`
  dessine. Courbe : un SVG par sévérité (`role="img"`, `<title>` et `<desc>` traduits,
  échelle propre, point final marqué même seul, zones de survol avec `<title>` par
  point), et un tableau équivalent dans un `<details>`. Barres (délai de correction) : un
  tableau dont chaque ligne porte le libellé, une barre SVG décorative et la valeur exacte.
  Couleurs par classes (`chart--critical`…), jamais par style en ligne.
- **Accessibilité vérifiée** : l'assistant de `webtest` refuse un `<svg>` ni décoratif
  (`aria-hidden`) ni image nommée, et toute référence `aria-labelledby` /
  `aria-describedby` vers un identifiant absent.

## Conséquences

- Le premier jour, chaque courbe n'a qu'un point ; elle s'allonge d'un point par jour.
- Un passage horaire par organisation coûte environ 0,75 s sur le jeu de référence (1 000
  projets) ; à surveiller si le nombre d'organisations devient grand (plafond par
  organisation possible, comme pour l'analyse).
- Les indicateurs des alertes (« alertes » de la maquette), des objectifs de délai par
  sévérité et des listes transverses de constats et de composants n'existent pas encore :
  T15 (alertes, politiques) et T09 (recherche).

## Alternatives écartées

- **Reconstruire l'historique depuis `finding_events`** : exact pour les constats, mais pas
  pour les projets ni les agents, et coûteux à chaque affichage ; la fiche demande une
  série enregistrée.
- **Un seul passage quotidien** : un arrêt au mauvais moment laisserait un trou d'un jour.
- **Graphiques en JavaScript ou bibliothèque** : interdit par la CSP et par la fiche ; un
  SVG serveur suffit.
- **Barres en SVG avec texte** : le texte d'un SVG étiré se déforme ou devient illisible en
  mobile ; le tableau garde des libellés HTML lisibles.
