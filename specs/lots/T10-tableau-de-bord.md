# T10 — Tableau de bord d'organisation

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T06 | À faire |

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

- [ ] Chaque indicateur est vérifié contre un jeu de données construit à la main.
- [ ] La page se charge en moins d'1 s au 95e centile sur le jeu de données de T06, selon
      `docs/benchmarks.md`.
- [ ] Les graphiques sont lisibles en thème clair et sombre et passent l'assistant
      d'accessibilité.

## Tests attendus

Fichiers SVG attendus (« golden ») pour les graphiques ; intégration des agrégats ;
isolement.

## Points à trancher

- Seuil « agent muet » par défaut (7 jours, comme dans le cahier des charges).

## Journal

_À remplir pendant la réalisation._
