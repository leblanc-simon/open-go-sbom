# T18 — Recette du lot 2

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T12, T13, T14, T15, T16, T17 | À faire |

## Objectif

Passer le critère du lot 2 : **aucun composant ajouté par l'IA sans preuve vérifiée**, avec
un taux de faux positifs mesuré et tenu, et publier une préversion `v0.2.0` durcie.

## Périmètre

**Inclus**

- Évaluation finale de l'enrichissement IA sur le corpus annoté étendu et sur un
  échantillon annoté des dépôts pilotes ; rapport (précision, rappel, taux de faux positifs,
  coût, motifs de rejet).
- Revue de sécurité ciblée par un relecteur distinct de l'auteur, gravité selon l'OWASP Risk
  Rating : agent dépôt (injection d'instructions, sorties vers le fournisseur, secrets des
  forges), notifications (webhooks, SMTP), droits par équipe ; mise à jour du modèle de
  menace.
- Audit RGAA des écrans du lot 2.
- Nouvelle mesure des cibles de performance avec les équipes et les conteneurs, selon
  `docs/benchmarks.md`.
- Documentation utilisateur et exploitation du lot 2 ; `CHANGELOG.md` ; `v0.2.0`.

**Exclu** : toute nouvelle fonction.

## Critères d'acceptation

- [ ] Zéro composant d'origine IA accepté sans preuve vérifiée, sur le corpus et le pilote.
- [ ] Taux de faux positifs et rappel dans les seuils validés en T12, sur le corpus et sur
      l'échantillon pilote annoté.
- [ ] Aucune faiblesse de gravité haute ou critique ouverte.
- [ ] Grille RGAA remplie pour chaque nouvel écran, sans non-conformité bloquante.
- [ ] `v0.2.0` publiée.

## Journal

_À remplir pendant la réalisation._
