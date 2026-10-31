# T11 — Recette du lot 1

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T07, T08, T09, T10 | À faire |

## Objectif

Passer le critère du lot 1 : **un parc pilote inventorié et interrogé**. Durcir, mesurer,
documenter et publier une préversion.

## Périmètre

**Inclus**

- Écrans d'administration d'instance : traitements en échec (relancer, abandonner), état de
  la base de vulnérabilités (version cible, version de chaque instance, âge, dernière mise à
  jour) et import manuel d'une archive.
- Mesures consolidées des cibles du cahier des charges selon `docs/benchmarks.md` :
  ingestion et analyse de 5 000 composants, recherche, tableau de bord, scan de l'agent
  serveur.
- Revue de sécurité de tout le lot 1 par un relecteur distinct de l'auteur, gravité selon
  l'OWASP Risk Rating ; mise à jour du modèle de menace ; correction des constats.
- Audit RGAA de tous les écrans du lot 1 (grille consignée) ; corrections.
- Point sur les évolutions d'open-go-base du § 23 de l'architecture attendues avant ce lot
  (codes de secours de mfax).
- `docs/operations.md` complet pour le lot 1 ; guide de démarrage utilisateur (FR et EN).
- Déploiement pilote et recette sur le périmètre défini avec l'utilisateur.
- Préversion `v0.1.0` : `CHANGELOG.md`, étiquette, binaires.

**Exclu** : toute nouvelle fonction.

## Critères d'acceptation

- [ ] Toutes les cibles chiffrées sont tenues au 95e centile sur la machine de référence,
      ou une nouvelle cible a été validée par l'utilisateur et reportée au cahier des
      charges.
- [ ] Aucune faiblesse de gravité haute ou critique (OWASP Risk Rating) ouverte à l'issue de
      la revue.
- [ ] Grille RGAA remplie pour chaque écran, sans non-conformité bloquante.
- [ ] Sur le parc pilote : tous les serveurs et dépôts prévus ont un instantané de moins de
      24 h.
- [ ] Pour trois CVE choisies avant la recette, la recherche renvoie exactement la liste de
      projets attendue, établie à la main au préalable.
- [ ] `v0.1.0` publiée.

## Décisions

Prises le 31 octobre 2026 :

- Parc pilote de démonstration : conteneurs Debian, Rocky Linux (famille RHEL) et Alpine
  portant l'agent serveur, et dépôts publics sur GitHub et GitLab. La liste exacte et les
  CVE de contrôle sont fixées au début du lot, avant toute recherche.
- `v0.1.0` publiée en préversion sur GitHub Releases : étiquette, binaires des trois rôles,
  sommes de contrôle.

## Journal

_À remplir pendant la réalisation._
