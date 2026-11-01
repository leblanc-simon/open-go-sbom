# T16 — Équipes et droits

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T11 | À faire |

## Objectif

Rattacher chaque projet à une équipe et limiter la visibilité et les droits de chacun aux
projets de ses équipes, sans affaiblir l'isolement entre organisations.

C'est le **premier lot du lot 2** : il touche tous les stores et toutes les surfaces de
lecture. T12, T13, T14 et T17 en dépendent pour ne pas modifier les mêmes fichiers en
parallèle.

## Périmètre

**Inclus**

- Équipes dans une organisation, membres et rôle par équipe, projet rattaché à une équipe.
- Matrice des droits documentée (`docs/security/permissions.md`) : qui voit, trie, modifie
  quoi selon le rôle d'organisation et le rôle d'équipe.
- Application de la matrice dans les stores (filtre d'équipe) et les handlers, avec tests
  générés à partir de la matrice.
- Jetons d'inscription et agents rattachables à une équipe : les projets créés héritent de
  l'équipe.
- Écrans : équipes, membres, rattachement des projets.
- Audit : création, modification et suppression des équipes, changements de membres et de
  rattachement des projets.

**Exclu** : SSO et correspondance de groupes (T25).

## Conception

- Les administrateurs d'organisation voient tout. Les autres membres voient les projets de
  leurs équipes.
- La recherche, le tableau de bord, les exports et l'API respectent le filtre d'équipe : un
  même test vérifie chaque surface.
- Migration de l'existant : équipe « Général » par organisation (voir Décisions).

## Livrables

Migrations, stores, écrans, matrice des droits, tests dérivés de la matrice.

## Critères d'acceptation

- [ ] Un membre sans équipe ne voit aucun projet rattaché à une équipe.
- [ ] Recherche, tableau de bord, exports et API respectent la matrice.
- [ ] La matrice documentée et les tests sont générés depuis la même source.
- [ ] Chaque modification d'équipe produit un événement d'audit.

## Tests attendus

Tests en table dérivés de la matrice, sur chaque route et chaque surface d'agrégat.

## Décisions

Prises le 1er novembre 2026 :

- Migration de l'existant : une équipe « Général » est créée dans chaque organisation ;
  tous les projets existants y sont rattachés et tous les membres actuels en deviennent
  membres avec leur rôle d'organisation actuel. Tout projet a ensuite toujours une équipe
  (pas de projet sans équipe).
- Rôles : le rôle d'organisation se réduit à « membre » ou « administrateur »
  (l'administrateur voit et gère tout). Les droits sur les projets viennent uniquement du
  rôle dans l'équipe : lecteur, analyste (trie les constats) ou administrateur d'équipe.
  Les `viewer` et `analyst` actuels deviennent membres de l'organisation, avec le même
  rôle dans l'équipe « Général ».
- SEC-09 corrigé : l'ajout d'un membre à une organisation crée une invitation, que le
  compte doit accepter avant d'être membre ; la réponse est identique que le compte
  existe ou non.

## Journal

_À remplir pendant la réalisation._
