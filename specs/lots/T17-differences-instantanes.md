# T17 — Différences d'instantanés

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | À faire |

## Objectif

Montrer ce qui a changé entre deux instantanés d'une référence, et garder un historique dont
la taille est maîtrisée.

## Périmètre

**Inclus**

- Calcul de la différence entre l'ensemble d'inventaire d'un instantané et celui du
  précédent : composants ajoutés, retirés, montés ou descendus de version (comparaison par
  `version`), stockée par couple d'ensembles (deux instantanés au même ensemble n'ont
  aucune différence à calculer).
- Différence entre deux instantanés quelconques, à la demande.
- Effet sur la sécurité : constats introduits et résolus par un instantané.
- Écrans : frise des instantanés d'une référence, comparaison de deux instantanés.
- Rétention configurable des anciens instantanés (nombre ou durée, avec conservation d'un
  instantané par mois au-delà) et nettoyage par job des ensembles d'inventaire et des blobs
  devenus orphelins.
- Routes d'API correspondantes.

**Exclu** : recherche à une date passée (T21), qui s'appuie sur cette rétention.

## Conception

- Deux composants de même `purl_base` et de versions différentes forment une montée ou une
  descente, pas un ajout plus un retrait.
- La rétention ne supprime jamais le dernier instantané d'une référence, ni un ensemble ou
  un blob encore référencé.

## Livrables

Migrations, calcul, écrans, job de rétention, documentation de la rétention.

## Critères d'acceptation

- [ ] Les quatre catégories de changement sont correctes sur un jeu construit à la main.
- [ ] Une montée de version qui corrige une CVE apparaît comme « constat résolu ».
- [ ] La rétention garde un instantané par mois au-delà de la fenêtre et supprime les
      ensembles et blobs orphelins, et eux seuls.

## Tests attendus

Tables de différences ; intégration de la rétention avec horloge simulée ; isolement.

## Points à trancher

- Valeurs par défaut de la rétention.

## Journal

_À remplir pendant la réalisation._
