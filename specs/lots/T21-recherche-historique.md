# T21 — Recherche à une date passée

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Répondre à « quels projets utilisaient ce composant à telle date ? », par exemple pour
mesurer l'exposition passée lors d'une réponse à incident.

## Périmètre

**Inclus**

- Pour chaque référence, l'instantané en vigueur à la date demandée (le dernier reçu avant
  elle) ; recherche identique à T09 sur ces instantanés.
- Champ « à la date du » sur l'écran de recherche, paramètre dans l'API.
- Avertissement quand la date précède la rétention (T17) : les résultats sont alors partiels.

**Exclu** : constats de vulnérabilité à une date passée (la base Grype de l'époque n'est pas
conservée).

## Conception

- Index sur (référence, date de réception) ; la requête « dernier instantané avant la date »
  ne parcourt pas l'historique complet.
- Les résultats indiquent la date de l'instantané retenu pour chaque projet.
- S'appuie sur la rétention de T17 ([ADR 0039](../../docs/adr/0039-retention-des-instantanes.md)) :
  pour toute date postérieure ou égale à l'**horizon** de l'organisation
  (`inventory.ReadRetention`, table `snapshot_retention` : la plus récente coupure
  appliquée), l'instantané en vigueur de chaque référence existe encore et la recherche
  est exacte ; pour une date antérieure, il ne reste que le dernier instantané de chaque
  mois (l'état retenu est celui de la fin du mois précédent ou plus ancien) : c'est le
  cas de l'avertissement. Sans ligne, la rétention n'est jamais passée et l'historique
  est complet. Les instantanés sont ordonnés par date de scan puis identifiant
  (`snapshots_ref_idx`), comme `ref_current`.

## Critères d'acceptation

- [ ] Un composant retiré le 10 n'apparaît plus pour une date du 11, mais apparaît pour le 9.
- [ ] Une date antérieure à la rétention affiche l'avertissement.
- [ ] Moins de 5 s au 95e centile sur le jeu de données de T06 enrichi de 12 mois
      d'historique, selon `docs/benchmarks.md`.

## Tests attendus

Intégration avec horloge simulée et instantanés datés ; isolement.

## Points à trancher

Aucun.

## Journal

_À remplir pendant la réalisation._
