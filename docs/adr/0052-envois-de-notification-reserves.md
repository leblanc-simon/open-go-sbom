# 0052 — Envois de notification réservés avant l'appel réseau

- Statut : Accepté
- Date : 2026-11-01
- Lot : T18 (recette du lot 2)
- Complète : [0046](0046-notifications.md)

## Contexte

L'ADR 0046 promet un seul envoi par couple (canal, violation). Chaque envoi est un job
`notify.send` de clé d'unicité `channel:<id>:<mode>` ; mais la file ne dédoublonne que les
jobs **en attente** : pendant qu'un envoi est en cours (appel réseau, jusqu'à
`notify.timeout`), une nouvelle évaluation peut mettre en file un second job, qu'un autre
worker prend aussitôt. Les deux lisaient les mêmes envois en attente et envoyaient le
même lot. La recette du lot 2 l'a constaté sur une vraie instance : une politique qui
ouvrait 195 violations a fait partir 295 violations en cinq messages, le premier lot de
100 deux fois, à 3 ms d'écart, avec le même `X-Lotor-Delivery`.

## Décision

- La préparation d'un envoi **verrouille la ligne du canal** (`FOR UPDATE`) puis
  **réserve** son lot : `notification_deliveries.claimed_at` = instant de la réservation
  (migration 023). Elle ne prend que des envois en attente **libres** : sans réservation,
  ou réservés depuis plus de **10 minutes** (`claimTTL`, au-delà de `notify.timeout`,
  borné à 5 min) — la réservation d'un envoi interrompu (arrêt pendant l'appel réseau) se
  reprend donc. **[à relire]**
- L'issue de l'envoi lève la réservation : succès, envois marqués `sent` ; échec,
  réservation retirée pour la tentative suivante ; violation résolue entre-temps,
  `skipped`.
- Un envoi qui ne trouve que des envois réservés par un autre renvoie
  `ErrSendInProgress` : son job est réessayé selon la file (10 s, 20 s…), et trouve alors
  le lot envoyé, ou la réservation expirée. **[à relire]**
- Garantie inchangée vis-à-vis du destinataire : au moins une fois, avec un identifiant
  de message stable par lot ; le doublon ne vient plus que d'une réponse perdue (le
  destinataire l'écarte par `X-Lotor-Delivery`, Matrix de lui-même).

## Alternatives écartées

- **Garder la transaction ouverte pendant l'appel réseau** (verrou du canal jusqu'à la
  fin) : pas de migration, mais une connexion et un verrou tenus jusqu'à
  `notify.timeout`, qui bloquent la modification du canal et, par la clé étrangère,
  l'insertion de nouveaux envois du canal par l'évaluation des politiques.
- **Clé d'unicité étendue aux jobs en cours** : une violation ouverte pendant un envoi
  n'aurait plus de job pour partir avant le suivant.
- **Verrou consultatif de session** : la couche `db` ne prête pas de connexion hors
  transaction, et un verrou de session perdu avec la connexion se comprend mal.

## Conséquences

- Migration 023 (colonne `claimed_at`, contrainte : seul un envoi en attente est réservé).
- `TestConcurrentSendsNeverDuplicate` : deux envois simultanés, échec, réservation
  récente et expirée ; il échoue sans la réservation.
- Un job `notify.send` peut échouer brièvement (« envoi en cours ») sans conséquence :
  ses tentatives sont celles de la file (30).
