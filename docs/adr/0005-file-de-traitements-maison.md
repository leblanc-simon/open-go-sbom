# 0005 — File de traitements maison sur PostgreSQL

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Le serveur met en file ingestions, analyses et réanalyses, dans la transaction qui produit
la donnée (§ 16 de l'architecture). Besoins : au moins une fois, baux renouvelés,
réessais à délai exponentiel, priorité relevée par une seconde mise en file (clé
d'unicité), plafond de jobs simultanés par organisation, planificateur à une seule
exécution par échéance, compatible pgbouncer en mode session.

## Décision

`internal/jobs` implémente la file sur PostgreSQL avec `database/sql`, sans dépendance :
table `jobs` globale, prise par `SELECT … FOR UPDATE SKIP LOCKED`, bail `locked_until`,
`ON CONFLICT … DO UPDATE` pour la clé d'unicité, table `schedules` pour le planificateur
(prise d'échéance par `UPDATE … RETURNING`, sans verrou de session).

## Conséquences

Environ quelques centaines de lignes à maintenir, couvertes par des tests d'intégration
et un test de charge court (T02). Mise en file transactionnelle sans adaptation : le job
est une ligne insérée avec la donnée.

## Alternatives écartées

- River : excellent, mais conçu d'abord pour `pgx` natif (son pilote `database/sql` est
  limité), avec ses propres tables et migrations, et sans plafond de jobs simultanés par
  organisation.
- File externe (Redis, NATS) : second système à exploiter, et perte de la mise en file
  dans la même transaction.
