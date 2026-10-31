# 0002 — PostgreSQL seul, pilote pgx derrière database/sql

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Le serveur a besoin d'isolement des organisations garanti par la base (RLS), de
`SKIP LOCKED` pour la file de traitements, de recherche par trigrammes et d'upserts en lot.
Les stores d'authx et de mfax (open-go-base) prennent un `*sql.DB` et choisissent leur
dialecte par `appconf.Database.Driver`.

## Décision

- PostgreSQL 16 ou plus est le seul moteur supporté.
- Le pool est un `*sql.DB` ouvert avec le pilote `github.com/jackc/pgx/v5/stdlib`
  (v5.12.0 au moment de la décision), partagé par authx, mfax et le code du projet.
- `Database.Driver` vaut `postgres` pour qu'open-go-base choisisse le dialecte PostgreSQL.
- Les tableaux passent en slices Go encodées par pgx, sans `lib/pq` ; le premier store qui
  en utilise (T01) vérifie par un test d'intégration l'encodage de chaque type employé.

## Conséquences

- Une seule interface d'accès (`database/sql`) dans tout le code ; les fonctions propres à
  pgx (COPY, types pgtype) restent accessibles par `stdlib.AcquireConn` si une mesure le
  justifie.
- Pas de SQLite, même pour les tests : les tests d'intégration tournent sur un vrai
  PostgreSQL (§ 21 de l'architecture).

## Alternatives écartées

- `pgxpool` natif : plus rapide, mais authx et mfax exigent `*sql.DB` ; deux pools
  doubleraient les connexions.
- `lib/pq` : en maintenance, sans avantage sur pgx.
- Support de plusieurs moteurs : la RLS, `SKIP LOCKED` et les trigrammes sont au cœur du
  produit.
