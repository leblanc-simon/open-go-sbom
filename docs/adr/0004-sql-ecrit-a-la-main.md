# 0004 — Requêtes SQL écrites à la main

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Décision du 31 octobre 2026 : sqlc si les tableaux passent sans `lib/pq` avec le pilote
pgx derrière `database/sql`, sinon SQL écrit à la main. Exploration menée avec sqlc
v1.31.1 (programme jetable, non conservé) :

- schéma `components (org_id uuid, id uuid, purl text)` et deux requêtes à tableaux :
  `INSERT … SELECT unnest(@ids::uuid[]), unnest(@purls::text[])` et
  `WHERE purl = ANY(@purls::text[])` ;
- configuration `engine: postgresql`, `sql_package: database/sql` (le mode
  `pgx/v5` génère du code pour `pgx.Conn` / `pgxpool`, incompatible avec le `*sql.DB`
  partagé avec authx et mfax, ADR 0002) ;
- résultat : le code généré importe `github.com/lib/pq` et enveloppe chaque tableau dans
  `pq.Array(...)`. Aucune option de sqlc ne le remplace.

Constats annexes : sqlc se construit sans CGO (`CGO_ENABLED=0`) et ajoute environ 130
lignes à `go.sum` ; la directive `tool` aurait été possible.

## Décision

Les requêtes sont écrites à la main, dans le store de chaque paquet, avec `database/sql`
et le pilote pgx. Règles :

- requêtes en constantes nommées, paramètres positionnels `$n`, jamais de concaténation
  de valeurs ;
- les requêtes dynamiques (recherche) sont assemblées par un petit constructeur local au
  paquet qui ne concatène que des fragments constants et numérote les paramètres ;
- chaque requête est couverte par un test d'intégration PostgreSQL ;
- les tableaux passent en slices Go, que pgx encode nativement.

## Conséquences

Pas de vérification à la compilation du lien entre requête et schéma : les tests
d'intégration du store la remplacent, et sont exigés en revue. Pas de dépendance à
`lib/pq`, pas de générateur de plus.

## Alternatives écartées

- sqlc en `database/sql` : dépendance à `lib/pq` (pilote en maintenance, second encodage
  des tableaux à côté de pgx).
- sqlc en mode `pgx/v5` : impose un second pool natif à côté du `*sql.DB` d'open-go-base.
- ORM (GORM, ent, bun) : opaque pour la RLS et les plans de requête, dépendances lourdes.
