# Décisions d'architecture (ADR)

Une décision structurante = un ADR, écrit dans le commit qui l'applique (règle : ADR 0001).
Gabarit : [`0000-gabarit.md`](0000-gabarit.md). Un ADR accepté ne se réécrit pas : une
décision contraire fait l'objet d'un nouvel ADR qui le remplace.

| N° | Titre | Statut |
| --- | --- | --- |
| [0001](0001-format-des-adr.md) | Format des ADR | Accepté |
| [0002](0002-postgresql-pgx.md) | PostgreSQL seul, pilote pgx derrière database/sql | Accepté |
| [0003](0003-routeur-chi.md) | Routeur chi | Accepté |
| [0004](0004-sql-ecrit-a-la-main.md) | Requêtes SQL écrites à la main | Accepté |
| [0005](0005-file-de-traitements-maison.md) | File de traitements maison sur PostgreSQL | Accepté |
| [0006](0006-api-openapi-oapi-codegen.md) | API conçue en OpenAPI 3.1, code généré par oapi-codegen | Accepté |
| [0007](0007-adaptateurs-anchore.md) | Bibliothèques d'Anchore derrière des adaptateurs | Accepté |
| [0008](0008-front-sans-chaine-de-construction.md) | Interface sans chaîne de construction front | Accepté |
