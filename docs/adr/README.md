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
| [0009](0009-fonctions-de-gabarit-par-langue.md) | Fonctions de gabarit dépendantes de la requête : un jeu de gabarits par langue | Accepté |
| [0010](0010-migrations-et-roles-postgresql.md) | Exécuteur de migrations, droits du rôle d'exécution et contrôle de la RLS | Accepté |
| [0011](0011-conception-de-la-file.md) | Conception de la file de traitements : horloge, prise, plafond, arrêt | Accepté |
| [0012](0012-isolement-des-organisations.md) | Isolement des organisations : RLS obligatoire, pas de schéma par organisation, lectures inter-organisations listées | Accepté |
| [0013](0013-comptes-et-second-facteur.md) | Comptes et second facteur : secrets TOTP chiffrés, méthode de session, secours par ticket | Accepté |
| [0014](0014-jetons-et-api-des-agents.md) | Jetons et API des agents : format, résolution de l'organisation, limitation par jeton | Accepté |
| [0015](0015-decodage-des-sbom-dans-le-worker.md) | Décodage des SBOM dans le processus worker, sous bornes préalables, plutôt qu'en sous-processus | Accepté |
| [0016](0016-ingestion-et-inventaire.md) | Ingestion et inventaire : identité des composants, empreinte, règles d'instantané, validation | Accepté |
| [0020](0020-agent-serveur-envoi-conditionnel.md) | Agent serveur : envoi conditionnel confirmé par le serveur, scan à la demande, état muet | Accepté |
| [0021](0021-deploiement-agent-serveur.md) | Déploiement de l'agent serveur : moindre privilège, secrets, mTLS, paquets | Accepté |
