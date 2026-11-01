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
| [0017](0017-base-grype-commune.md) | Base Grype commune : archives en blocs dans PostgreSQL, cible, copie locale par instance | Accepté |
| [0018](0018-analyse-et-constats.md) | Analyse et constats : correspondance hors transaction, écriture sous verrou, identifiants CVE | Accepté |
| [0019](0019-mesures-et-autoanalyse.md) | Mesures de référence et autoanalyse en CI | Accepté |
| [0020](0020-agent-serveur-envoi-conditionnel.md) | Agent serveur : envoi conditionnel confirmé par le serveur, scan à la demande, état muet | Accepté |
| [0021](0021-deploiement-agent-serveur.md) | Déploiement de l'agent serveur : moindre privilège, secrets, mTLS, paquets | Accepté |
| [0023](0023-agent-depot.md) | Pipeline de l'agent dépôt et accès aux forges : webhook comme signal, extraction d'un commit précis, scan hors ligne, SBOM déterministe | Accepté |
| [0024](0024-recherche-transverse.md) | Recherche transverse : index sous la RLS, plan d'exécution, pagination et export | Accepté |
| [0025](0025-jetons-d-acces-personnels.md) | Jetons d'accès personnels : donnée du compte, lecture seule, appartenance vérifiée à chaque requête | Accepté |
| [0026](0026-comparaison-de-versions.md) | Comparaison de versions par écosystème et plages vers | Accepté |
| [0027](0027-tableau-de-bord.md) | Tableau de bord : indicateurs instantanés, statistiques quotidiennes, graphiques SVG | Accepté |
| [0028](0028-administration-de-la-base-et-des-traitements.md) | Administration de l'instance : import d'une archive par PostgreSQL, état des instances, purge, traitements en échec | Accepté |
| [0029](0029-remediation-des-identifiants.md) | Identifiants : verrouillage par compte, révocation d'office, réinitialisation avec mot de passe, durée absolue de session | Accepté |
| [0030](0030-durcissement-base-et-quotas.md) | Durcissement de la base et bornes de ressources : journal en ajout seul, rôle sans DDL, quotas d'ingestion, plafonds par compte | Accepté |
| [0031](0031-csrf-cookies-et-perimetre-de-l-agent-depot.md) | CSRF lié à la session, cookies __Host-, protection inter-origines ; périmètre de l'agent dépôt | Accepté |
| [0032](0032-publication-des-versions.md) | Publication des versions : étiquette, workflow de préversion, fichiers livrés, unité du serveur | Accepté |
| [0033](0033-renommage-en-lotor.md) | Renommage du projet en lotor : correspondance unique, migrations réécrites avant toute publication, identité visuelle | Accepté |
| [0034](0034-equipes-et-droits.md) | Équipes et droits : rôle d'organisation membre ou administrateur, droits par équipe, filtre d'équipe déclaré à la transaction, invitations | Accepté |
| [0042](0042-fournisseurs-de-modeles.md) | Fournisseurs de modèles : SDK Go officiel d'Anthropic sans environnement, Ollama par HTTP | Accepté |
| [0043](0043-enrichissement-ia-prouve.md) | Enrichissement IA prouvé : réglage par projet, politique d'envoi de code, vérificateur, statut | Accepté |
| [0044](0044-confinement-de-l-analyse-ia.md) | Confinement de l'analyse IA : os.Root et surface d'outils, sans processus fils | Accepté |
