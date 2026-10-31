# 0012 — Isolement des organisations : RLS obligatoire, pas de schéma par organisation, lectures inter-organisations listées

- Statut : Accepté
- Date : 2026-10-31
- Lot : T03

## Contexte

Le § 9 de l'architecture impose la RLS forcée sur toute table d'organisation et réserve
les lectures inter-organisations à `internal/db/crossorg`. T03 crée les premières tables
d'organisation (`organizations`, `org_memberships`, `audit_events`) et la garde
d'organisation, qui doit résoudre un slug et l'appartenance **avant** de connaître
l'organisation à déclarer. Trois points restaient à fixer : l'alternative du schéma par
organisation (écartée par le § 9, à motiver ici), le moyen pour une fonction
`SECURITY DEFINER` de lire au-delà de l'organisation déclarée alors que la RLS est
forcée, et la liste initiale de ces fonctions.

## Décision

- **RLS obligatoire** sur toute table d'organisation, posée par
  `ogsbom_enforce_org_rls` et vérifiée au démarrage (ADR 0010). Une organisation inconnue,
  archivée ou dont le compte n'est pas membre répond **404**, jamais 403.
- **Pas de schéma par organisation**, pour les raisons du § 9 : l'isolement reposerait
  sur un `search_path` correct (la discipline qu'on veut éviter) ou sur un rôle et un
  pool par organisation ; les migrations seraient rejouées par organisation ; créer une
  organisation exigerait du DDL à chaud, donc des droits de DDL pour l'application ; les
  traitements de toutes les organisations passeraient par du SQL dynamique ; le gain de
  volume est nul à l'échelle visée (les index commencent par `org_id`). Si une
  organisation devient très volumineuse, le partitionnement par `org_id` donne la même
  séparation physique en gardant la RLS.
- **Le rôle propriétaire a l'attribut `BYPASSRLS`** **[à relire]**. La RLS étant
  *forcée*, le propriétaire y est soumis : une fonction `SECURITY DEFINER` qu'il possède
  ne verrait rien sans organisation déclarée. `BYPASSRLS` ne lui donne aucun pouvoir
  nouveau (il peut déjà désactiver la RLS de ses tables), il ne sert qu'au moment de la
  migration, et le rôle d'exécution, lui, est toujours refusé s'il l'a ou s'il est membre
  d'un rôle qui l'a. La migration 005 échoue avec un message explicite si le propriétaire
  n'a pas l'attribut.
- **Fonctions de `crossorg`** (migration 005), `SECURITY DEFINER`, `search_path` fixé,
  `STABLE`, et ce qu'elles renvoient :

  | Fonction | Usage | Renvoie |
  | --- | --- | --- |
  | `ogsbom_org_access(slug, user_id)` | garde `/o/{slug}` | id, slug, nom, langue, rôle — si membre et organisation active, sinon rien |
  | `ogsbom_user_orgs(user_id)` | sélecteur d'organisation, organisation par défaut | id, slug, nom, rôle des organisations actives du compte (200 au plus) |
  | `ogsbom_list_organizations(after, limit)` | administration de l'instance | métadonnées (id, slug, nom, langue, archivage, création, nombre de membres), page bornée à 200 |
  | `ogsbom_org_id_by_slug(slug)` | administration de l'instance | l'identifiant seul |
  | `ogsbom_agent_token_org(public_id)` | API des agents (T04, ADR 0014, migration 007) | l'identifiant de l'organisation active du jeton d'agent, rien sinon |
  | `ogsbom_enrollment_token_org(public_id)` | inscription d'un agent serveur (T04, ADR 0014, migration 007) | l'identifiant de l'organisation active du jeton d'inscription, rien sinon |
  | `ogsbom_search_component_names(query, limit)` | recherche par nom (T09, ADR 0024, migration 013) | identifiants des composants de l'organisation **déclarée par InOrg** (`ogsbom.org_id`, jamais en paramètre), 1 001 au plus ; échoue hors InOrg |
  | `ogsbom_search_component_hashes(hash, limit)` | recherche par empreinte (T09, ADR 0024, migration 013) | idem, composants portant l'empreinte |

  Aucune ne renvoie de donnée métier. Les deux dernières sont appelables par le rôle
  d'exécution comme les autres : c'est le code Go (`requireInstanceAdmin`) qui les réserve
  aux administrateurs d'instance, comme le prévoit le rôle privilégié assumé du § 10.
- **Règle de revue** : tout ajout à `crossorg` est un changement de sécurité, inscrit
  dans ce tableau (nouvel ADR qui remplace celui-ci si la règle change) et dans le
  Journal du lot qui l'ajoute ; il ne renvoie que des métadonnées, jamais une ligne
  métier entière.
- **Harnais d'isolement**, à étendre par chaque lot : `internal/db/orgtables_integration_test.go`
  (liste des tables d'organisation, contrôlée contre le catalogue) et
  `internal/web/isolation_integration_test.go` (parcours de toutes les routes de
  `/o/{slug}`, et refus de toute route hors de `/o/{slug}` non déclarée globale).

## Conséquences

- Une nouvelle table d'organisation qui manque au harnais fait échouer les tests ; une
  nouvelle route d'organisation est testée sans rien écrire de plus.
- L'installation d'une base existante demande `ALTER ROLE ogsbom_owner BYPASSRLS` en
  superutilisateur (docs/operations.md).
- La clé étrangère `account_settings.default_org_id` vers `organizations` est contrôlée
  par PostgreSQL hors RLS ; elle ne révèle rien (la préférence est validée par
  `ogsbom_user_orgs`).

## Alternatives écartées

- **Schéma par organisation** : voir ci-dessus.
- **Rôle dédié `NOLOGIN BYPASSRLS` propriétaire des seules fonctions** : plus étroit,
  mais sa création exige un superutilisateur à chaque installation et ne protège de rien
  de plus que le propriétaire, qui possède déjà les tables.
- **Annuaire global (slug → id) sans RLS** pour la garde : il recopierait des métadonnées
  d'organisation dans une table globale et n'éviterait pas une fonction inter-organisations
  pour le sélecteur.
- **`set_config` de chaque organisation en boucle** dans une fonction : SQL dynamique,
  coûteux et fragile, pour le même résultat.
