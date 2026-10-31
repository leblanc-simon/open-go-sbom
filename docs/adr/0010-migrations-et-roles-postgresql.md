# 0010 — Exécuteur de migrations, droits du rôle d'exécution et contrôle de la RLS

- Statut : Accepté
- Date : 2026-10-31
- Lot : T01

## Contexte

Le § 7 de l'architecture fixe deux rôles PostgreSQL (propriétaire qui migre, rôle
d'exécution sans privilège de DDL), un verrou de migration par `LOCK TABLE` sur une
connexion dédiée, et l'immuabilité des migrations publiées. Restaient à trancher :
comment les migrations, figées, accordent leurs droits à un rôle d'exécution dont le nom
varie (`ogsbom_app` par défaut, rôles jetables dans les tests) ; la granularité des
transactions ; et comment garantir, au-delà de la relecture, que chaque table
d'organisation porte la RLS standard.

## Décision

- **Rôle d'exécution** : son nom est lu dans `database.dsn` (utilisateur de la
  connexion), sans réglage supplémentaire. L'exécuteur le déclare dans le paramètre
  `ogsbom.app_role`, propre à la transaction ; les migrations le lisent par
  `current_setting` et le citent par `format('%I')`. Aucune substitution de texte dans
  les fichiers, dont la somme reste celle du fichier publié.
- **001_init.sql** pose les privilèges par défaut du propriétaire : `SELECT`, `INSERT`,
  `UPDATE`, `DELETE` sur les tables, `USAGE`, `SELECT` sur les séquences, `EXECUTE` sur
  les fonctions, retiré à `PUBLIC`. Ces privilèges sont globaux (sans `IN SCHEMA`), seul
  moyen de retirer `EXECUTE` à `PUBLIC`. Elle crée la procédure
  `ogsbom_enforce_org_rls(table, colonne)` qui active et force la RLS et crée la politique
  standard `org_isolation`, réservée aux migrations.
- **Table de suivi** `ogsbom_schema_migrations` (version, nom, somme SHA-256, date) :
  créée par l'exécuteur sous un verrou consultatif de transaction (deux `CREATE TABLE IF
  NOT EXISTS` concurrents peuvent échouer sur le catalogue), avec `SELECT` accordé au
  rôle d'exécution pour qu'il vérifie le schéma (`/readyz`, démarrage sans migration).
- **Transactions** : la transaction du verrou porte aussi toutes les migrations du projet
  en attente, leur enregistrement et la validation finale : tout ou rien. Les étapes
  externes (authx, mfax en T03) tournent sous le verrou sur une autre connexion du pool,
  d'où le minimum de deux connexions. Conséquence : une migration du projet ne peut pas
  contenir d'instruction interdite en transaction (`CREATE INDEX CONCURRENTLY`) ; le
  besoin, s'il apparaît, fera l'objet d'un nouvel ADR.
- **Validation** : avant de valider, `CheckOrgIsolation` lit le catalogue et refuse toute
  table qui a une colonne `org_id NOT NULL` (ou la table `organizations`) sans RLS
  activée et forcée, sans politique `org_isolation` fondée sur `ogsbom.org_id`, ou avec
  une politique permissive qui ne l'est pas. Une table globale à `org_id` facultatif
  (`jobs`) n'est pas concernée.
- **Démarrage** (`db.Start`) : attente bornée de la base, migration si
  `migration.dsn` est fourni (pool fermé ensuite), contrôle du rôle d'exécution
  (superutilisateur, `BYPASSRLS`, propriétaire ou membre d'un rôle propriétaire d'une
  relation, membre d'un rôle superutilisateur ou `BYPASSRLS` : refus), puis vérification
  que toutes les migrations embarquées sont appliquées avec la même somme. Sans
  `migration.dsn`, une instance refuse de démarrer sur un schéma en retard.

## Conséquences

- L'oubli de la RLS sur une nouvelle table d'organisation empêche le démarrage, en test
  comme en production : l'isolement est vérifié, pas seulement relu.
- Changer de rôle d'exécution après coup demande d'accorder à la main les droits sur les
  objets existants et les privilèges par défaut (procédure dans `docs/operations.md`).
- Une base migrée par une version plus récente (migration inconnue) est refusée par un
  binaire plus ancien.

## Alternatives écartées

- Nom du rôle en dur (`ogsbom_app`) dans les migrations : incompatible avec les rôles
  jetables des tests parallèles et avec un nommage propre à l'exploitant.
- Gabarits textuels dans les fichiers de migration : la somme vérifiée ne serait plus
  celle du SQL exécuté, et l'échappement des identifiants reposerait sur le code Go.
- Une transaction par migration, enregistrée sur la connexion du verrou : le verrou
  `EXCLUSIVE` bloque l'enregistrement fait depuis une autre connexion, et un arrêt entre
  deux transactions laisserait une migration appliquée mais non enregistrée.
- Rôle de groupe partagé recevant les droits : les rôles sont globaux au serveur
  PostgreSQL, ce qui ferait se télescoper les tests parallèles.
