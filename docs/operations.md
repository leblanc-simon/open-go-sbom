# Exploitation d'ogsbom-server

Installation, configuration et surveillance du serveur. Ce document grandit avec les lots :
sauvegarde, mise à jour, sites isolés et procédures de secours des administrateurs y
seront ajoutés par les lots qui les portent.

## Installation de développement

Prérequis : Go 1.26 (la chaîne exacte est téléchargée d'après `go.mod`), `make`,
PostgreSQL 16 ou plus.

1. PostgreSQL : `docker compose -f deploy/compose.yaml up -d` démarre un PostgreSQL 16 et
   crée la base `ogsbom`, le rôle propriétaire `ogsbom_owner` et le rôle d'exécution
   `ogsbom_app` (`deploy/initdb/01-roles.sql`, mots de passe de développement). Sur un
   PostgreSQL déjà installé, voir « Rôles et droits » ci-dessous.
2. Configuration : `cp config.example.yaml config.yaml` (valeurs prévues pour
   `deploy/compose.yaml`).
3. `make run` construit les binaires et lance `bin/ogsbom-server -c config.yaml`.
   L'interface répond sur <http://127.0.0.1:8080/>, la gestion sur
   <http://127.0.0.1:8081/readyz>.

Tests : `make test` (unitaires), `make test-integration` (PostgreSQL requis : chaque test
crée sa base et ses rôles jetables à partir de `OGSBOM_TEST_DATABASE_DSN`, connexion
d'administration, par défaut celle de `deploy/compose.yaml`), `make ci` (tout ce que fait
la CI).

## Configuration

Le serveur lit le fichier YAML désigné par `-c` (`config.yaml` par défaut) s'il existe,
sinon l'environnement. Chaque clé a sa variable `OGSBOM_*`, qui l'emporte sur le fichier ;
`ogsbom-server --help` les liste toutes avec leur description, et
[`config.example.yaml`](../config.example.yaml) les documente. Une configuration invalide
arrête le démarrage (code de sortie 2) avec un message par champ fautif, par exemple :

```
database.driver (OGSBOM_DB_DRIVER) : doit valoir « postgres » (reçu "sqlite")
```

Défauts propres au projet, qui s'appliquent bien que `--help` affiche ceux
d'open-go-base : `database.driver` vaut `postgres`, `i18n.default_language` `fr`,
`logging.level` `info`. `i18n.dir` est sans effet : les traductions sont embarquées.

Les secrets (DSN avec mot de passe, clés de chiffrement) se donnent de préférence par
variables d'environnement, par exemple depuis un fichier d'environnement de systemd en
`0600`, plutôt que dans le fichier de configuration.

## Base de données

### Rôles et droits

Deux rôles PostgreSQL :

- le **propriétaire** possède la base et le schéma ; il n'est utilisé que pour migrer
  (`migration.dsn`), au démarrage. Il a l'attribut `BYPASSRLS` : les fonctions
  inter-organisations qu'il possède (garde d'organisation, sélecteur) en dépendent, la
  RLS étant forcée jusque pour lui (ADR 0012). La migration échoue sans lui ;
- le **rôle d'exécution** fait tourner l'application (`database.dsn`) avec `SELECT`,
  `INSERT`, `UPDATE`, `DELETE` seulement. Il ne doit être ni superutilisateur, ni
  `BYPASSRLS`, ni propriétaire des tables, ni membre d'un rôle qui l'est : le serveur
  refuse sinon de démarrer, car la séparation des organisations repose sur la sécurité
  au niveau des lignes (RLS) de PostgreSQL.

Création sur un PostgreSQL existant (en superutilisateur) :

```sql
CREATE ROLE ogsbom_owner LOGIN BYPASSRLS PASSWORD '…';
-- base existante créée avant T03 : ALTER ROLE ogsbom_owner BYPASSRLS;
CREATE ROLE ogsbom_app LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE DATABASE ogsbom OWNER ogsbom_owner;
REVOKE ALL ON DATABASE ogsbom FROM PUBLIC;
GRANT CONNECT ON DATABASE ogsbom TO ogsbom_app;
```

Les droits du rôle d'exécution sur les tables sont posés par les migrations (privilèges
par défaut du propriétaire, ADR 0010) : rien d'autre à accorder. Son nom est lu dans
`database.dsn`.

Changer de rôle d'exécution après coup (nouveau nom) : en propriétaire, accorder au
nouveau rôle les droits sur l'existant et les privilèges par défaut, puis retirer
l'ancien :

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nouveau;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nouveau;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nouveau;
REVOKE INSERT, UPDATE, DELETE ON ogsbom_schema_migrations FROM nouveau;
REVOKE EXECUTE ON PROCEDURE ogsbom_enforce_org_rls(regclass, name) FROM nouveau;
ALTER DEFAULT PRIVILEGES GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nouveau;
ALTER DEFAULT PRIVILEGES GRANT USAGE, SELECT ON SEQUENCES TO nouveau;
ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO nouveau;
```

### Connexion

Connexion directe, ou pgbouncer en mode **session** (le mode transaction est incompatible
avec le verrou de migration). Chaque connexion est réglée en UTC. Le pool se règle par
`database.max_open_conns`, `max_idle_conns` et `conn_max_lifetime`. Au démarrage, le
serveur attend la base au plus `database.startup_timeout`.

### Migrations

Au démarrage, si `migration.dsn` est renseigné, le serveur applique les migrations
manquantes avec le rôle propriétaire, sous un verrou : plusieurs instances peuvent
démarrer ensemble, une seule migre, les autres attendent (au plus
`migration.lock_timeout`) puis constatent qu'il n'y a rien à faire. Toutes les
migrations en attente s'appliquent dans une seule transaction : tout ou rien.

Sans `migration.dsn`, le serveur ne migre pas et refuse de démarrer si le schéma n'est
pas à jour : on peut réserver la connexion du propriétaire à une seule instance, ou à un
lancement ponctuel lors d'une mise à jour.

Le serveur refuse aussi de démarrer si :

- une migration déjà appliquée a été modifiée depuis (somme SHA-256 différente de celle
  enregistrée dans `ogsbom_schema_migrations`) : les migrations publiées sont immuables ;
- la base porte une migration inconnue du binaire (base migrée par une version plus
  récente) ;
- une table d'organisation n'a pas la RLS forcée et sa politique standard.

## TLS et mandataire inverse

Deux modes :

- **TLS natif** : `tls.cert_file` et `tls.key_file` (PEM). TLS 1.2 minimum.
  `tls.client_ca_file` active la vérification des certificats clients des agents
  (mTLS) : un certificat présenté doit être signé par cette autorité.
- **Derrière un mandataire inverse** qui termine TLS (nginx, HAProxy, Caddy…) : le serveur
  écoute en HTTP sur `web.host:web.port`. Déclarer le mandataire dans
  `web.trusted_proxies` (CIDR) : seuls les mandataires listés peuvent indiquer l'IP du
  client (`X-Forwarded-For`, `X-Real-IP`, utilisés par la limitation de débit et les
  journaux) et le HTTPS (`X-Forwarded-Proto: https`). Le mTLS des agents est alors
  indisponible.

`Strict-Transport-Security` n'est envoyé que pour une requête arrivée en HTTPS (TLS natif
ou mandataire de confiance).

## Gestion : sondes et métriques

Une écoute séparée, `management.host:management.port` (par défaut `127.0.0.1:8081`), à ne
pas exposer publiquement :

| Chemin | Rôle |
| --- | --- |
| `/healthz` | vivacité : le processus répond (200), indépendamment de la base |
| `/readyz` | disponibilité : 200 si la base répond et si le schéma est à jour ; 503 sinon, avec la vérification en échec, et 503 dès le début d'un arrêt. La base Grype s'y ajoutera pour les instances à workers (T06). |
| `/metrics` | métriques Prometheus : `ogsbom_http_requests_total` et `ogsbom_http_request_duration_seconds` (par groupe de routes, méthode, motif de route, statut), file de traitements (`ogsbom_jobs`, `ogsbom_job_*`, voir « Traitements »), pool de connexions (`go_sql_*`), processus et moteur Go |

## Traitements

Ingestions, analyses et échéances passent par une file en base (tables `jobs` et
`schedules`), partagée par toutes les instances : n'importe quelle instance à workers
prend n'importe quel job, et un job survit au redémarrage de toutes les instances.

- `workers.enabled` (vrai par défaut) lance sur l'instance `workers.concurrency` workers
  (4) et le planificateur. `false` donne une instance purement web, par exemple pour
  qu'un envoi lourd ne ralentisse pas l'interface ; il faut alors au moins une autre
  instance à workers.
- **Au moins une fois** : un job pris pose un bail de `workers.lease` (30 s), renouvelé
  tant qu'il tourne. Si l'instance disparaît (panne, `SIGKILL`), le job est repris par une
  autre instance après expiration du bail. Les traitements sont conçus pour être rejoués
  sans dommage.
- **Réessais** : un job en échec est réessayé après `retry_base × 2^(n−1)` (10 s, 20 s,
  40 s…), plafonné à `workers.retry_max` (30 min), plus une gigue de 0 à 20 %. Après son
  nombre maximal de tentatives (10 par défaut), ou sur une erreur définitive, il passe au
  statut `dead` avec sa dernière erreur ; il y reste jusqu'à ce qu'un administrateur le
  relance ou le supprime (écran d'administration, T11).
- **Priorités et plafonds** : un job prioritaire (une ingestion fraîche) passe avant le
  travail de fond (réanalyse de toutes les références). Les types lourds sont plafonnés
  par organisation, toutes instances confondues : une organisation très active ne prive
  pas les autres.
- **Échéances** : chaque échéance (vérification de la base de vulnérabilités, statistiques
  quotidiennes…) est cherchée toutes les `workers.schedule_interval` (10 s) et n'est prise
  que par une seule instance, même si toutes tournent. Les échéances suivent une grille en
  UTC ; un point manqué pendant une panne générale est rattrapé une fois au redémarrage.
- **Rétention** : les jobs terminés sont purgés après `workers.retention` (7 jours).
- **Horloges** : baux et échéances se calculent avec l'horloge de chaque instance, qui
  doit être synchronisée (NTP ou équivalent).

Métriques (`/metrics`) :

| Métrique | Contenu |
| --- | --- |
| `ogsbom_jobs{kind, status}` | jobs en attente (`pending`), en cours (`running`) et morts (`dead`), lus en base : même valeur sur toutes les instances |
| `ogsbom_job_runs_total{kind, outcome}` | exécutions de l'instance : `done`, `retry` et `dead` (échecs), `lost` (bail perdu, résultat ignoré), `released` (interrompu par l'arrêt) |
| `ogsbom_job_duration_seconds{kind}` | durée des exécutions de l'instance |
| `ogsbom_job_schedule_fires_total{schedule}` | échéances prises par l'instance |

À surveiller : `ogsbom_jobs{status="dead"}` qui croît, `ogsbom_jobs{status="pending"}`
qui ne décroît pas (workers absents ou sous-dimensionnés), `outcome="lost"` fréquent
(bail trop court ou base saturée).

## Arrêt

Sur `SIGTERM` (ou `SIGINT`), le serveur passe `/readyz` à 503, cesse d'accepter des
connexions et laisse aux requêtes en cours `http.shutdown_timeout` (30 s par défaut) pour
finir ; au-delà, il ferme les connexions restantes. En même temps, les workers cessent de
prendre des jobs et laissent aux jobs en cours `workers.shutdown_timeout` (30 s) ; à
l'approche de ce délai, les jobs encore en cours sont interrompus et remis en attente,
sans que la tentative compte, pour qu'une autre instance les reprenne aussitôt. Code de
sortie 0 après un arrêt propre. Côté systemd, `TimeoutStopSec` doit dépasser le plus grand
de `http.shutdown_timeout` et `workers.shutdown_timeout`.

## Comptes et connexion

Tout compte local se connecte par mot de passe **et** code TOTP (enrôlement obligatoire à
la première connexion). Les mots de passe comptent 12 caractères au moins.

**Premier administrateur.** Sur une base sans compte, définir au premier démarrage
`OGSBOM_BOOTSTRAP_ADMIN_EMAIL` et `OGSBOM_BOOTSTRAP_ADMIN_PASSWORD` (mot de passe
temporaire). Le compte est créé administrateur d'instance ; à sa connexion, il enrôle son
TOTP puis choisit un nouveau mot de passe. Les variables sont ignorées dès qu'un compte
existe : les retirer ensuite (le journal le rappelle). Deux instances qui démarrent
ensemble ne créent qu'un compte.

**Comptes.** L'administration (`/admin`) crée les comptes avec un mot de passe temporaire
affiché une seule fois, les désactive, réinitialise leur mot de passe ou leur TOTP
(sessions fermées), nomme les administrateurs d'instance, crée et archive les
organisations. Chaque action est journalisée (`/admin/audit`). Garder **deux
administrateurs d'instance au moins** : l'interface avertit s'il n'y en a qu'un.

**Procédure de secours** (administrateur unique qui a perdu son TOTP) :

1. Ouvrir un ticket d'incident et choisir sa référence (8 caractères au moins, par
   exemple `INC-2026-0042`).
2. Redémarrer le serveur avec `OGSBOM_BOOTSTRAP_RESCUE_TOTP_EMAIL=<e-mail de
   l'administrateur>` et `OGSBOM_BOOTSTRAP_RESCUE_TICKET=<référence>`. Le TOTP de ce
   compte est retiré et ses sessions fermées ; l'événement « procédure de secours » entre
   au journal d'audit avec la référence. Le compte doit être un administrateur d'instance
   actif, sinon le serveur refuse de démarrer.
3. L'administrateur se connecte avec son mot de passe et enrôle un nouveau TOTP.
4. Retirer les deux variables. Laissées en place, elles n'ont plus d'effet (un ticket ne
   s'applique qu'une fois) et le journal le signale à chaque démarrage. Un nouvel incident
   demande une nouvelle référence.

Un administrateur qui a perdu son mot de passe se le fait réinitialiser par un autre
administrateur. La procédure de secours ne couvre que le TOTP : un administrateur unique
qui perd aussi son mot de passe relève d'une intervention en base, hors de l'application
(à éviter en gardant deux administrateurs).

**Limitation.** `login.rate_limit` (10 par défaut) borne les `POST` de `/login` et
`/login/2fa` par minute et par IP, en plus de `web.rate_limit`. Un défi TOTP tolère
`mfa.max_attempts` codes faux. Les sessions et défis expirés sont purgés toutes les
heures (job `auth.purge`, instances à workers).

## Clés de chiffrement des secrets

Les secrets stockés en base (canaux de notification, OIDC, dans les lots qui les
introduisent) sont chiffrés en AES-256-GCM par des clés nommées :
`secrets.keys` (`OGSBOM_SECRETS_KEYS=id:base64,…`) et `secrets.active_key`. Générer une
clé : `openssl rand -base64 32`. Un nom de clé : minuscules, chiffres, `-` et `_`, 32
caractères au plus (par exemple la date : `2026-10`).

Les clés sont **obligatoires** : les secrets TOTP des comptes sont chiffrés en base. Les
perdre toutes impose de réinitialiser le TOTP de chaque compte.

Rotation : ajouter la nouvelle clé à côté de l'ancienne, la désigner comme active,
redémarrer ; les nouveaux secrets sont chiffrés avec elle, les anciens restent lisibles.
Au démarrage, le serveur rechiffre les secrets TOTP avec la clé active (le journal donne
leur nombre) : l'ancienne clé peut être retirée au démarrage suivant.

## Journaux

Journaux `slog` sur la sortie d'erreur, au format `logging.format` (`json` en production).
Chaque requête est journalisée avec `request_id` (renvoyé au client dans `X-Request-Id`
et affiché sur les pages d'erreur), méthode, chemin sans la chaîne de requête, motif de
route, statut, taille, durée et IP du client. Aucun mot de passe, jeton, secret ni contenu
de SBOM n'y figure.
