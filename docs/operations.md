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
  `tls.client_ca_file` active le mTLS des agents : un certificat présenté doit être
  signé par cette autorité, et toute requête de l'API des agents (`/api/v1/agent/*`) sans
  certificat client vérifié est refusée (401 `error.client_cert_required`), avant la
  lecture du jeton. L'interface web, servie par la même écoute, n'en demande pas.
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
| `/readyz` | disponibilité : 200 si la base répond et si le schéma est à jour ; 503 sinon, avec la vérification en échec, et 503 dès le début d'un arrêt. Sur une instance à workers (`workers.enabled`), 503 aussi tant qu'aucune base de vulnérabilités n'est chargée (vérification `vulndb`). |
| `/metrics` | métriques Prometheus : `ogsbom_http_requests_total` et `ogsbom_http_request_duration_seconds` (par groupe de routes, méthode, motif de route, statut), file de traitements (`ogsbom_jobs`, `ogsbom_job_*`, voir « Traitements »), base de vulnérabilités (`ogsbom_vulndb_target_age_seconds`, `ogsbom_vulndb_stale`, `ogsbom_vulndb_loaded`, voir « Base de vulnérabilités »), pool de connexions (`go_sql_*`), processus et moteur Go |

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
  travail de fond (réanalyse de toutes les références). Les types lourds (décodage des
  SBOM, analyses) sont plafonnés à `workers.org_limit` (2) jobs simultanés par
  organisation, toutes instances confondues : une organisation très active ne prive pas
  les autres.
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

## Agents et jetons

Les écrans **Projets** et **Agents** d'une organisation (`/o/<slug>/projects`,
`/o/<slug>/agents`) sont réservés en écriture à ses administrateurs.

- **Agent serveur** (`ogsbom-host-agent`, T07) : créer un **jeton d'inscription**
  (« Inscrire des serveurs ») : validité (1 heure à 30 jours), nombre d'usages (un par
  hôte), étiquettes des projets créés, ou projet de serveur existant à rattacher. Chaque
  hôte l'échange contre son propre jeton d'agent (`POST /api/v1/agent/enroll`) ; le
  serveur crée le projet de l'hôte, ou rattache l'agent au projet désigné, ou au projet
  qui suit déjà ce nom d'hôte s'il n'a plus d'agent actif.
- **Agent dépôt** (`ogsbom-repo-agent`, T08) : « Nouvel agent dépôt » crée l'agent et son
  premier jeton ; les dépôts lui sont confiés depuis leur fiche.
- Un jeton n'est **affiché qu'une fois** ; seul son SHA-256 est conservé. Le fournir à
  l'agent par un fichier en `0600` ou un credential systemd, jamais dans un fichier de
  configuration. **Rotation** : créer un second jeton sur la fiche de l'agent, le
  déployer, vérifier sa date de dernière utilisation, révoquer l'ancien. Une révocation
  vaut dès la requête suivante.
- **Désactiver** un agent révoque ses jetons et lui retire ses projets ; un hôte peut
  ensuite s'inscrire de nouveau sous le même nom.
- **Limitation** : `agent_api.rate_limit` (120 par défaut) borne les requêtes par minute et
  **par jeton**, `agent_api.failure_rate_limit` (30) les jetons refusés par minute et par
  IP. Au-delà : 429 avec `Retry-After`. Ces compteurs sont propres à chaque instance.
- Un agent est dit **muet** après 3 jours : sans inventaire de son hôte pour un agent
  serveur (même s'il répond encore : envois refusés, scans en échec), sans contact pour un
  agent dépôt.

## Agent serveur

`ogsbom-host-agent` inventorie un hôte Linux (amd64, arm64) avec Syft et n'envoie un SBOM
que lorsque l'inventaire a changé (ADR 0020, 0021).

### Installation

1. Installer le paquet (`make packages` produit dans `dist/` les paquets deb et rpm des
   deux architectures, non signés) : `sudo apt install ./ogsbom-host-agent_<version>_amd64.deb`
   ou `sudo dnf install ./ogsbom-host-agent-<version>.x86_64.rpm`. Le paquet crée
   l'utilisateur système `ogsbom-agent`, `/etc/ogsbom-host-agent/config.yaml`, les unités
   systemd ; il n'en active aucune.
2. Renseigner `server.url` (`https://…` seulement) dans la configuration, et au besoin
   `server.ca_file` (autorité privée, qui remplace celles du système), `server.proxy`,
   `server.client_cert_file` (mTLS), `labels`, `scan.exclude`. Chaque clé a sa variable
   `OGSBOM_HOST_AGENT_*` (`ogsbom-host-agent --help`).
3. Déposer le **jeton d'inscription** (« Inscrire des serveurs », l'écran qui l'affiche
   donne ces commandes), lisible du seul agent :
   `printf '%s' '<jeton>' | sudo install -m 0600 -o ogsbom-agent -g ogsbom-agent /dev/stdin /etc/ogsbom-host-agent/enrollment-token`.
   Variante chiffrée : `printf '%s' '<jeton>' | sudo systemd-creds encrypt --name=enrollment-token - /etc/ogsbom-host-agent/enrollment-token.cred`,
   puis `sudo systemctl edit ogsbom-host-agent` et
   `LoadCredentialEncrypted=enrollment-token:/etc/ogsbom-host-agent/enrollment-token.cred`.
   La clé du certificat client suit le même chemin (fichier `server.client_key_file` en
   `0600`, ou credential `client-key`). Un fichier secret lisible par le groupe ou les
   autres est refusé.
4. Démarrer **une** des deux formes : `sudo systemctl enable --now ogsbom-host-agent.service`
   (démon : un scan par `scan.interval`, 24 h, et un signal de vie par
   `scan.poll_interval`, 5 min, qui reçoit les demandes « Scanner maintenant ») ou
   `sudo systemctl enable --now ogsbom-host-agent-oneshot.timer` (un scan par jour vers 2 h,
   heure tirée dans l'heure ; une demande de scan attend le passage suivant).
5. Au premier cycle, l'agent s'inscrit et garde son jeton d'agent dans
   `/var/lib/ogsbom-host-agent/agent-token` (`0600`) ; supprimer ensuite le jeton
   d'inscription. L'hôte apparaît dans les projets avec son contexte (système, noyau,
   architecture, durée du scan).

### Fonctionnement

- **Scan** de `/` avec les catalogueurs d'un système installé (dpkg, rpm, apk, paquets
  Python, Ruby, Node.js installés, archives Java, binaires Go et Rust), sans catalogage de
  fichiers. **Exclus** : `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, les stockages de
  Docker, Podman (y compris sans root, `~/.local/share/containers`), containerd, kubelet,
  LXC/LXD, Rancher, les montages réseau (NFS, CIFS, sshfs, Ceph…), de conteneurs
  (overlay…) et autofs, plus `scan.exclude`. Les images de conteneurs relèvent de T13.
- **Envoi conditionnel** : l'empreinte d'inventaire du SBOM est calculée comme par le
  serveur. Inchangée, l'agent envoie un signal de vie avec son empreinte ; le serveur
  avance la date de dernière analyse, ou réclame le SBOM s'il ne connaît pas cet
  inventaire. Changée, le SBOM part (Syft JSON compressé) et l'agent attend son rangement.
- **Réessais** : `server.retries` tentatives (erreurs réseau, 429, 5xx), délai
  exponentiel, `Retry-After` respecté. Un SBOM refusé (`error.ingest.*`) est renvoyé au
  cycle suivant ; un jeton refusé (401) demande une intervention (nouvelle inscription).
- **Sobriété** : `resources.max_procs` (1) borne `GOMAXPROCS` et les catalogueurs
  simultanés, `resources.memory_limit_mib` (512) la mémoire du runtime (limite douce),
  `scan.max_duration` (1 h) le scan ; l'unité ajoute `Nice=19`, `IOSchedulingClass=idle`,
  `MemoryMax=1536M`, et propose `CPUQuota=` (à décommenter, au prix d'un scan plus long).
- **Moindre privilège** : utilisateur `ogsbom-agent`, seule capacité
  `CAP_DAC_READ_SEARCH` (lecture de tout fichier), écriture limitée au répertoire d'état,
  unité durcie (`systemd-analyze security` : 1,9).
- **Mise à jour** : installer le nouveau paquet ; le démon redémarre, l'état est gardé.
  **Désinstallation** : arrête les unités ; `/var/lib/ogsbom-host-agent` et l'utilisateur
  restent (à supprimer à la main pour une réinscription propre, après avoir désactivé
  l'agent dans l'interface).
- **Journaux** : `journalctl -u ogsbom-host-agent` ; ni jeton ni contenu de SBOM.

### Mesures

Protocole (root requis, hors CI) : `make build GOARCH=amd64`, puis
`OGSBOM_HOST_AGENT_BINARY=$PWD/bin/ogsbom-host-agent go test -tags measure -count=1 -v -run 'TestMeasure|TestLeastPrivilege' ./internal/hostagent/`
(agent sous `nobody` avec `CAP_DAC_READ_SEARCH`, contre un faux serveur ;
`OGSBOM_MEASURE_ROOT` choisit la racine). Résultats et cibles : Journal de T07 et cahier
des charges.

## Ingestion

Un agent envoie un SBOM par `POST /api/v1/agent/ingestions` (deux parties : `context`
puis `sbom`, compressé en gzip de préférence) pour une référence d'un projet qui lui est
confié. Formats acceptés : **CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3, Syft JSON** ; pas
de XML. La requête stocke le SBOM et met son décodage en file ; l'agent suit l'état par
`GET /api/v1/agent/ingestions/{id}` (`queued`, `processing`, `done`, `failed` avec une
clé d'erreur traduite). L'onglet **Instantanés** de chaque projet montre les dernières
réceptions, leurs erreurs, et permet de télécharger le SBOM reçu ou réencodé en
CycloneDX 1.6 ou SPDX 2.3.

Bornes (`ingest.*`) :

| Réglage | Défaut | Au-delà |
| --- | --- | --- |
| `max_upload_mib` | 32 | refus 413 dans la requête, sans ingestion |
| `max_decompressed_mib` | 64 | ingestion `failed` (`error.ingest.too_large`) |
| `max_depth` | 64 | ingestion `failed` (`error.ingest.too_deep`) |
| `max_components` | 50 000 | ingestion `failed` (`error.ingest.too_many_components`) |
| `decode_timeout` | 5 min | job réessayé, puis `dead` |

- Un JSON non compressé compte tout entier dans `max_upload_mib` : les agents envoient du
  gzip (un SBOM se compresse d'environ dix fois).
- **Mémoire** : le décodage charge le document ; le pic mesuré vaut environ **trente fois
  sa taille** (1,5 Mio pour un hôte de 800 paquets : quelques dizaines de Mio ; 10 Mio et
  50 000 composants : environ 330 Mio). Prévoir, par job de décodage simultané
  (`workers.concurrency`, et au plus `workers.org_limit` par organisation), trente fois le
  plus gros SBOM attendu, et poser `GOMEMLIMIT` à environ 80 % de la mémoire de
  l'instance. Une instance web (`workers.enabled: false`) ne garde en mémoire que l'envoi
  en cours de réception (`max_upload_mib` par requête simultanée).
- Le SBOM brut est conservé compressé et dédoublonné : renvoyer le même document ne le
  stocke pas deux fois. Un dépôt qui renvoie le même SBOM pour le même commit ne crée rien.
- Rien du contenu d'un SBOM n'est journalisé ; seuls l'identifiant de l'ingestion, sa clé
  d'erreur et le nombre de composants le sont.
- Décision de conception : ADR 0015 (décodage dans le worker) et ADR 0016 (règles de
  l'inventaire).

## Base de vulnérabilités

Les SBOM sont confrontés à la base de vulnérabilités de **Grype** (schéma v6, environ
200 Mio compressée, 3,2 Gio installée), **commune à toutes les instances** (ADR 0017) :

1. **Vérification** (échéance `vulndb.check`, toutes les `vulndb.check_interval`, une seule
   instance à la fois) : lecture de la liste de distribution (`vulndb.listing_url`), et si
   elle annonce une base plus récente que la cible, téléchargement, vérification de la
   SHA-256 annoncée, installation complète pour valider l'ouverture, stockage de l'archive
   dans PostgreSQL (`vulndb_archives`, par blocs de 8 Mio), puis la base devient la
   **cible** (`vulndb_state`). Une archive corrompue ou dont la somme diffère n'est jamais
   stockée ni activée ; l'erreur est notée et affichée.
2. **Synchronisation** : chaque instance worker installe la cible dans `vulndb.dir` depuis
   PostgreSQL (jamais depuis Internet) au démarrage, toutes les `vulndb.sync_interval` et
   avant chaque analyse, puis bascule sans interrompre les analyses en cours. Deux workers
   ne produisent donc jamais de constats contradictoires.
3. **Réanalyse** : chaque nouvelle cible met en file la réanalyse de toutes les
   références actives, en priorité basse ; une ingestion fraîche passe devant.

L'écran **Administration → Base de vulnérabilités** montre la cible (date de
construction, schéma, taille, origine, somme), la dernière vérification et son erreur,
les archives stockées. Au-delà de `vulndb.max_age` (5 jours par défaut), ou sans base, un
avertissement apparaît sur toutes les pages d'administration et `ogsbom_vulndb_stale`
vaut 1 : à surveiller (alerte Prometheus conseillée sur `ogsbom_vulndb_stale == 1`).

| Réglage | Défaut | Rôle |
| --- | --- | --- |
| `listing_url` | liste d'Anchore | `latest.json` de Grype, ou d'un miroir interne (même arborescence) |
| `dir` | `/var/lib/ogsbom/vulndb` | copie locale de l'instance (chemin absolu) |
| `offline` | `false` | `true` : aucune interrogation de la liste (site isolé) |
| `check_interval` | 6 h | fréquence de vérification (au moins 10 min ; Anchore publie chaque jour) |
| `sync_interval` | 1 min | fréquence de contrôle de la copie locale |
| `max_age` | 120 h | âge déclenchant l'avertissement |
| `download_timeout` | 30 min | interrogation ou téléchargement ; le job de vérification a le double |
| `max_archive_mib` | 2 048 | taille maximale d'une archive |
| `analysis_timeout` | 10 min | durée maximale d'une analyse, synchronisation locale comprise |

- **Espace disque** : sur chaque instance worker, environ **3,5 Gio** pour la base
  installée et **le double pendant une bascule** (ancienne et nouvelle), plus l'archive
  le temps de l'installer : prévoir 8 Gio libres dans `vulndb.dir`. L'instance qui vérifie
  la liste a besoin du même espace. Côté PostgreSQL, environ 200 Mio par archive
  conservée (purge des anciennes archives avec l'écran d'import, T11).
- **Mémoire et CPU** : une analyse de 5 000 composants prend environ 6 s sur 4 cœurs
  (`docs/benchmarks.md`) ; la base est ouverte une seule fois par instance et partagée par
  les analyses simultanées (`workers.concurrency`, au plus `workers.org_limit` par
  organisation).
- **Plusieurs instances** : toutes lisent la même cible ; une instance purement web
  (`workers.enabled: false`) n'a pas de copie locale et reste prête sans base. Le premier
  démarrage d'un parc neuf n'a aucune base : les instances worker ne sont pas prêtes
  (`/readyz` 503) jusqu'à la fin de la première vérification (téléchargement et
  installation : quelques minutes). Les analyses demandées entre-temps se terminent sans
  rien écrire ; la première cible réanalyse tout.
- **Accès réseau** : seule l'instance qui exécute la vérification sort, vers
  `listing_url` et l'adresse de l'archive qu'elle annonce (`grype.anchore.io` par défaut),
  en HTTPS, par le mandataire de l'environnement (`HTTPS_PROXY`).
- **Hors ligne** : `vulndb.offline: true`, et soit un **miroir interne** de la liste
  (`listing_url` vers lui, `offline: false`), soit l'**import** d'une archive téléchargée
  ailleurs (`vulnerability-db_v6.*.tar.zst`, liste d'Anchore), par l'écran d'import
  d'administration (T11). L'archive importée passe les mêmes contrôles d'installation.
- Rien du contenu des SBOM n'est journalisé par l'analyse.

## Agent dépôt

`ogsbom-repo-agent` est un service externe aux CI : il détient seul les accès aux forges,
reçoit leurs webhooks de push, extrait le commit visé, l'analyse avec Syft et envoie le
SBOM (CycloneDX 1.6, composants marqués `ogsbom:origin=syft`). Configuration d'exemple
commentée et unité systemd durcie : `deploy/ogsbom-repo-agent/`.

### Mode d'exploitation

- **Une instance par organisation** : elle porte le jeton d'un agent dépôt de cette
  organisation (« Agents › Nouvel agent dépôt »). Les dépôts lui sont confiés depuis leur
  fiche ; leur **URL de forge** (`https://github.com/acme/app`,
  `https://gitlab.example.org/groupe/sous-groupe/projet`) désigne la forge configurée dont
  l'URL web la préfixe. Un dépôt sans forge configurée est signalé au journal et ignoré.
- **Webhooks** : l'URL publique de l'instance est `https://<hôte public>/webhooks/<nom de
  la forge>` (le `name` de la forge dans la configuration). Seule cette route et
  `GET /healthz` sont servies. Le récepteur borne le corps (`webhook.max_body_kib`),
  limite le débit par IP (`webhook.rate_limit`), **refuse tout webhook mal signé**
  (401, journalisé avec la forge et l'IP, sans contenu), ignore une livraison déjà reçue
  (`X-GitHub-Delivery`, `X-Gitlab-Event-UUID`) et répond aussitôt (202) : l'analyse est
  asynchrone. Un webhook ne sert que de signal : l'agent résout lui-même la tête de la
  référence auprès de la forge, si bien qu'un webhook rejoué ou en retard ne fait jamais
  analyser un commit dépassé.
- **Rattrapage** : il n'y a pas de file durable côté agent. Au démarrage puis toutes les
  `catchup.interval` (15 min), l'agent relit ses dépôts (`GET /api/v1/agent/projects`),
  envoie un signal de vie, compare la tête de chaque référence suivie au commit du
  dernier instantané du serveur et analyse les commits manqués, **du plus ancien au plus
  récent** (`catchup.max_commits`, 20 au plus, les plus récents). Un webhook perdu, une
  file pleine ou un agent arrêté sont donc rattrapés au passage suivant. Une étiquette, une
  première analyse ou une histoire réécrite donnent l'analyse de la seule tête. Coût : un
  appel d'API de forge par référence et par passage (plus une comparaison s'il y a du
  neuf) ; 500 références toutes les 15 minutes font environ 2 000 appels par heure, sous la
  limite de 5 000 par heure d'une installation de GitHub App.
- **Serveur** : client commun des agents (`internal/agentclient`) ; `server.retries`
  tentatives pour une erreur réseau, 429 ou 5xx, délai exponentiel, `Retry-After`
  respecté ; un refus 4xx (référence inconnue, SBOM trop gros) est définitif jusqu'au
  redémarrage. HTTPS seulement ; `server.ca_file` pour une autorité privée,
  `server.client_cert_file` et `server.client_key_file` (`credential:<nom>` ou fichier en
  `0600`) quand le serveur exige le mTLS, `server.proxy` pour un mandataire.
- **Analyse** : un sous-répertoire de `work.dir` par commit, supprimé à la fin quoi qu'il
  arrive (et au démarrage s'il en reste après un arrêt brutal). git est lancé avec un
  environnement maîtrisé : ni configuration système ni globale, aucune invite, crochets
  désactivés, `core.symlinks=false` (un lien symbolique du dépôt devient un simple fichier
  qui contient sa cible), LFS inerte, un seul protocole (celui de l'URL de clonage), pas de
  redirection, objets vérifiés (`transfer.fsckObjects`). Le commit exact est récupéré
  (`git fetch --depth 1 --no-tags <url> <commit>`), extrait puis vérifié ; `.git` est
  supprimé avant le scan. Syft ne lance aucun programme et n'accède pas au réseau (le
  catalogueur Go n'appelle pas `go list`). Aucun fichier du dépôt n'est exécuté.
- **Bornes** : `work.max_clone_mib` (1 024) mesuré pendant le clonage, qui est tué
  au-delà (échec définitif pour ce commit, non retenté avant redémarrage) ;
  `work.clone_timeout` (10 min) et `work.scan_timeout` (15 min), retentés au passage
  suivant ; `work.parallelism` (2) analyses simultanées, jamais deux à la fois pour une
  même référence ; `work.queue_size` (1 000) références en attente.
- Le SBOM produit ne porte ni numéro de série ni horodatage : deux analyses du même
  commit donnent les mêmes octets, que le serveur reconnaît comme un renvoi (200, rien de
  créé). Le composant décrit est le projet (son slug) à ce commit.
- **Réseau sortant** : le serveur open-go-sbom, l'API et le service git HTTPS des forges.
  Entrant : le récepteur de webhooks seul.

### GitHub : GitHub App

1. Paramètres de l'organisation GitHub › *Developer settings* › *GitHub Apps* › *New GitHub
   App*. URL du webhook : `https://<hôte public>/webhooks/github` ; secret de webhook : une
   valeur aléatoire (`openssl rand -hex 32`), conservée pour l'agent.
2. **Droits minimaux** (*Repository permissions*) : **Contents : Read-only** (clonage,
   lecture des références et comparaisons) ; *Metadata : Read-only* est imposé par GitHub.
   Aucun autre droit, aucun droit d'organisation ni de compte. (T15 ajoutera *Commit
   statuses : Read and write* pour publier le verdict.) Événements : **Push** seulement.
3. Générer une clé privée (fichier PEM) ; noter l'*App ID*.
4. Installer l'application sur l'organisation, en limitant l'accès aux dépôts suivis
   (*Only select repositories*). L'installation est trouvée pour chaque dépôt ; la fixer
   par `installation_id` si l'application a plusieurs installations.

L'agent signe un JWT RS256 de 9 minutes avec la clé, obtient un jeton d'installation
**restreint à `contents: read`** (même si l'application a d'autres droits), le garde en
mémoire jusqu'à cinq minutes de son expiration, et le présente à git dans un en-tête HTTP
(`x-access-token`). Vérification : un dépôt non sélectionné dans l'installation est refusé
(`installation de l'application : … introuvable` au journal), et un push sur un dépôt
suivi apparaît dans l'onglet *Advanced › Recent deliveries* de l'application avec une
réponse 202.

### GitLab : compte de service

1. Créer un compte de service (GitLab 16.1 et plus, Premium) ou, à défaut, un utilisateur
   dédié ; lui donner le rôle **Reporter** (le plus faible qui lit le code) sur les
   groupes ou projets suivis. Un jeton d'accès de groupe ou de projet, au rôle Reporter,
   convient aussi.
2. Jeton d'accès avec les **portées minimales** `read_api` (références et comparaisons) et
   `read_repository` (clonage) ; aucune portée d'écriture. Prévoir sa rotation avant son
   expiration (déposer le nouveau credential et redémarrer l'agent).
3. Sur chaque projet (ou groupe) : *Settings › Webhooks*, URL
   `https://<hôte public>/webhooks/gitlab`, *Secret token* aléatoire, déclencheurs **Push
   events** et **Tag push events**, vérification SSL activée.

Le secret est comparé en temps constant à `X-Gitlab-Token`. Vérification : *Test › Push
events* sur la page du webhook doit répondre 202 ; un secret faux, 401.

### Secrets et credentials systemd

Les secrets (jeton d'agent, clé privée de la GitHub App, jeton GitLab, secrets de
webhook, clé TLS du récepteur) ne sont **jamais dans le fichier de configuration** : celui-ci
les désigne par `credential:<nom>` (credential systemd) ou par le chemin absolu d'un
fichier lisible du seul compte de l'agent (`0600` ou `0400`, refusé sinon). Avec l'unité
fournie (`DynamicUser=yes`, `StateDirectory=ogsbom-repo-agent`, durcissement
`ProtectSystem=strict`, `NoNewPrivileges=yes`, aucune capacité) :

```bash
install -d -m 0700 /etc/ogsbom-repo-agent
systemd-creds encrypt --name=agent-token agent-token.txt /etc/ogsbom-repo-agent/agent-token.cred
systemd-creds encrypt --name=github-app-key app.private-key.pem /etc/ogsbom-repo-agent/github-app-key.cred
systemd-creds encrypt --name=github-webhook-secret github-secret.txt /etc/ogsbom-repo-agent/github-webhook-secret.cred
systemd-creds encrypt --name=gitlab-token gitlab-token.txt /etc/ogsbom-repo-agent/gitlab-token.cred
systemd-creds encrypt --name=gitlab-webhook-secret gitlab-secret.txt /etc/ogsbom-repo-agent/gitlab-webhook-secret.cred
shred -u agent-token.txt app.private-key.pem github-secret.txt gitlab-token.txt gitlab-secret.txt
```

Retirer de l'unité les `LoadCredentialEncrypted=` des forges non utilisées. Les
identifiants de clonage n'apparaissent ni dans les arguments des processus (`ps`), ni
dans l'URL, ni dans les journaux : ils passent à git par l'environnement
(`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`, en-tête `Authorization`), que `ProtectProc=
invisible` cache aux autres comptes.

### Exploitation

- Journaux `slog` (`logging.format: json` en production) : rattrapages, pushs reçus et
  refusés, envois (`project`, `ref`, `commit`), échecs d'analyse avec leur cause.
- `GET /healthz` sur l'écoute du récepteur sert de sonde de vie.
- Arrêt sur SIGTERM : le récepteur termine ses requêtes (10 s), les clonages en cours
  sont tués et leurs répertoires supprimés ; le travail perdu est rattrapé au démarrage.
- Décision de conception : ADR 0023.

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
