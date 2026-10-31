# Architecture technique de référence

Ce document fait autorité sur l'architecture, les noms et les conventions d'open-go-sbom.
Le besoin fonctionnel est dans [`docs/cahier-des-charges.md`](../docs/cahier-des-charges.md) ;
le découpage du travail est dans [`specs/README.md`](README.md). Toute décision qui s'en
écarte passe par un ADR (`docs/adr/`) et une mise à jour de ce document dans le même commit.

## 1. Principes directeurs

1. **La qualité prime sur la vitesse.** Un lot n'est terminé que lorsque ses tests, sa
   documentation et ses critères d'acceptation sont au vert ; on ne reporte pas la dette.
2. **Un binaire par rôle, tout embarqué.** Gabarits, CSS, JS, traductions et migrations sont
   compilés dans le binaire via `go:embed`. Le serveur n'a besoin que de PostgreSQL.
3. **La base est la seule source de vérité.** Un processus redémarré ne perd rien ; aucun
   état métier ne vit uniquement en mémoire ou sur le disque d'une seule instance.
4. **Le serveur calcule, le client affiche.** Aucune logique métier en JavaScript.
5. **Dépendances minimales et validées.** Toute nouvelle dépendance tierce est proposée à
   l'utilisateur avant d'être ajoutée (§ 5). Les bibliothèques d'Anchore sont isolées
   derrière des adaptateurs.
6. **Multi-organisation par construction.** Aucune donnée d'organisation ne vit dans une
   table globale ; l'isolement est garanti par PostgreSQL lui-même (RLS forcée sur toute
   table d'organisation), par le schéma (clés étrangères composites) et par les signatures
   de fonctions, pas par la discipline.
7. **Traduction dès le premier écran.** Aucune chaîne visible en dur, ni dans les gabarits,
   ni dans le code.
8. **Sécurité par défaut.** TOTP obligatoire hors SSO, CSP stricte, CSRF, limitation de
   débit, secrets chiffrés, journal d'audit, entrées bornées.

## 2. Binaires

| Binaire | Rôle | Lots |
| --- | --- | --- |
| `ogsbom-server` | Interface web, API REST, workers (ingestion, analyse, notifications), planificateur | T01 → |
| `ogsbom-host-agent` | Agent serveur Linux (puis Windows) : inventaire de l'hôte et de ses conteneurs | T07, T13, T19, T22, T23, T24 |
| `ogsbom-repo-agent` | Agent dépôt, service externe : forges, clonage, Syft, enrichissement IA | T08, T12, T15, T19, T23, T24 |

`ogsbom-server` lance web et workers dans le même processus ; `workers.enabled: false` sert à
séparer les rôles sur plusieurs instances (recommandé dès qu'on dépasse un usage modeste,
pour qu'un envoi lourd ne ralentisse pas l'interface).

Un `ogsbom-repo-agent` sert une organisation (un jeton d'agent). Plusieurs organisations sur
une instance → une instance d'agent dépôt par organisation qui en a besoin.

## 3. Arborescence du dépôt

```
cmd/
  ogsbom-server/            # main : chargement config, câblage, démarrage
  ogsbom-host-agent/
  ogsbom-repo-agent/
internal/
  config/                # Config composée : fragments appconf + fragments propres
  db/                    # pool, transactions (InTx, InOrg), démarrage, migrations
    crossorg/            # seules fonctions inter-organisations (SECURITY DEFINER), § 9
    dbtest/              # base et rôles jetables pour chaque test d'intégration
    migrations/          # NNN_<sujet>.sql, immuables une fois publiées
  locale/                # traductions embarquées, choix de la langue (§ 18), sans HTTP
  pagination/            # curseurs opaques et pages bornées (§ 15)
  jobs/                  # file de traitements PostgreSQL + planificateur
  secret/                # chiffrement des secrets stockés (AES-256-GCM, clés versionnées)
  audit/                 # journal d'audit
  tenant/                # type OrgID, contexte, garde d'organisation
  account/               # comptes (écriture dans users), méthode d'authentification, rendu
  org/                   # organisations, appartenances, rôles (+ équipes en T16)
  project/               # projets, références suivies, hiérarchie hôte/conteneurs
  agent/                 # agents, jetons d'inscription et d'agent, signaux de vie
  sbom/                  # modèle interne, normalisation purl, empreinte d'inventaire
    syft/                # décodage et encodage via Syft
  inventory/             # composants, ensembles d'inventaire, instantanés
  ingest/                # réception, stockage brut, pipeline de décodage
  version/               # comparaison de versions par écosystème, analyse de `vers`
    grypeversion/        # adaptateur vers les comparateurs de Grype
  vuln/                  # base de vulnérabilités, catalogue, interface Matcher
    grype/               # correspondance et cycle de vie de la base via Grype
  finding/               # cycle de vie des constats
  search/                # analyse de requête, plan, exécution, export
  dashboard/             # agrégats et statistiques quotidiennes
  triage/ policy/ notify/ # lot 2
  license/
    grant/               # lot 3
  web/                   # routeur chi, handlers HTML par écran, gestion, serveurs
    middleware/          # identifiant de requête, journal, en-têtes, langue, métriques
    webtest/             # assistant de test : accessibilité, absence de code en ligne
  api/                   # handlers REST (interfaces générées depuis api/openapi.yaml)
    gen/                 # code généré, jamais modifié à la main
    problem/             # erreurs RFC 9457
  render/                # moteur de gabarits, FuncMap, empreinte des assets, SVG
  agentclient/           # client de l'API agent (généré), partagé par les deux agents
  hostagent/             # pipeline de l'agent serveur
  repoagent/             # pipeline de l'agent dépôt
  forge/                 # GitHub App, GitLab (Forgejo plus tard)
  llm/                   # fournisseurs de modèles (lot 2)
  archtest/              # tests d'architecture (§ 4)
api/openapi.yaml         # contrat de l'API, source unique
web/                     # paquet Go qui embarque gabarits et fichiers statiques
  templates/             # layout, partials, un dossier par écran
  static/css/            # tokens.css, fonts.css, base.css, components/*.css, screens/*.css
  static/js/             # modules ES, un par écran, sans build
  static/fonts/          # Atkinson Hyperlegible Next et Mono (WOFF2, licence OFL)
locales/                 # en.yaml, fr.yaml (paquet Go qui les embarque)
config.example.yaml      # configuration commentée du serveur
deploy/                  # compose.yaml (dev), unités systemd, configs de paquets, Containerfile
docs/                    # cahier des charges, adr/, operations.md, benchmarks.md, security/
specs/                   # ce document, index des lots, fiches de lots
testdata/                # SBOM d'exemple, systèmes de fichiers et dépôts de test
```

Nommage : paquets courts en anglais, jamais de paquet fourre-tout (`util`, `helper`,
`common`). Le code Go est en anglais ; les commentaires et la documentation en français.

## 4. Règles de dépendance entre paquets

- `cmd/*` câble, ne contient aucune logique.
- `web` et `api` dépendent des paquets métier ; jamais l'inverse.
- Les paquets métier ne dépendent ni de `net/http` ni de `html/template`.
- **Imports directs** autorisés des bibliothèques d'Anchore (Grype dépend lui-même de Syft,
  la règle porte donc sur les imports directs, pas sur le graphe transitif) :
  - `github.com/anchore/syft/...` : `sbom/syft`, `vuln/grype`, `hostagent`, `repoagent` ;
  - `github.com/anchore/grype/...` : `vuln/grype`, `version/grypeversion` ;
  - `github.com/anchore/grant/...` : `license/grant`.
- Les types d'Anchore ne traversent jamais la frontière d'un adaptateur.
- `agentclient`, `hostagent`, `repoagent`, `forge`, `llm` ne dépendent d'aucun paquet
  serveur (`db`, `inventory`…) : les agents restent des binaires légers.
- Pas de variable globale mutable ; les dépendances sont injectées par constructeur.

`internal/archtest` lit les imports directs de chaque paquet, tests compris
(`go list -json`), et échoue en CI au premier écart. Les listes de paquets métier, de
présentation, d'agents et de serveur sont tenues dans `internal/archtest/rules.go` : un
nouveau paquet y est classé dans le commit qui le crée. « `cmd` ne contient aucune
logique » et « pas de variable globale mutable » ne se lisent pas dans les imports et
restent vérifiés en relecture.

## 5. Socle et dépendances

Versions minimales : Go 1.26, PostgreSQL 16. Validations du 31 octobre 2026 ; versions
relevées en T00 (une montée de version ultérieure ne demande pas de nouvelle validation).

| Besoin | Choix | Version (T00) | Statut |
| --- | --- | --- | --- |
| Configuration, journaux, i18n, CSRF, limitation de débit (par IP ou par clé), CORS, comptes, sessions, TOTP | `leblanc.io/open-go-base` | v1.0.1, puis commits de v1.1.0 (T03) et v1.2.0 (T04), étiquettes à pousser | Décidé |
| Pilote PostgreSQL | `github.com/jackc/pgx/v5/stdlib` via `database/sql` (partagé avec les stores d'authx et mfax) | v5.12.0 | Validé (ADR 0002) |
| Routeur HTTP | `github.com/go-chi/chi/v5` (comme open-go-canivet) | v5.5.0 | Validé (ADR 0003) |
| SBOM, vulnérabilités, licences | `github.com/anchore/syft`, `grype`, `grant` | v1.55.0, v0.121.0, v0.6.8 | Décidé (ADR 0007) |
| Pilote SQLite pur Go, exigé par Syft pour les bases RPM récentes | `modernc.org/sqlite` (déjà dans le graphe d'open-go-base) | celle du graphe | Validé en T00 (ADR 0007) |
| Manipulation CycloneDX côté agents et dans l'adaptateur `sbom/syft` (réencodage) | `github.com/CycloneDX/cyclonedx-go` (déjà dans le graphe de Syft) | v0.12.0 | Validé |
| purl | `github.com/package-url/packageurl-go` (déjà dans le graphe de Syft) | v0.1.7 | Validé |
| UUID v7 | `github.com/google/uuid` (déjà indirect) | v1.6.0 | Validé |
| Contrat d'API | `oapi-codegen` en directive `tool` + `github.com/oapi-codegen/runtime` | v2.8.1, v1.8.0 | Validé (ADR 0006) |
| Requêtes SQL | écrites à la main (sqlc impose `lib/pq` avec `database/sql`) | — | Tranché (ADR 0004) |
| File de traitements | maison, sur PostgreSQL (§ 16) | — | Retenu (ADR 0005) |
| Analyse statique | `staticcheck`, `govulncheck` en directives `tool` | v0.8.2, v1.9.0 | Validé |
| Validation des SBOM par schéma JSON | schémas officiels embarqués, `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Validé |
| Métriques | `github.com/prometheus/client_golang` | v1.25.0 | Validé |
| Paquets deb et rpm | `nfpm` en directive `tool` | v2.48.0 | Validé |
| Fournisseur de modèle | SDK Go officiel d'Anthropic ; Ollama par son API HTTP sans SDK | — | À valider en T12 |
| Règles de politique | `github.com/google/cel-go` | — | À valider en T15 |
| OIDC | `oidcx` dans open-go-base, ou paquet local | — | Point ouvert, T25 |

Sans dépendance : client Git (binaire `git` du système), clients des forges (HTTP + JWT
RS256 en stdlib), client de l'API Docker (celui du graphe de stereoscope s'il y est, sinon
HTTP sur socket Unix), envoi de courriels (`net/smtp`), graphiques (SVG côté serveur),
confinement des fichiers (`os.Root`).

## 6. Configuration

`internal/config.Config` compose les fragments d'`appconf` avec le préfixe `OGSBOM_` :
`Web`, `Logging`, `I18n`, `Database` (complété par les réglages du pool et l'attente au
démarrage), `Auth` et `MFA` (avec authx et mfax, T03), `CORS` (API utilisateur). Fragments
propres au projet : `HTTP` (délais des serveurs, délai d'arrêt propre),
`TLS` (certificat, clé, autorité des certificats clients pour le mTLS des agents),
`Management` (écoute séparée métriques et sondes), `Workers` (activation, nombre de
workers, scrutation, bail, réessais, rétention, planificateur, délai d'arrêt, plafond de
jobs lourds par organisation), `Ingest` (bornes de taille reçue et décompressée, de profondeur
et de composants, délai du décodage, T05),
`VulnDB` (URL de la liste, répertoire local, fréquence, mode hors ligne), `Secrets` (clés
de chiffrement versionnées, obligatoires depuis T03 : les secrets TOTP sont chiffrés),
`Bootstrap` (premier administrateur et procédure de secours, T03), `Login` (débit des
tentatives de connexion, T03), `AgentAPI` (débit de l'API des agents par jeton et des
jetons refusés par IP, T04), `Migration`
(`migration_dsn` : connexion du rôle propriétaire, utilisée uniquement pour migrer).
`Database.DSN` est la connexion du rôle d'exécution. `--help` liste toutes les variables
d'environnement. Un `config.example.yaml` commenté accompagne chaque binaire. Un fragment
n'entre dans `Config` qu'avec le lot qui l'utilise : aucune variable sans effet. Défauts
propres au projet, posés avant le chargement : pilote `postgres`, langue `fr`, journaux
`info`.

Contrôles au démarrage :

- `Database.Driver` doit valoir `postgres` (pour que `Dialect()` renvoie PostgreSQL ; le
  pool est ouvert avec le pilote `pgx`) ;
- le pool de migration doit autoriser au moins 2 connexions (le verrou de migration en tient
  une pendant que les migrations travaillent sur une autre) ;
- le rôle d'exécution ne doit être ni superutilisateur, ni `BYPASSRLS`, ni propriétaire des
  tables : sinon la RLS serait contournée, et le serveur refuse de démarrer ;
- TLS natif facultatif ; sans lui, le serveur est placé derrière un mandataire inverse qui
  termine TLS, et le mTLS des agents est alors indisponible.

## 7. Base de données

- PostgreSQL 16 ou plus, seul moteur supporté. Connexion directe, ou via pgbouncer en mode
  session (le mode transaction est incompatible avec les migrations et les verrous).
- Deux rôles PostgreSQL (noms par défaut) :
  - `ogsbom_owner` possède le schéma, applique les migrations (y compris celles d'authx et
    de mfax) et possède les fonctions de `crossorg` ; il a l'attribut `BYPASSRLS`, sans
    lequel ces fonctions ne verraient rien sous la RLS forcée (ADR 0012) — il ne lui
    donne aucun pouvoir nouveau sur des tables qu'il possède ;
  - `ogsbom_app` exécute l'application : `SELECT`, `INSERT`, `UPDATE`, `DELETE` accordés
    par les migrations (privilèges par défaut sur les tables futures), rien d'autre.
- En fonctionnement, un pool `*sql.DB` unique sur `ogsbom_app`, partagé par les stores
  d'authx/mfax et par le code du projet ; le pool du propriétaire n'existe que le temps de
  migrer.
- Identifiants : UUID v7 générés en Go pour les entités du projet. Les comptes gardent
  l'identifiant `bigint` d'authx ; les tables du projet qui les référencent utilisent
  `bigint`. Les organisations et les projets ont aussi un `slug` pour les URL.
- Horodatages en `timestamptz`, toujours en UTC. Valeurs fermées en `text` + `CHECK`.
- `jsonb` uniquement pour des données sans requête relationnelle (étiquettes, preuves IA,
  contexte d'hôte).
- **Migrations** : celles d'authx et de mfax par leur `Migrate` ; celles du projet par
  l'exécuteur de `internal/db`, dans `internal/db/migrations/NNN_<sujet>.sql`, suivies dans
  la table `ogsbom_schema_migrations` avec leur somme SHA-256. Une migration publiée dont la
  somme a changé empêche le démarrage : l'immuabilité est vérifiée, pas seulement promise.
  Ordre au démarrage, avec le pool du rôle propriétaire : transaction de verrou
  (`LOCK TABLE ogsbom_schema_migrations IN EXCLUSIVE MODE`) sur une connexion dédiée →
  authx → mfax → projet (dont politiques RLS, droits du rôle d'exécution et fonctions de
  `crossorg`) → validation. Une seconde instance attend le verrou puis constate qu'il n'y a
  rien à faire. Les migrations du projet, leur enregistrement et la validation partagent
  la transaction du verrou (tout ou rien, donc pas de `CREATE INDEX CONCURRENTLY`) ; le
  rôle d'exécution, lu dans `database.dsn`, leur est déclaré dans `ogsbom.app_role` ; la
  validation refuse toute table d'organisation sans la RLS standard (ADR 0010). Sans
  `migration.dsn`, une instance ne migre pas et refuse un schéma en retard.
- Accès : un « store » par paquet métier, qui ne renvoie que des types du domaine.
- Transactions : `db.InOrg(ctx, orgID, func(tx) error)` pour toute donnée d'organisation
  (§ 9), `db.InTx(ctx, func(tx) error)` pour les seules tables globales ; aucune transaction
  ne traverse un appel réseau. Les upserts en lot trient leurs clés pour éviter les
  interblocages.

## 8. Modèle de données

Données **globales** (publiques ou propres à l'instance, jamais des données d'organisation) :

| Table | Contenu |
| --- | --- |
| `vulnerabilities` | identifiant (CVE, GHSA…), alias, sévérité, CVSS, description, références, EPSS, KEV |
| `vulndb_state`, `vulndb_archives` | version cible de la base Grype, archives vérifiées (téléchargées ou importées) |
| `jobs`, `schedules` | file de traitements et échéances du planificateur |
| `users`, `sessions`, `mfa_*` | tables d'open-go-base ; `users` est écrit par `account` (§ 10) |
| `account_settings`, `session_auth` | préférences du compte ; méthode d'authentification de chaque session |
| `instance_audit_events` | journal d'audit de l'instance (événements sans organisation) |

Données **par organisation** (toutes portent `org_id`) :

| Table | Contenu |
| --- | --- |
| `organizations`, `org_memberships` | organisation (slug, nom, langue par défaut) ; compte × organisation × rôle |
| `projects` | type (`repo`, `host`, `container`), nom, slug, étiquettes, `parent_id` (T13), équipe (T16), archivage |
| `tracked_refs` | référence suivie (branche, tag, ou l'hôte) |
| `agents`, `agent_tokens`, `enrollment_tokens`, `personal_access_tokens` | agents et jetons hachés |
| `components` | composant de l'organisation : purl canonique (unique par organisation), `purl_base`, type, nom, version, CPE, empreintes |
| `component_sets`, `component_set_items` | ensemble d'inventaire adressé par son empreinte ; ses composants avec origine (`syft`, `ia`), confiance, modèle, preuve, portée, licences, identification faible |
| `sbom_blobs` | SBOM brut compressé, dédoublonné par empreinte SHA-256 |
| `ingestions` | réception d'un SBOM : statut, erreurs, instantané produit |
| `snapshots` | instantané d'une référence : commit, date, agent, version d'agent, blob, ensemble d'inventaire |
| `ref_current` | instantané et ensemble courants de chaque référence (lecture rapide) |
| `findings` | constat (référence × composant × vulnérabilité) : première et dernière détection, résolution, risque |
| `audit_events`, `org_daily_stats` | journal d'audit ; agrégats quotidiens |
| `triage_decisions`, `policies`, `notification_channels`, `teams`… | lots 2 et 3 |

Les **ensembles d'inventaire** sont adressés par contenu : deux instantanés au même
inventaire partagent le même ensemble. Un nouveau commit sans changement de dépendances
coûte une ligne, la différence entre instantanés est une différence entre ensembles, et la
rétention supprime les ensembles orphelins.

## 9. Multi-organisation

- Toute table d'organisation porte `org_id NOT NULL`. Les clés étrangères entre tables
  d'organisation sont **composites** : `snapshots (org_id, project_id)` référence
  `projects (org_id, id)`. Une ligne ne peut pas pointer vers une autre organisation.
- Les composants sont propres à chaque organisation : un purl de paquet privé ou une
  empreinte de fichier interne n'est jamais partagé. Seul le catalogue des vulnérabilités,
  public, est global.
- Les fonctions de store prennent un `tenant.OrgID` typé en premier paramètre métier.
- L'organisation courante vient de l'URL (`/o/{slug}/…`) côté web, du jeton côté agent et
  du chemin `/api/v1/orgs/{org}/…` côté API utilisateur. Un middleware vérifie
  l'appartenance avant tout handler et place `tenant.OrgID` dans le contexte.
- Une suite de tests d'isolement parcourt chaque route avec un compte d'une autre
  organisation et exige un 404 (jamais un 403, pour ne rien révéler).

### RLS obligatoire

- Toute table d'organisation a `ENABLE` et `FORCE ROW LEVEL SECURITY`, et une politique
  `USING (org_id = current_setting('ogsbom.org_id')::uuid)` avec la même condition en
  `WITH CHECK` (pour `organizations`, la colonne est `id`). PostgreSQL limite ainsi lecture
  et écriture à l'organisation déclarée, même si une requête oublie son filtre. Une
  migration la pose par `CALL ogsbom_enforce_org_rls('table')` (ou
  `('organizations', 'id')`) ; le démarrage refuse une table à `org_id NOT NULL` qui ne
  l'a pas, ou qui a en plus une politique permissive étrangère à `ogsbom.org_id`.
- `db.InOrg(ctx, orgID, fn)` ouvre une transaction et y déclare l'organisation par
  `set_config('ogsbom.org_id', $1, true)` : portée limitée à la transaction, donc
  compatible avec un pool de connexions et avec pgbouncer. C'est le seul accès aux tables
  d'organisation.
- Échec franc : hors `InOrg`, le paramètre est absent ou vide et sa conversion en `uuid`
  lève une erreur. Une requête sans organisation déclarée échoue ; elle ne renvoie jamais
  zéro ligne en silence.
- Le rôle d'exécution ne peut pas contourner la RLS (§ 6, § 7).
- Opérations inter-organisations : résolution d'un slug et de l'appartenance par la garde,
  liste des organisations d'un compte, liste des références actives pour la réanalyse,
  liste des organisations pour les statistiques quotidiennes. Ce sont des fonctions
  `SECURITY DEFINER` du rôle propriétaire, à `search_path` fixé, qui ne renvoient que le
  strict nécessaire. Elles vivent toutes dans `internal/db/crossorg`, sont listées dans un
  ADR (0012 : `ogsbom_org_access`, `ogsbom_user_orgs`, `ogsbom_list_organizations`,
  `ogsbom_org_id_by_slug` ; 0014 : `ogsbom_agent_token_org`, `ogsbom_enrollment_token_org`,
  qui donnent l'organisation d'un jeton présenté à l'API des agents), et tout ajout est
  relu comme un changement de sécurité.
- La RLS s'ajoute aux autres protections sans les remplacer : PostgreSQL ne l'applique pas
  aux contrôles de clés étrangères (d'où les clés composites), et `tenant.OrgID` garde des
  erreurs claires et des plans de requête prévisibles.
- Les tables globales (§ 8) n'ont pas de RLS ; elles ne contiennent aucune donnée
  d'organisation.
- Tests propres à la RLS : dans `InOrg(A)`, des requêtes volontairement sans filtre
  `org_id` ne lisent ni n'écrivent aucune ligne de B ; hors `InOrg`, toute requête sur une
  table d'organisation échoue ; au démarrage, un rôle d'exécution trop puissant est refusé.

### Pourquoi pas un schéma par organisation

Écarté (ADR 0012). Tant qu'un seul rôle accède à tous les schémas, l'isolement reposerait
sur un `search_path` correctement positionné, soit la même discipline qu'un filtre oublié ;
un rôle par organisation imposerait un pool par organisation. Les migrations seraient
rejouées une fois par organisation, la création d'une organisation demanderait de créer des
tables à chaud (donc des droits de DDL pour l'application), et les traitements qui couvrent
toutes les organisations passeraient par du SQL dynamique. Le gain de volume est nul à
l'échelle visée : un index qui commence par `org_id` mène directement aux lignes de
l'organisation. Si une organisation devenait très volumineuse, le partitionnement des plus
grandes tables par `org_id` donnerait la même séparation physique en gardant la RLS.

## 10. Identité et accès

- Comptes : authx lit `users` et gère les sessions ; **la création et la modification des
  comptes reviennent au projet** (paquet `account`), qui écrit dans `users` avec
  `authx.HashPassword` et utilise sa colonne `must_change_pwd`. Ni authx ni mfax n'appliquent
  ce drapeau : un middleware du projet redirige vers le changement de mot de passe.
- Second facteur via `mfax` avec enrôlement **obligatoire** (ne jamais passer
  `WithOptionalEnrollment()`).
- `session_auth` enregistre, pour chaque session (clé : SHA-256 du jeton de session), la
  méthode d'authentification : `local_totp`, ou `sso` avec l'organisation dont le
  fournisseur a authentifié. La garde d'organisation s'en sert pour imposer le SSO d'une
  organisation qui l'exige (T25), même pour un membre de plusieurs organisations.
- Premier administrateur créé au premier démarrage depuis `bootstrap.*` (ignoré dès qu'un
  compte existe) ; changement de mot de passe et enrôlement TOTP à la première connexion.
- Administrateur d'instance : rôle privilégié assumé (il peut réinitialiser le mot de passe
  et le TOTP d'un compte, chaque fois audité) ; deux administrateurs au moins sont
  recommandés et l'interface avertit s'il n'y en a qu'un. Procédure de secours documentée
  pour un administrateur unique qui perd son TOTP : `bootstrap.rescue_totp_email` et
  `bootstrap.rescue_ticket`, lus au démarrage, appliqués une fois par ticket, audités, à
  retirer ensuite (ADR 0013).
- Secrets TOTP chiffrés en base par `internal/secret` (enveloppe du store de mfax),
  rechiffrés par la clé active au démarrage (ADR 0013).
- Pas d'envoi de courriel avant T15 : les comptes sont créés avec un mot de passe temporaire.
- Rôles d'organisation : `viewer`, `analyst` (trie les constats), `admin`. Les équipes (T16)
  restreignent ensuite la visibilité par projet.
- Jetons : préfixés par leur nature (`ogsbom_agt_`, `ogsbom_enr_`, `ogsbom_pat_`), puis un
  identifiant public (128 bits) et un secret de 256 bits, en base32 minuscule séparés par
  `_`. Seul le SHA-256 du secret est stocké ; comparaison en temps constant ; révocation
  immédiate ; date de dernier usage (écrite une fois par minute au plus). L'organisation
  d'un jeton est résolue par `crossorg`, le reste vérifié dans `InOrg` (ADR 0014).
- Agents : un projet est confié à au plus un agent de même nature (clé étrangère
  composite) ; un agent serveur couvre un seul hôte, dont le projet est créé ou rattaché à
  l'inscription ; un agent dépôt reçoit ses dépôts depuis leur fiche.
- Limitation de débit : par IP pour l'interface (open-go-base) ; **par jeton** pour l'API
  agent et l'API utilisateur, pour que des hôtes derrière une même sortie NAT ne se gênent
  pas.

## 11. Pipeline d'ingestion

1. `POST /api/v1/agent/ingestions` (jeton d'agent), multipart dans cet ordre : `context`
   (JSON : projet, référence, commit, version d'agent, date de scan) puis `sbom` (JSON, gzip
   de préférence). Contrôles synchrones : contexte, référence confiée à l'agent
   (`project.RefForAgent`, avant toute lecture du SBOM et de nouveau dans la transaction),
   taille reçue (413 au-delà, sans ingestion), taille décompressée d'un envoi gzip. Le blob
   (gzip, dédoublonné par le SHA-256 du JSON) est stocké, l'ingestion créée, un job
   `ingest.decode` mis en file dans la même transaction ; réponse `202`. Un envoi
   impossible à stocker (gzip corrompu, trop gros décompressé) donne une ingestion
   `failed` ; le même SBOM renvoyé pour la même référence et le même commit d'un dépôt
   renvoie l'ingestion existante (`200`), sans rien créer.
2. `ingest.decode` :
   - bornes préalables par lecture en flux, avant tout décodage complet : taille
     décompressée, profondeur JSON, nombre de composants (`sbom.Precheck`) ;
   - validation par le schéma officiel embarqué (`sbom/schema` ; l'énumération des
     licences SPDX de CycloneDX n'est pas imposée à la réception, ADR 0016) ;
   - décodage par `sbom/syft` (décodeurs de Syft, ceux de Grype) vers `sbom.Document`,
     normalisation des purl et fusion des doublons ;
   - calcul de l'**empreinte d'inventaire** (composants canoniques triés, origine, preuve),
     indépendante des horodatages et numéros de série du document ;
   - dans une transaction, référence verrouillée : upsert trié des composants de
     l'organisation, ensemble d'inventaire réutilisé ou créé, instantané, `ref_current`,
     fin de l'ingestion ; un SBOM refusé termine l'ingestion en `failed` avec sa clé, sans
     rien ranger.
3. Règle d'instantané : pour un dépôt, un instantané par (référence, commit), même si
   l'inventaire n'a pas changé (il réutilise alors l'ensemble existant) ; le même commit
   renvoyé avec un autre inventaire remplace l'ensemble de son instantané. Pour un hôte ou
   un conteneur, un inventaire identique au courant met seulement à jour la date de
   dernière analyse. L'instantané courant est le plus récent par date de scan.
4. Si l'ensemble courant de la référence a changé, job `analysis.ref` (charge
   `{"ref_id"}`, clé `ref:<id>`, priorité haute) mis en file dans la même transaction.
5. `GET /api/v1/agent/ingestions/{id}` expose le statut (`queued`, `processing`, `done`,
   `failed` + clé d'erreur traduisible) et l'instantané produit.

Formats acceptés : CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3, Syft JSON. Pas de XML.
Canonicalisation des purl : encodage, casse et tri des qualificatifs normalisés selon la
spécification purl, telle que l'applique `packageurl-go` (ADR 0016) ; **les qualificatifs
d'identité (`distro`, `arch`, `epoch`, `upstream`…) sont conservés**, car Grype en a
besoin. Un composant sans purl utilisable reçoit `pkg:generic/<nom>@<version>` et
l'« identification faible ». Les CPE sont conservés. Propriétés CycloneDX propres
au projet, espace de noms `ogsbom:` : `ogsbom:origin` (`syft` ou `ia`), `ogsbom:confidence` (0 à 1),
`ogsbom:model` ; la preuve IA utilise le champ standard `evidence`.

Le décodage s'exécute dans le processus worker ; les bornes préalables, le délai du job
et le plafond de jobs simultanés par organisation (`workers.org_limit`) empêchent un seul
agent de saturer une instance. L'isolation en sous-processus a été étudiée et écartée tant
qu'aucune mesure ne la justifie (ADR 0015).

## 12. Analyse de vulnérabilités

- **Grype reçoit le SBOM d'origine**, pas une reconstruction : `vuln.Matcher.Match(ctx,
  blob)` ; l'adaptateur `vuln/grype` décode le blob avec Syft (distribution, CPE,
  paquets sources, métadonnées intacts), lance la correspondance, puis rattache chaque
  résultat au composant par son purl canonique. Le reste du code ne connaît pas Grype.
- `analysis.ref` analyse **l'ensemble courant de la référence au moment de l'exécution**
  (le plus récent gagne), sous verrou de ligne sur la référence : deux analyses de la même
  référence ne se chevauchent jamais. Constats : nouveaux couples créés, couples revus
  prolongés, couples absents résolus ; un couple résolu qui réapparaît est rouvert.
- Base Grype, version cible commune à toutes les instances :
  - l'échéance `vulndb.check` (une seule instance l'exécute, § 16) interroge la liste de
    distribution, télécharge, vérifie la somme de contrôle, valide l'ouverture, stocke
    l'archive dans `vulndb_archives` et fixe la nouvelle cible dans `vulndb_state` ;
  - hors ligne, l'archive est importée depuis l'écran d'administration vers la même table ;
  - chaque instance worker synchronise sa copie locale sur la cible, bascule atomiquement et
    garde une seule base ouverte, derrière un verrou lecture/écriture ;
  - un job d'analyse exige la version cible : un worker en retard se synchronise avant de
    le traiter. Chaque constat note la version de base qui l'a produit.
- Changement de cible → `analysis.rescan_all` met en file un `analysis.ref` par référence
  active, en priorité basse.
- Une base plus vieille que N jours déclenche une alerte d'administration.

## 13. Recherche

- Une barre unique ; le type de requête est déduit : `pkg:` → purl, `CVE-`/`GHSA-` →
  vulnérabilité, `sha256:` ou 64 caractères hexadécimaux → empreinte, `license:` →
  licence, sinon nom de composant (approché par trigrammes).
- Une plage de versions `vers` ne s'applique qu'à un `purl_base` exact : SQL réduit
  l'ensemble à ce paquet (un nombre borné de versions), puis Go compare les versions par
  l'écosystème. Une recherche approchée par nom n'accepte pas de plage.
- Exécution sur `ref_current` + `component_set_items` + `components`, filtrée par
  organisation (et par équipe après T16). Résultats groupés par projet, paginés,
  exportables en CSV et JSON en flux.
- La RLS ajoute le filtre d'organisation à chaque requête, et les opérateurs non
  `LEAKPROOF` (trigrammes, `ILIKE`) sont évalués après elle. Les index de recherche
  commencent donc par `org_id` (index composites ; GIN composite via l'extension
  `btree_gin` pour les trigrammes si la mesure l'exige).
- Cible : moins de 2 s au 95e centile pour 1 000 projets et 1 million de liens, **RLS
  active**, selon le protocole de `docs/benchmarks.md`.

## 14. Interface web

- **Design de référence** : canevas
  [« open-go-sbom — Interface »](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj) (fondations,
  composants, huit écrans en thème clair, thème sombre, mobile). Sa feuille `project/ogs.css`
  est la source des tokens et des composants portés dans `web/static/css` (T01) ; sa
  racine `.ogs` devient `.ogsbom` au portage, et le thème se choisit par `data-theme`.
  Ses polices (Atkinson Hyperlegible Next et Mono, licence OFL) sont auto-hébergées et
  embarquées, jamais chargées depuis un CDN (CSP `'self'`). Chaque fiche de lot à écran
  nomme ses planches.
- Routeur chi avec **trois groupes de routes** :
  - interface : identifiant de requête → limitation par IP → journalisation → récupération
    de panique → en-têtes de sécurité → session (authx) → changement de mot de passe imposé
    → CSRF (csrfx) → langue → organisation courante → handler ;
  - API agent (`/api/v1/agent/`) : jeton d'agent, limitation par jeton, pas de session ni
    de CSRF ;
  - API utilisateur (`/api/v1/orgs/{org}/`) : jeton personnel sans CSRF, ou session avec
    en-tête CSRF pour le JavaScript de l'interface.
- CSP : `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  frame-ancestors 'none'; form-action 'self'; base-uri 'none'`. Aucun script ni style en
  ligne. Réponses d'API : `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`.
- Gabarits `html/template` : un layout, des partials, un dossier par écran. Chaque écran a
  un modèle de vue typé construit dans `internal/web/<écran>` ; les gabarits ne font que de
  l'affichage. Les fonctions de traduction sont liées à un jeu de gabarits par page et par
  langue, préparé au démarrage ; ce qui dépend de la requête (jeton CSRF, thème,
  identifiant de requête) passe par `render.Page`, que le rendu remplit (ADR 0009).
- CSS natif imbriqué, sans préprocesseur : `tokens.css` (propriétés personnalisées, thèmes
  clair et sombre : couleurs en `light-dark()`, qui suit `prefers-color-scheme`, et
  `color-scheme` imposé par `[data-theme]`), `fonts.css`, `base.css`, un fichier par
  composant et par écran. Modificateurs BEM écrits `&.bloc--modificateur`. Au démarrage, le
  serveur concatène les feuilles embarquées en `css/app.css` et sert tous les fichiers
  statiques sous `/static/<empreinte>/` (immuables, un an de cache). La bascule de thème
  mémorise le choix dans `localStorage` et dans le cookie `ogsbom_theme`, que le serveur
  lit pour rendre `data-theme` dès la première peinture, sans script en ligne.
- JavaScript : modules ES natifs, un par écran, amélioration progressive ; chaque page
  fonctionne sans JS. Les libellés arrivent traduits via des attributs `data-`.
- Graphiques en SVG produits côté serveur, avec titre, description et tableau de données.
- Accessibilité RGAA / WCAG 2.1 AA : HTML sémantique, lien d'évitement, focus visible,
  sévérité jamais portée par la seule couleur. Des tests Go analysent le HTML rendu ; un
  audit manuel clôt chaque lot fonctionnel.

## 15. API REST

- `api/openapi.yaml` est la source unique, en OpenAPI 3.1.0 (ADR 0006) ; serveur et client
  des agents sont générés par oapi-codegen dans `internal/api/gen` et
  `internal/agentclient/gen`. `make generate-check` vérifie en CI que le code généré est à
  jour.
- Préfixe `/api/v1`. Routes des agents sous `/api/v1/agent/`, routes utilisateur sous
  `/api/v1/orgs/{org}/`. Le point compatible Dependency-Track (T19) vit sous `/dt/` pour ne
  pas mêler son espace d'URL au nôtre.
- Erreurs au format RFC 9457 (`application/problem+json`) : `type` porte une clé stable
  (`error.ingest.too_large`), `title` et `detail` les messages traduits de
  `<clé>.title` et `<clé>.text` selon la langue de la requête, `instance` le chemin et
  `request_id` l'identifiant de requête (`internal/api/problem`).
- Pagination par curseur opaque. Toute réponse liste est bornée.

## 16. File de traitements

`internal/jobs`, sur PostgreSQL, sans dépendance, sémantique **au moins une fois** :

- Table `jobs` : type, organisation (facultative), charge JSON, priorité, statut,
  tentatives, prochaine exécution, bail (`locked_until`), clé d'unicité, dernière erreur.
- Prise par `SELECT … FOR UPDATE SKIP LOCKED` ; bail renouvelé pendant l'exécution ; un job
  dont le bail expire est repris. Chaque handler est idempotent (exigence de revue).
- La table `jobs` est globale ; un handler qui touche des données d'organisation travaille
  dans `InOrg(job.OrgID)`. Les rares jobs inter-organisations (`analysis.rescan_all`,
  statistiques quotidiennes) obtiennent leur liste par une fonction de `crossorg`, puis
  mettent en file un job par organisation.
- Réessais à délai exponentiel avec gigue ; au-delà du maximum, statut `dead`.
- Clé d'unicité sur les jobs en attente ; une seconde mise en file **relève la priorité** et
  avance l'échéance si besoin (`ON CONFLICT … DO UPDATE`) : une ingestion fraîche n'attend
  pas derrière une réanalyse de fond.
- Plafond de jobs simultanés par organisation pour les types lourds (décodage, analyse) :
  une organisation ne peut pas affamer les autres.
- Planificateur : une ligne par échéance dans `schedules` ; chaque instance tente
  `UPDATE schedules SET next_run_at = … WHERE name = … AND next_run_at <= now() RETURNING …`
  et seule celle qui obtient la ligne met le travail en file. Pas de verrou de session :
  robuste aux coupures de connexion et à pgbouncer.
- Détails (ADR 0011) : dates calculées par une horloge Go injectable (`jobs.Clock`),
  jamais par `now()` de PostgreSQL, d'où des instances synchronisées par NTP ; prise des
  jobs au bail expiré d'abord, puis des jobs en attente par l'index partiel ; plafond tenu
  strictement par un verrou consultatif de transaction par (type, organisation) ;
  `lease_token` pour ignorer le résultat d'un bail perdu ; transitions d'état du runner
  validées en `synchronous_commit = off` ; `Stop` remet en attente, sans compter la
  tentative, les jobs encore en cours à l'approche de son délai ; échéances sur une grille
  UTC fixe ; purge des jobs terminés et passage en `dead` des jobs épuisés au bail expiré
  par une maintenance sur chaque instance.

## 17. Agents

- Client API commun `agentclient` (généré), avec réessais bornés, délai exponentiel et
  respect de `Retry-After` ; certificat client facultatif (mTLS).
- Inscription : jeton d'inscription → jeton d'agent stocké dans le répertoire d'état
  (droits `0600`).
- Secrets des agents (jeton, clés de forge, clés d'API des modèles) : jamais dans le fichier
  de configuration. Ils sont fournis par les credentials systemd (`LoadCredentialEncrypted=`,
  chiffrés au repos) ou par des fichiers en `0600`, au choix de l'exploitant.
- `ogsbom-host-agent` : voir T07 (hôte), T13 (conteneurs), T22 (Windows), T23 (hors ligne).
- `ogsbom-repo-agent` : service externe qui détient seul les secrets des forges. Il reçoit les
  webhooks, clone, analyse, envoie, puis attend le verdict du serveur pour publier le statut
  de commit (T15). Tout accès au contenu d'un dépôt passe par `os.Root` (aucune sortie de
  l'arborescence, aucun lien symbolique suivi hors d'elle). Voir T08 et T12.
  Détails (ADR 0023) : un webhook vérifié n'est qu'un signal, l'agent résout lui-même la
  tête de la référence ; rattrapage au démarrage et à intervalle depuis le commit du
  dernier instantané, commits manqués du plus ancien au plus récent ; file en mémoire
  bornée, une référence jamais traitée deux fois à la fois ; extraction du commit exact
  par `git fetch --depth 1 <url> <commit>` sous environnement maîtrisé
  (`core.symlinks=false` : aucun lien symbolique sur disque, ce qu'un parcours par
  `os.Root` vérifie ; crochets et LFS inertes ; identifiants par `GIT_CONFIG_*`), taille
  mesurée pendant le clonage ; Syft, qui lit l'arborescence par son propre résolveur
  borné à sa racine, hors ligne et sans exécution (`golang.UsePackagesLib=false`) ; SBOM
  CycloneDX 1.6 déterministe (ni numéro de série ni horodatage) ; secrets désignés par
  `credential:<nom>` ou par un fichier `0600`. Configuration (`OGSBOM_REPO_*`) et unité
  systemd : `deploy/ogsbom-repo-agent/`.

## 18. Internationalisation

- `locales/en.yaml` et `locales/fr.yaml`, embarqués (`i18n.NewFS`). Langue choisie dans cet
  ordre : `?lang=`, préférence du compte, `Accept-Language`, langue de l'organisation, langue
  par défaut de l'instance. Le middleware de langue précède la garde d'organisation
  (§ 14) : celle-ci (T03) recalcule la langue avec la langue de l'organisation
  (`middleware.ResolveLanguage`). Hors requête, `locale.Catalog` donne le localiseur
  d'une langue.
- Clés en anglais `écran.élément` (`login.email`, `search.placeholder`). Racines
  transverses : `format.*`, `status.*`, `severity.*`, `validation.*`, `error.*`, `nav.*`.
- Le code serveur ne concatène jamais de fragments traduits : il renvoie une clé et des
  paramètres que le gabarit résout, ou reçoit le traducteur.
- Les textes émis hors ligne de requête (notifications, résumés) utilisent la langue de
  l'organisation.
- Un test échoue si une clé manque dans une langue ou si un gabarit utilise une clé absente.

## 19. Sécurité transverse

- Modèle de menace tenu à jour dans `docs/security/threat-model.md` (créé en T00).
- Secrets stockés en base (secrets des canaux de notification, secret client OIDC…)
  chiffrés en AES-256-GCM par `internal/secret`, clé maîtresse en configuration,
  identifiant de clé stocké avec le chiffré pour permettre la rotation. Les secrets des
  forges ne sont jamais en base : ils restent dans l'agent dépôt.
- Aucune donnée sensible dans les journaux (mots de passe, jetons, contenu de SBOM).
- Entrées bornées partout : taille de requête, taille décompressée, profondeur JSON, nombre
  de composants.
- Contenu des dépôts et des SBOM traité comme non fiable, y compris par l'agent IA
  (injection d'instructions).
- L'accès à la socket d'un moteur de conteneurs équivaut à root : désactivé par défaut,
  documenté comme tel.
- Journal d'audit : connexions et échecs, comptes et rôles, jetons, organisations, équipes,
  décisions de triage, politiques, canaux, paramètres d'organisation.
- Gravité des faiblesses évaluée selon l'OWASP Risk Rating ; chaque revue de recette est
  menée par un relecteur distinct de l'auteur du code.

## 20. Observabilité et exploitation

- Journaux `slog` (via `logx`), JSON en production, champs `request_id`, `org`, `job`.
- Écoute de gestion séparée : `/metrics` (Prometheus), `/healthz`, `/readyz`. `/readyz`
  vérifie la base et les migrations sur toutes les instances, et la base Grype chargée
  seulement si `workers.enabled` : une instance purement web reste disponible, y compris
  pour importer une base sur un site isolé. Dès le début d'un arrêt, `/readyz` répond 503.
- Arrêt propre sur SIGTERM : fin des requêtes en cours, libération des baux de jobs.
- `docs/operations.md` : installation, configuration, sauvegarde, mise à jour, rotation des
  clés, sites isolés, procédure de secours des administrateurs.

## 21. Tests et barrières de qualité

- `make ci` (identique en CI) : `gofmt`, `go vet`, `staticcheck`, `govulncheck`, tests
  `-race`, tests d'intégration PostgreSQL (dont les tests RLS du § 9, exécutés avec le rôle
  d'exécution réel), tests d'architecture, complétude des traductions, code généré à jour.
- Tests d'intégration contre un vrai PostgreSQL (`OGSBOM_TEST_DATABASE_DSN`, fourni par
  `deploy/compose.yaml` en local et par un service en CI), base jetable par test.
- SBOM d'exemple dans `testdata/sbom/` (CycloneDX 1.5, 1.6, 1.7, SPDX 2.3, Syft JSON),
  dont des SBOM d'hôtes Debian, RHEL et Alpine ; fichiers attendus (« golden »).
- Fuzzing natif Go : purl, `vers`, requêtes de recherche, bornes préalables, décodage.
- Grype est remplacé par un faux `vuln.Matcher` dans les tests unitaires ; un test
  d'intégration étiqueté `grypedb` utilise une vraie base.
- **Cibles chiffrées** mesurées selon `docs/benchmarks.md` (écrit en T06) : machine de
  référence, jeu de données synthétique, 95e centile, cache froid et chaud. Une cible non
  tenue garde le lot ouvert, sauf nouvelle cible validée par l'utilisateur et reportée au
  cahier des charges.
- Couverture : 80 % au moins sur les paquets métier, hors code généré ; chaque règle métier
  a un test qui la nomme.
- La plateforme publie son propre SBOM et s'analyse elle-même dès que T06 est livré.

## 22. Conventions de code

- `gofmt`, noms explicites, fonctions courtes, erreurs enveloppées avec `%w` et contexte.
- Commentaires : uniquement le « pourquoi » non évident ; doc de paquet dans `doc.go`.
- `context.Context` en premier paramètre de toute fonction qui fait des E/S.
- Pas de `panic` hors initialisation ; pas de goroutine sans propriétaire ni arrêt.
- Commits atomiques au format conventionnel en français (`feat(ingest): …`), comme dans
  open-go-base.

## 23. Évolutions à proposer à open-go-base

open-go-base est un autre dépôt ; ces évolutions y sont proposées par l'utilisateur ou avec
son accord, au plus tard au lot indiqué. En attendant, le projet les contourne sans les
dupliquer.

| Évolution | Pourquoi | Avant |
| --- | --- | --- |
| Erreurs d'authx, mfax et csrfx exposées comme clés plutôt qu'en texte français | Messages traduits (« Identifiants invalides », « Code invalide », « Accès interdit », réponse 403 de csrfx) | Fait en T03 (PR #1 d'open-go-base) |
| Gestionnaire d'échec configurable dans csrfx | Page 403 traduite et au format du projet | Fait en T03 (PR #1 d'open-go-base) |
| Clé de limitation configurable dans `ratelimit` (par jeton) | Évite le limiteur maison de `internal/ratelimit` | Fait en T04 (`WithKeyFunc`, PR #2 d'open-go-base) |
| Codes de secours dans mfax | Récupération sans administrateur d'instance | T11 |
| Composant `oidcx` | SSO réutilisable par les projets open-go | T25 |
