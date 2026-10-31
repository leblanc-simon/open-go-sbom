# Leçons et pièges connus

À lire avant chaque lot ; à compléter à la fin de chaque lot avec les erreurs commises et
les pièges découverts, pour ne pas les reproduire. Une entrée = le constat, puis la règle.

## Environnement et outillage

- **Chaîne Go** : `go.mod` fixe `toolchain go1.26.10`. Une machine avec un Go plus ancien
  télécharge la bonne chaîne d'elle-même (`GOTOOLCHAIN=auto`) ; ne pas modifier la ligne
  `toolchain` pour s'adapter à la machine.
- **PostgreSQL local** : sans Docker, un PostgreSQL 16 natif convient ; le mot de passe du
  rôle `postgres` doit valoir `postgres` pour le DSN par défaut du Makefile.
- **Proxy réseau** : un téléchargement de module peut échouer ponctuellement
  (`ws_closed_mid_exchange`) ; relancer la commande, ne pas changer de version pour autant.

## Anchore

- `syft.GetSource(ctx, "dir:/chemin", nil)` interprète le préfixe comme un registre
  d'images : passer le chemin nu et `syft.DefaultGetSourceConfig().WithSources("dir")`.
- Syft échoue sur les bases RPM récentes sans pilote SQLite enregistré : importer
  `_ "modernc.org/sqlite"` dans tout binaire qui catalogue (agents, tests).
- La base Grype v6 fait environ 3,2 Gio décompressée et met plusieurs minutes à
  télécharger : jamais dans les tests unitaires ; tests réels sous l'étiquette `grypedb`,
  avec un répertoire de base fourni par variable d'environnement.
- Les identifiants de vulnérabilité de Grype sont ceux de la source (GHSA pour Java…) ;
  le rattachement aux CVE passe par les alias ou `NormalizeByCVE`.

## Git et intégration

- Ne pas réécrire une branche déjà poussée (force-push refusé) : préférer un commit
  correctif, ou une fusion « squash » de la PR.
- Commits signés « Simon Leblanc <contact@leblanc-simon.eu> », avec la ligne
  `Co-Authored-By` de Claude.

## Base de données (T01)

- **Tableaux pgx via `database/sql`** : passer une `[]string` en paramètre marche, mais la
  relire (`Scan(&slice)`) échoue (« unsupported Scan »). Règle : `row.Scan(db.Array(&s))`.
  Pour `[]uuid.UUID`, pgx exige d'enregistrer les types **pointeurs** (`*[]uuid.UUID`) :
  `db.Array` le fait.
- **RLS et `current_setting`** : jamais `current_setting('ogsbom.org_id', true)` dans une
  politique (NULL, donc zéro ligne en silence). Après un `set_config(…, true)`, le
  paramètre ne disparaît pas en fin de transaction : il vaut `''` sur la connexion, et
  `''::uuid` échoue. Les tests RLS couvrent les deux cas (connexion neuve, connexion
  réutilisée) avec un pool d'une connexion.
- **Privilèges par défaut** : `ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE ON FUNCTIONS
  FROM PUBLIC` n'a d'effet que sans `IN SCHEMA`. Toute nouvelle table d'organisation :
  `CALL ogsbom_enforce_org_rls('table')`, sinon le serveur refuse de démarrer.
- **Migration sans nom de rôle en dur** : le rôle d'exécution est dans
  `current_setting('ogsbom.app_role')`, à citer par `format('%I')`. Une migration est
  exécutée dans la transaction du verrou : pas de `CREATE INDEX CONCURRENTLY`.
- **Tests d'intégration** : toujours `dbtest.New(t)` (base et rôles jetables) ; jamais de
  base nommée en dur. Une base de développement manuelle prend un nom propre au lot et se
  supprime après usage.

## Go, open-go-base et chi (T01)

- **appconf** : `Load` lit `os.Args` (les options de `go test` font échouer l'analyse) et
  termine le programme sur `--help`. Règle : dans les tests, fixer `os.Args`, et tester
  `--help` dans un sous-processus. Un `env-default` ne s'applique qu'à un champ vide :
  poser les défauts du projet avant `Load` (`config.Defaults`) ; `--help` affiche quand
  même celui d'appconf.
- **cleanenv** accepte un fragment embarqué avec `yaml:",inline"` : variables et YAML
  fonctionnent (`config.Database`).
- **go-i18n** prend pour un message toute table YAML qui contient un nom réservé
  (`description`, `id`, `hash`, `translation`…) : ses clés disparaissent en silence. Le
  test de `locales` l'interdit ; ne pas nommer un élément ainsi.
- **chi** : un sous-routeur sans aucune route n'exécute pas ses propres middlewares
  (sa réponse NotFound part sans en-têtes ni journal). Monter un groupe par
  `r.With(mws...).Route(…)`. `middleware.GetHead` ne marche qu'au niveau racine, avant le
  routage. Le `NotFound` racine ne passe pas par les middlewares d'un groupe : l'envelopper
  explicitement (`chi.Chain(...).Handler`).
- **html/template** échappe à la première exécution : `render` force l'échappement au
  démarrage pour qu'un gabarit ambigu échoue tôt. Cloner un jeu par requête coûte cher
  (ADR 0009).
- **Course de données** : `http.Server.Serve` modifie `TLSConfig` (HTTP/2) ; ne pas le
  relire depuis une autre goroutine. La sortie d'un `exec.Cmd` lue pendant qu'il tourne
  passe par un tampon protégé par un mutex.
- **TLS** : le client Go n'envoie pas un certificat client d'une autorité que le serveur
  n'annonce pas ; pour tester un refus, forcer `GetClientCertificate`.
- **`go get module/paquet` sans version** monte le module à sa dernière version : préciser
  la version du graphe (`@v0.61.0`) si on ne veut pas de montée.

## File de traitements (T02)

- **`SetMaxIdleConns(0)`** ne garde aucune connexion inactive (ce n'est pas « le défaut ») :
  chaque transaction rouvrait une connexion et refaisait l'authentification, 12 ms par
  transaction en test. Règle : `db.PoolConfig.MaxIdleConns` nul garde le défaut de
  `database/sql` ; un pool très sollicité règle `MaxIdleConns` égal à `MaxOpenConns`.
  Une lenteur uniforme d'environ 10 ms par transaction en local signale ce piège.
- **cleanenv et booléens** : un `env-default:"true"` s'applique à un champ resté à sa
  valeur zéro, donc écrase `enabled: false` lu dans le fichier. Règle : un booléen vrai
  par défaut n'a pas d'`env-default`, son défaut se pose dans `config.Defaults` (et
  un test charge un fichier qui le met à `false`).
- **Numéros de migration en dur dans les tests** : les tests de l'exécuteur ajoutaient
  `002_*.sql`, cassés dès la vraie migration 002. Règle : migrations de test nommées
  `+N_sujet.sql` (`withMigrations` calcule le numéro), et aucune table de test ne porte
  le nom d'une table réelle (`jobs`).
- **`OR` dans une requête de prise** : `(status = 'pending' AND …) OR (status = 'running'
  AND …)` empêche l'index partiel ordonné et trie toute la file à chaque prise (O(n)).
  Règle : une requête par cas, chacune sur son index partiel, vérifiée par `EXPLAIN
  ANALYZE` (attendu : `Index Scan using jobs_pending`, arrêt à la première ligne).
- **Arrêt et prise concurrente** : un job pris pendant que `Stop` relève les jobs à
  libérer lui échappe (son bail resterait actif). Règle : la prise et son inscription
  parmi les jobs en cours se font sous un verrou que `Stop` prend avant de relever.
- **Délai de `Stop` sous charge** : libérer les baux un par un à 150 ms de l'échéance a
  échoué sous charge (`driver: bad connection`, vraisemblablement le contexte expiré en cours de requête). Règle :
  une seule instruction pour tous les baux, et une marge d'un quart du délai (2 s au
  plus).
- **Horloge injectable et `Enqueue`** : `Enqueue` date avec l'horloge du système ; une
  horloge de test en retard sur l'heure réelle ne voit pas les jobs échus. Règle : la
  fausse horloge part après l'heure réelle et n'avance que vers l'avant ; elle est
  arrondie à la microseconde pour comparer exactement les `timestamptz` relus.
- **Tuer un worker pour de vrai** : le test « worker tué » relance le binaire de test en
  sous-processus (`os.Args[0] -test.run=…` et une variable d'environnement) et le tue par
  `SIGKILL`, plutôt que de simuler une panne dans le même processus.

## Outillage (T01)

- **`make generate-check`** échoue tant que le code généré n'est pas commité (fichiers
  non suivis ou seulement indexés) : committer avant de lancer `make ci`.
- **Variables d'environnement** : chaque appel de commande repart d'un shell neuf ; un
  `export` ne survit pas. Passer `OGSBOM_TEST_DATABASE_DSN=…` sur la ligne, ou passer par
  `make test-integration` qui le pose.
- **Captures d'écran** : `google-chrome --headless=new --screenshot` est disponible ;
  `--blink-settings=preferredColorScheme=0` simule le thème sombre du système.

## Comptes, RLS et open-go-base (T03)

- **RLS forcée et `SECURITY DEFINER`** : `FORCE ROW LEVEL SECURITY` soumet aussi le
  propriétaire ; une fonction `SECURITY DEFINER` qu'il possède ne lit rien sans
  organisation déclarée (erreur sur `''::uuid`). Règle : le propriétaire a `BYPASSRLS`
  (ADR 0012), vérifié par la migration 005 ; dans `dbtest`, le rôle propriétaire est créé
  avec cet attribut.
- **Tables d'authx et de mfax créées avant 001** : sur une base neuve, leur `Migrate` passe
  avant les privilèges par défaut du projet ; le rôle d'exécution n'y a alors aucun droit.
  Règle : droits accordés explicitement par une migration du projet (003).
- **Paramètre SQL réutilisé avec deux types** : `VALUES ($1, … left($1::text, 8))` échoue
  (« inconsistent types deduced for parameter $1 »). Règle : caster chaque occurrence
  (`$1::uuid`). Et un UUID v7 commence par l'horodatage : ses 8 premiers caractères se
  répètent d'un test à l'autre, prendre la fin pour un slug unique.
- **Écrire après `WriteHeader`** : mfax appelle `w.WriteHeader(401)` avant le `Renderer` ;
  le rendu ne peut plus poser son `Content-Type`. Règle : envelopper le `ResponseWriter`
  (`deferredHeader`) pour retenir le statut jusqu'à la première écriture.
- **`wrap(err)` sans test de nil** : une fonction d'enveloppe d'erreur qui ne renvoie pas
  `nil` pour `nil` transforme chaque succès en échec (`%!w(<nil>)`). Règle : `if err ==
  nil { return nil }` en tête, et un test d'intégration du cas nominal dès le premier
  appel.
- **Gabarits et texte en dur** : le test de `render` refuse toute lettre hors action de
  gabarit, même « UTC ». Règle : clé `format.utc`. Un champ caché `<input hidden>` sans
  libellé fait aussi échouer l'assistant d'accessibilité.
- **Gabarit partagé entre pages** : un `{{define}}` placé dans le fichier d'une page n'est
  pas vu des autres pages (un jeu par page). Règle : les blocs communs vont dans
  `partials/`.
- **Outil d'isolement des agents** : les longues commandes shell composées (heredoc
  python, `for … do git`) sont refusées dans un worktree isolé. Règle : écrire les scripts
  d'édition dans le répertoire temporaire et les lancer par une commande simple ; une
  commande git par appel, avec `git -C` pour un autre dépôt.
- **Pousser une étiquette** : le mandataire git de la session refuse les pushs
  d'étiquettes (HTTP 403) mais accepte les branches. Règle : pseudo-version du commit
  fusionné (`go get module@<sha>`), étiquette annotée créée seulement dans le clone local,
  et action consignée pour l'utilisateur dans la section « Actions pour l'utilisateur » de
  `specs/avancement.md` (et dans le Journal). Ne pas chercher à la pousser autrement.
- **Tests d'un binaire et configuration obligatoire** : rendre un réglage obligatoire
  (`secrets.keys`) casse le test de bout en bout du binaire, qui part d'un environnement
  vide. Règle : mettre à jour `start()` de `cmd/ogsbom-server/main_integration_test.go`
  dans le même commit.
- **Codes TOTP en test** : mfax refuse un pas déjà consommé et tolère ±1 pas. Règle : au
  plus trois connexions TOTP par compte et par test, avec des pas croissants (−30 s, 0,
  +30 s) ; voir `app.code` dans `internal/web/app_integration_test.go`.

## Projets, agents et API générée (T04)

- **Index git partagé entre commits** : un `git rm` fait tôt reste indexé et part dans le
  commit suivant, même si celui-ci n'ajoute (`git add`) que d'autres chemins. Règle :
  supprimer un fichier dans le commit qui en tire la conséquence (`git rm` juste avant
  lui), et relire `git show --stat` après chaque commit.
- **oapi-codegen, client** : le client génère un type `<OperationId>Response` par
  opération ; un schéma nommé `EnrollResponse` pour l'opération `enroll` entre en
  collision (« redeclared »). Règle : nommer les schémas de réponse autrement
  (`EnrollmentResult`, `HeartbeatStatus`).
- **oapi-codegen, chi** : le serveur généré enregistre les chemins complets du contrat
  (`/agent/enroll`, relatifs à `servers: /api/v1`) sur le routeur fourni. Le monter dans
  `Route("/api/v1/agent")` donnerait `/api/v1/agent/agent/enroll`. Règle : groupe dans le
  sous-routeur `/api/v1`, `NotFound` et `MethodNotAllowed` de ce sous-routeur enveloppés
  dans la chaîne d'API (`chi.Chain(...).Handler`).
- **Limitation par clé** : une clé lue telle quelle dans la requête (identifiant public
  d'un jeton non vérifié) donnerait un compteur neuf par valeur inventée. Règle : la clé
  est posée par le middleware d'authentification, le limiteur passe après lui ; les refus
  passent par un limiteur par IP placé sur le seul chemin du refus.
- **Captures d'écran** : une page enregistrée en fichier et ouverte en `file://` ne charge
  pas les feuilles du serveur (`Cross-Origin-Resource-Policy: same-origin`). Règle : servir
  la page capturée depuis un serveur de test de même origine, qui relaie `/static/` vers
  l'application (`httputil.NewSingleHostReverseProxy`).
- **Onglets** : `overflow-x: auto` avec des liens à `margin-bottom: -1px` fait apparaître
  une barre de défilement verticale. Règle : `overflow-y: hidden` sur `.tabs`.
- **Couverture par paquet** : `go test -cover` ne compte que les tests du paquet lui-même ;
  `agent` qui appelle `project.ListForAgent` ne couvre pas `project`. Règle : chaque
  paquet métier teste ses propres fonctions exportées, même celles qu'un autre paquet
  exerce déjà.
- **Outil d'isolement des agents (suite)** : refusées aussi, les commandes qui citent un
  DSN entre guillemets (`'postgres://…'`) ou combinent `cd sous-dossier && heredoc`.
  Règle : DSN sans guillemets (`OGSBOM_TEST_DATABASE_DSN=postgres://…?sslmode=disable go
  test …`), fichiers écrits par l'outil d'écriture, éditions multiples par un script
  Python du répertoire temporaire lancé seul.
