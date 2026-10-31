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

## Ingestion, Syft et schémas (T05)

- **Énumérations figées des schémas officiels** : le `spdx.schema.json` de CycloneDX 1.6
  ne connaît pas « Artistic-dist », que Syft v1.55.0 écrit en `license.id` ; un SBOM
  légitime produit par Syft échouait à la validation. Règle : à la réception, ne pas
  imposer l'énumération des licences (`schema.Validator.Validate`) ; pour ce que le
  serveur produit, `ValidateStrict` et réécriture en `license.name`
  (`syft.Encode(…, CycloneDXLicenseIDs("1.6"))`). Un test le prouve sur un vrai SBOM.
- **packageurl-go canonicalise plus que prévu** : il met en minuscules les noms golang
  (`github.com/BurntSushi/toml` → `burntsushi`) et n'encode pas « : » dans la version
  (`1:2.36-9`), contrairement à la sortie de Syft (`1%3A…`). Règle : toute comparaison de
  purl passe par `sbom.CanonicalPURL`/`ComponentPURL` des deux côtés, jamais par la chaîne
  du document.
- **Fusion de doublons et ordre** : une première version de `merge` départageait deux
  mentions au même rang sans regarder la confiance (`nil` contre `0`) ; le résultat
  dépendait de l'ordre du document, trouvé par `FuzzNormalize` en quelques secondes. Règle :
  un départage par ordre total sur tous les champs non fusionnés, et un fuzz « ordre
  inversé = même empreinte » pour toute normalisation.
- **Les décodeurs JSON de Go ignorent la casse des clés** : `"COMPONENTS"` ou
  `"components"` sont lus comme `components` par `encoding/json`. Règle : un
  contrôle préalable compare les clés décodées (échappements `\u` compris) sans tenir
  compte de la casse, sinon il se contourne.
- **Mémoire du décodage** : le pic du tas vaut environ trente fois la taille du SBOM
  (décodeurs de Syft + schéma JSON). Règle : dimensionner les bornes par défaut sur cette
  mesure (64 Mio décompressés), la documenter pour l'exploitation (ADR 0015).
- **Syft décode `metadata.component` comme un paquet** et ne garde ni les empreintes, ni la
  portée, ni les propriétés inconnues d'un composant CycloneDX. Règle : relire le document
  pour ces champs (index par `bom-ref`, qui devient l'identifiant du paquet Syft ; SPDXID
  sans `SPDXRef-` pour SPDX) et exclure le composant décrit.
- **Jeux d'essai réalistes sans Docker** : un système de fichiers factice (`/etc/os-release`
  + base de paquets) catalogué par Syft donne de vrais SBOM d'hôte ; les bases RPM réelles
  existent dans les jeux d'essai de `github.com/anchore/go-rpmdb` (cache des modules). Les
  chemins absolus du répertoire temporaire se retrouvent dans les SBOM (noms de fichiers,
  SPDXID) : les retirer avant de committer.
- **Outil d'isolement des agents (suite)** : refusés aussi les `for` en shell, les
  accolades `{a,b}` dans un chemin et `cd … && python3 - <<EOF`. Règle : script dans le
  répertoire temporaire lancé seul (`python3 -I script.py`), ou `python3 -I -c "…"` sans
  `cd` préalable, ou l'outil d'édition.
- **`rm` d'un motif relatif après `cd`** est bloqué par la protection contre les
  suppressions : écrire dans un nouveau dossier plutôt que vider l'ancien, et supprimer un
  fichier par son chemin absolu.

## Analyse de vulnérabilités et base Grype (T06)

- **Le client de distribution de Grype décompresse au téléchargement** : `Download` passe
  par go-getter en mode répertoire, qui extrait le tar.zst ; il ne reste aucune archive à
  stocker, et l'appel ne prend pas de contexte. Règle : télécharger par un `vuln.Fetcher`
  injecté (`internal/download`, `net/http`) et n'utiliser de Grype que la lecture de
  `latest.json` (`NewLatestFromReader`) et `ResolveArchiveURL`.
- **Une vraie base Grype sans 3 Gio** : `v6.NewWriter` + `SetDBMetadata` + `Close` donne
  une base v6 vide mais valide, qu'une archive tar.gz (bibliothèque standard) rend
  installable par le curateur. Règle : `grypetest.TinyArchive` pour tout test
  d'installation, d'ouverture ou de bout en bout ; la vraie base reste sous `grypedb`.
- **Dates relues de PostgreSQL** : `timestamptz` arrondit à la microseconde ; comparer une
  date Go (nanosecondes) à sa relecture échouait (« base locale du …027, attendue du
  … »). Règle : arrondir (`Round(time.Microsecond)`) avant d'écrire une date qu'on
  comparera, et comparer après arrondi.
- **`NormalizeByCVE` ne remplace pas les métadonnées** : Grype change l'identifiant (GHSA
  → CVE) mais laisse la fiche de la source d'origine sur la correspondance. Règle : lire la
  fiche NVD du CVE (`VulnerabilityMetadata`, espace `nvd:cpe`) pour le catalogue ; une
  fiche absente revient comme une souche (sans CVSS ni description), à détecter.
- **Les attributs de gabarit numériques** : une largeur de jauge par `style="--p: 94%"`
  est refusée par la CSP. Règle : jauges en SVG, largeur en attribut (`<rect width>`),
  calculée par la fonction `barWidth` ; nombres localisés par `decimal` et `percent`
  (`golang.org/x/text/number`), jamais formatés en Go dans la vue.
- **Valeur d'attribut en dur** : le test de `render` refuse `value="resolved"` dans un
  gabarit. Règle : la valeur vient de la vue (`StatusValue`).
- **Nouveau SBOM d'exemple** : `TestGolden` parcourt tout `testdata/sbom/` ; un fichier
  ajouté sans attendu fait échouer `make ci`. Règle : `go test ./internal/sbom/syft -run
  TestGolden -update`, relire l'attendu, compléter `testdata/sbom/README.md`.
- **Instances worker et `/readyz`** : depuis T06, une instance à workers n'est prête
  qu'avec une base de vulnérabilités chargée ; le test de bout en bout du binaire importe
  une base (`grypetest`) et passe `OGSBOM_VULNDB_OFFLINE=true` pour ne jamais sortir sur le
  réseau. Règle : tout nouveau test qui attend `/readyz` sur une instance à workers fait de
  même (ou `OGSBOM_WORKERS_ENABLED=false`).
- **Commandes Anchore en CI sans action tierce** : `go run github.com/anchore/syft/cmd/syft@<version>`
  (et grype) fonctionne (aucune directive `replace`), compile en une quinzaine de secondes
  et reprend les versions de `go.mod` (`go list -m -f '{{.Version}}'`). Le champ KEV du
  JSON de grype est `.matches[].vulnerability.knownExploited`.
- **Tests concurrents d'une bascule** : un crochet (`Hook`) dans la fausse base qui bloque
  les correspondances sur un canal permet de prouver qu'une bascule attend les
  correspondances en cours, sans `time.Sleep` fragile pour la synchronisation.
- **Outil d'isolement des agents (suite)** : refusés aussi `cat >> fichier <<EOF` et
  `python3 script && git …` dans la même commande. Règle : écrire par l'outil d'écriture,
  une commande git seule par appel.

## Agent dépôt et forges (T08)

- **Syft exécute la chaîne Go par défaut** : `golang.DefaultCatalogerConfig()` met
  `UsePackagesLib: true`, qui lance `go list` (`golang.org/x/tools/go/packages`) sur le
  répertoire scanné, avec téléchargements possibles (`GOTOOLCHAIN`, modules). Règle : sur
  un contenu non fiable, partir de `pkgcataloging.DefaultConfig()` et couper
  `Golang.UsePackagesLib`, les recherches de licences distantes et locales, le réseau de
  Java (`repoagent.offlineCatalogers`). Chercher `os/exec` et `go/packages` dans les
  sources de Syft à chaque montée de version.
- **Pilote SQLite oublié** (piège déjà connu, retombé dedans) : le premier scan a échoué
  sur « sqlite driver is required ». Règle : l'import `_ "modernc.org/sqlite"` vit dans le
  paquet qui appelle `syft.CreateSBOM` (`repoagent/scan.go`), pas seulement dans le
  binaire, pour qu'aucun test ni binaire ne l'oublie.
- **SBOM de Syft non déterministe** : `serialNumber` aléatoire et `metadata.timestamp`
  rendent chaque analyse d'un même commit différente, donc une nouvelle ingestion côté
  serveur. Règle : les retirer (facultatifs en CycloneDX) et tester que deux analyses
  donnent les mêmes octets. Le composant décrit porte sinon le chemin temporaire : le
  nommer par `source.Alias`.
- **Clone d'une branche ≠ commit à rattraper** : `clone --depth 1 --single-branch` ne
  donne que la tête. Règle : `git init` + `git fetch --depth 1 <url> <commit>` ; un dépôt
  nu de test doit avoir `uploadpack.allowReachableSHA1InWant=true` pour le protocole v0,
  et l'URL locale doit être `file://` (un chemin nu ignore `--depth`).
- **git en test par HTTP sans service externe** : `net/http/cgi` avec `git http-backend`
  (`GIT_PROJECT_ROOT`, `GIT_HTTP_EXPORT_ALL=1`) sert un dépôt nu derrière un
  `httptest.Server`, ce qui permet de vérifier l'en-tête d'authentification et de
  simuler un clonage lent.
- **Vérifier « pas dans `ps` »** : envelopper git dans un script qui note `"$*"` et le
  passer comme binaire (`work.git`), puis chercher le jeton et sa forme base64 dans la
  trace et dans les journaux.
- **Réponse du client généré qui ne suit pas le contrat** : les méthodes
  `…WithResponse` d'oapi-codegen décodent le corps selon le statut et **échouent** si le
  JSON ne correspond pas (un faux serveur de test renvoyait un problème en 202). Règle :
  pour un appel où seuls le statut et la clé d'erreur comptent, utiliser la méthode brute
  et une lecture bornée.
- **Assistant de test appelé seulement par les tests `integration`** : staticcheck (sans
  étiquette) le signale inutilisé (U1000). Règle : le placer dans le fichier étiqueté, et
  lancer aussi `go tool staticcheck -tags integration` sur les paquets touchés.
- **Outil d'isolement des agents (suite)** : refusée aussi une commande qui enchaîne
  `git add`, `git commit` et `make` ; une commande git par appel.
## Agent serveur, paquets et lots parallèles (T07)

- **Numéros de migration attribués d'avance** : l'exécuteur exige des numéros contigus
  (« migrations non contiguës ») ; une migration 011 sans 009 ni 010 sur `main` ne passe
  pas. Règle : un numéro attribué est provisoire ; avant d'ouvrir la PR et à chaque
  intégration de `origin/main`, renommer sa migration au premier numéro libre après la
  dernière de `main`. Jamais de migration factice pour combler un trou.
- **`GOARCH=… go tool nfpm`** construit l'outil pour cette architecture
  (`exec format error`). Règle : ne jamais passer `GOOS`/`GOARCH` à un `go tool` ; nfpm
  lit ses propres variables (`PKG_ARCH`, `PKG_VERSION`).
- **nfpm ne développe pas les variables dans `contents.src`** (« Glob failed ») : copier
  le binaire de l'architecture courante vers un chemin fixe (`bin/package/`) avant chaque
  paquet.
- **`$(shell …)` de make et `case … )`** : la parenthèse fermante du motif clôt l'appel
  de fonction. Règle : `sed` ou un script plutôt qu'un `case` dans `$(shell …)`.
- **Valeurs YAML des traductions** : une valeur qui contient « : » (« Scan demandé :
  … ») casse tout le fichier (`mapping values are not allowed`). Règle : guillemets dès
  qu'une valeur contient « : », et relancer les tests de `locales` après chaque ajout.
- **Énumérations d'oapi-codegen** : sans collision, les constantes ne sont pas préfixées
  (`gen.Done`, `gen.Current`, pas `gen.IngestionStatusDone`). Règle : lire les noms
  générés (`grep '= "' client.gen.go`) avant de les employer ; un nouvel enum dont une
  valeur existe ailleurs renomme les deux.
- **Scanner « / » d'une machine de développement** : le cache des modules Go
  (380 000 fichiers sous `/root`) fait passer un scan Syft de « / » de 3 à 16 minutes et
  de 0,9 à 3 Gio de mémoire : Syft indexe chaque fichier parcouru. Règle :
  mesurer sur une racine représentative d'un serveur (protocole de `measure_test.go`,
  exclusions explicites), et le documenter.
- **`StateDirectory=` crée le répertoire en `0755`** : l'agent refuse un répertoire
  d'état ouvert. Règle : `StateDirectoryMode=0700` dans toute unité d'agent.
- **mTLS et interface sur la même écoute** : `RequireAndVerifyClientCert` refuserait les
  navigateurs. Règle : `VerifyClientCertIfGiven` au niveau TLS, refus de l'absence de
  chaîne vérifiée dans un middleware de l'API des agents.

## Recherche transverse et jetons personnels (T09)

- **RLS et index de recherche** : sous la RLS, un opérateur non `LEAKPROOF` ne peut pas
  servir de condition d'index ; `ILIKE`, `%` (pg_trgm), `@>`, `&&` et `lower()` ne le
  sont pas (`SELECT proname, proleakproof FROM pg_proc`), l'égalité de texte et d'uuid
  et `= ANY` le sont. Un index GIN `(org_id, name gin_trgm_ops)` est donc ignoré par une
  requête du rôle d'exécution. Règle : vérifier `proleakproof` avant de compter sur un
  index sous la RLS ; sinon une fonction `SECURITY DEFINER` qui lit l'organisation dans
  `ogsbom.org_id` (jamais en paramètre), dans `crossorg`, testée pour ne pas sortir de
  l'organisation (ADR 0024).
- **GIN composite `btree_gin`** : la clé `org_id` lit toute la liste de l'organisation ; sur
  une petite table, le planificateur lui préfère la clé primaire, même parcours
  séquentiels interdits. Règle : un test de plan d'un index GIN se fait sur un jeu assez
  gros (40 000 composants) et une valeur sélective, jamais sur quelques milliers de lignes.
- **Comparateurs de Grype** : faits pour la correspondance, pas pour trier. dpkg renvoie
  une différence (−9) au lieu d'un signe ; PEP 440 n'est pas antisymétrique sur les
  versions locales (`0+00` contre `0`, trouvé par `FuzzCompare` en cinq secondes) ; rpm
  ignore une époque présente d'un seul côté (`2.0-1` > `1:1.0-1`), même avec
  `MissingEpochStrategyZero` qui ne corrige que le côté gauche. Règle : combiner les deux
  sens de comparaison, écrire l'époque `0:` des deux côtés, et un fuzz d'antisymétrie
  pour tout comparateur.
- **Maven lit toute chaîne** : « latest » est un qualificatif, pas une version illisible.
  Règle : choisir les exemples de versions illisibles par écosystème (npm, PEP 440, Go,
  Debian), pas pour Maven.
- **Serveur généré et sous-routeur** : oapi-codegen enregistre les chemins complets du
  contrat ; monter l'API utilisateur dans un groupe de `/api/v1` fait perdre la chaîne
  CORS aux requêtes préliminaires (`OPTIONS` routé avant les middlewares d'un groupe).
  Règle : garder `r.With(cors, …).Route("/orgs/{org}", …)` et y monter chaque opération
  par `userapi.ServerInterfaceWrapper` (le test `TestUserAPICORS` l'a montré).
- **Deux serveurs générés dans un même paquet** : les noms (`ServerInterface`,
  `HandlerWithOptions`…) entrent en collision. Règle : un paquet par serveur généré
  (`internal/api/gen/userapi`), avec ses propres types.
- **`number` d'OpenAPI** devient `float32` chez oapi-codegen. Règle : `format: double`
  pour tout nombre relu en `float64`.
- **Paramètre de curseur inutilisé** : ajouter une valeur à la liste des arguments sans
  l'employer dans la requête donne « could not determine data type of parameter $n ».
  Règle : n'ajouter un argument qu'au moment où son texte est écrit, et typer les clés de
  curseur (`::float8`, `::timestamptz`, `::uuid`).
- **Export en flux et délai d'écriture** : `http.write_timeout` (60 s) coupe un export
  long. Règle : `http.NewResponseController(w).SetWriteDeadline` pour la durée de l'export
  (les enveloppes de la réponse exposent `Unwrap`), et un nombre d'exports simultanés
  borné, car chacun tient une connexion.
- **Outil d'isolement des agents (suite)** : refusés aussi `sed` ou `cat` sur un chemin
  passé par une variable shell (`$D/…`), une boucle `for`, et `python3 - <<EOF` même seul.
  Règle : chemins écrits en entier, scripts d'édition dans le répertoire temporaire lancés
  par `python3 -I chemin.py`, ou `python3 -I -c "…"` court.

## Tableau de bord et graphiques (T10)

- **Mesurer la page entière, pas les requêtes isolées** : chaque requête du tableau de bord
  prenait 20 à 280 ms sur le jeu de référence, mais la page complète a d'abord donné un
  p95 de 1,8 s (machine partagée par d'autres lots). Règle : un test de mesure par page
  (`TestReferenceDatasetDashboard`, garde, RLS et rendu compris), puis profiler requête
  par requête ; trois agrégats qui relisent les mêmes 67 000 constats se fondent en un
  seul passage groupé par projet et sévérité.
- **`count(DISTINCT …)` et `array_agg(DISTINCT …)` sur toute une table** : la liste des
  familles de composants coûtait 260 ms. Règle : réduire d'abord à des couples distincts
  (composant, projet) dans une CTE, regrouper, limiter, et ne lire les détails (versions)
  que pour les lignes retenues.
- **Alias joint deux fois** : une fonction qui ajoute des jointures à un fragment commun
  (`openWhere(joins)`) a produit « table name "p" specified more than once ». Règle : le
  fragment fixe ses jointures pour toutes les portées, l'appelant n'ajoute que des tables
  absentes.
- **SVG étirés (`preserveAspectRatio="none"`)** : cercles et textes s'y déforment. Règle :
  traits en `vector-effect: non-scaling-stroke`, point marqué par un tracé de longueur
  nulle à bouts ronds (`d="Mx,yh0"`), libellés et valeurs en HTML (barres rendues comme
  un tableau), jamais en `<text>`.
- **Grille CSS repliée en mobile** : passer `.trend` de trois à deux colonnes mélangeait
  libellé, valeur et courbe d'une ligne à l'autre. Règle : `grid-auto-flow: row dense` et
  colonne explicite de la valeur ; vérifier la capture mobile (390 px) de chaque écran.
- **Fusion pendant le lot : règle d'un autre lot** : T07 a refondu l'état « muet »
  (`agent.Activity`, dernier inventaire d'un agent serveur) pendant T10. Règle : tout calcul
  qui dépend d'une règle d'un autre paquet passe par sa fonction (`StateAt`,
  `Activity.Since`), en un seul point (`agent.SilentSince`), pour que la fusion ne touche
  qu'une ligne ; les jeux de test fixent `created_at` (un agent serveur sans inventaire est
  muet depuis sa création).
- **`webtest` et les SVG** : l'assistant ne vérifiait rien des `<svg>` ni des références
  `aria-labelledby`. Règle : un `<svg>` est `aria-hidden="true"` ou `role="img"` nommé,
  et toute référence ARIA vise un identifiant présent (vérifié sur toutes les pages).
