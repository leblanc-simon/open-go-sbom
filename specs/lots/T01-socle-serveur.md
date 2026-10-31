# T01 — Socle du serveur

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T00 | Terminé |

## Objectif

Un `ogsbom-server` qui démarre, se configure, migre sa base, sert une page d'accueil traduite
en thème clair et sombre, expose ses sondes et ses métriques, et s'arrête proprement.
Tout ce que les lots suivants réutilisent : configuration, base, rendu, assets, i18n, API.

## Périmètre

**Inclus**

- `internal/config` : `Config` composée (§ 6 de l'architecture), dont les fragments `TLS` et
  `Migration`, méthode `Validate()` aux messages explicites (pilote `postgres`, pool de
  migration d'au moins 2 connexions, cohérence TLS), `config.example.yaml` commenté.
- `internal/db` :
  - pool du rôle propriétaire ouvert le temps de migrer, puis pool d'exécution ;
  - attente bornée de la base au démarrage ;
  - contrôle du rôle d'exécution (ni superutilisateur, ni `BYPASSRLS`, ni propriétaire des
    tables), refus de démarrer sinon ;
  - `InTx` pour les tables globales et `InOrg` (§ 9 de l'architecture) pour les tables
    d'organisation, même si aucune n'existe encore ;
  - exécuteur de migrations du projet (table `ogsbom_schema_migrations` avec somme SHA-256,
    refus de démarrer si une migration publiée a changé), verrou de migration par
    `LOCK TABLE` sur une connexion dédiée ;
  - migration `001_init.sql` : privilèges par défaut du rôle d'exécution sur les tables et
    séquences futures du rôle propriétaire. Les appels aux `Migrate` d'authx et mfax sont
    branchés en T03, dans le même verrou.
- `deploy/compose.yaml` crée les deux rôles ; `docs/operations.md` décrit leur création
  et leurs droits pour une base existante.
- `internal/secret` : chiffrement AES-256-GCM, clés versionnées, rotation.
- Serveur HTTP public (chi), TLS natif facultatif, écoute de gestion séparée, arrêt propre
  sur SIGTERM.
- Les trois groupes de routes du § 14 : l'interface avec sa chaîne de middlewares jusqu'à
  la langue (la session arrive en T03) ; les groupes d'API montés vides, **sans** CSRF.
- `internal/render` : chargement des gabarits embarqués au démarrage (échec immédiat si un
  gabarit est invalide), layout, partials, FuncMap, pages d'erreur 404 et 500 traduites.
- Assets : concaténation des CSS embarquées en une feuille à empreinte, URL à empreinte pour
  les modules JS, en-têtes de cache.
- `web/static/css` : port des fondations du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj)
  (planche « Fondations — tokens » et feuille `project/ogs.css`) : `tokens.css` (couleurs,
  typographie, espacements, échelle de sévérité, KEV, origine IA, thèmes clair et sombre),
  `base.css`, en-tête, navigation, pied de page ; bascule de thème ; polices Atkinson
  Hyperlegible auto-hébergées (`web/static/fonts`). Les composants de la planche
  « Composants » sont portés au fur et à mesure des écrans qui les utilisent.
- `locales/en.yaml` et `fr.yaml` avec les clés du socle ; ordre de choix de la langue du
  § 18 (la préférence du compte se branche en T03) ; tests de complétude et d'usage.
- Infrastructure d'API : `api/openapi.yaml` initial, génération, erreurs RFC 9457, aide à la
  pagination par curseur, test « code généré à jour ».
- Gestion : `/healthz`, `/readyz` (selon les rôles actifs, § 20), `/metrics`.
- Assistant de test d'accessibilité réutilisable : analyse d'une page rendue (langue, titre,
  un seul `h1`, libellés de champs, textes alternatifs, lien d'évitement).

**Exclu** : comptes et sessions (T03), file de traitements (T02).

## Conception

- `cmd/ogsbom-server/main.go` ne fait que : charger la config, construire les dépendances,
  lancer les serveurs, attendre le signal.
- `secret.Box` : `Seal(plaintext) (ciphertext, keyID)` et `Open` ; la clé active chiffre, les
  anciennes déchiffrent. Le format du chiffré est versionné.
- En-têtes de sécurité : CSP du § 14, `Strict-Transport-Security` si TLS (natif ou déclaré
  par le mandataire de confiance), `X-Content-Type-Options`, `Referrer-Policy: same-origin`,
  `Permissions-Policy` restrictive.
- ADR « fonctions de gabarit dépendantes de la requête » : clonage par requête d'un jeu de
  gabarits jamais exécuté, ou traducteur et jeton CSRF passés dans les données de la page.
  Critères : coût mesuré par requête, simplicité des gabarits, impossibilité d'oublier la
  traduction.
- La bascule de thème mémorise le choix dans `localStorage` (protégé par `try/catch`) ;
  sans JS, le thème suit le système.

## Livrables

`ogsbom-server` démarrable, `config.example.yaml`, migration initiale, page d'accueil,
`api/openapi.yaml` initial, ADR des gabarits, `docs/operations.md` (installation de
développement, configuration, TLS ou mandataire inverse, sondes).

## Critères d'acceptation

- [x] `ogsbom-server --help` liste toutes les variables `OGSBOM_*` avec leur description.
- [x] Une configuration invalide arrête le démarrage avec un message qui nomme le champ.
- [x] Sur une base vide, les migrations s'appliquent ; deux instances lancées en même temps
      ne migrent qu'une fois ; une migration publiée modifiée empêche le démarrage.
- [x] Le serveur refuse de démarrer si le rôle d'exécution est superutilisateur, possède
      `BYPASSRLS` ou possède les tables.
- [x] Une table de test sous RLS forcée : dans `InOrg(A)`, une requête sans filtre ne voit
      que les lignes de A et ne peut pas en écrire pour B ; hors `InOrg`, la requête échoue.
- [x] La page d'accueil s'affiche en français et en anglais (`?lang=`), en thème clair et
      sombre, sans aucun script ni style en ligne.
- [x] Les en-têtes de sécurité et la CSP sont présents sur toutes les réponses de
      l'interface ; une requête `POST` vers un groupe d'API n'est pas soumise au CSRF.
- [x] `/readyz` renvoie une erreur tant que la base est injoignable.
- [x] SIGTERM laisse finir les requêtes en cours dans un délai configurable.
- [x] Une clé de traduction manquante dans une langue fait échouer les tests.

## Tests attendus

Unitaires : validation de config, `secret` (aller-retour, rotation, chiffré altéré refusé),
empreinte des assets, FuncMap. Intégration : migrations concurrentes et altérées, arrêt
propre, rendu des pages et assistant d'accessibilité.

## Décisions

Prises le 31 octobre 2026 :

- `prometheus/client_golang` validé pour `/metrics`.
- Langue par défaut d'une installation neuve : français.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T01-socle-serveur`.

### Livré

- `internal/tenant` : `OrgID` (UUID v7, zéro refusé, `Value`/`Scan`), contexte. Le
  middleware `/o/{slug}` reste à T03.
- `internal/db` : `Open` (pgx via `database/sql`, connexions en UTC, DSN jamais cité dans
  les erreurs), `WaitReady`, `Pool` avec `InTx(ctx, func(*db.Tx))` et
  `InOrg(ctx, org, func(*db.OrgTx))` (ni `Commit` ni `Rollback` exposés, `Querier`
  commun), `Migrate` (verrou `LOCK TABLE`, étapes `Before` pour authx et mfax, tout ou
  rien), `VerifySchema`, `CheckRuntimeRole`, `CheckOrgIsolation`, `Start` (séquence de
  démarrage), `Array` (lecture des tableaux PostgreSQL), `RoleFromDSN`.
- `internal/db/migrations/001_init.sql` : privilèges par défaut du rôle d'exécution,
  procédure `ogsbom_enforce_org_rls`.
- `internal/db/dbtest` : base et rôles jetables par test (suffixe aléatoire), migrations
  appliquées par le propriétaire, pool du rôle d'exécution, nettoyage ; `NewRole` et
  `AdminExec` pour les tests de rôles. Message explicite sans `OGSBOM_TEST_DATABASE_DSN`.
- `internal/secret` : `Box` AES-256-GCM, clés nommées, chiffré versionné, rotation.
- `internal/config` : `Config`, `Defaults`, `Load`, `Validate` (une erreur par champ,
  avec chemin YAML et variable), `Fields` ; `config.example.yaml` complet et testé.
- `internal/locale` (catalogue, ordre du § 18), `locales/` (fr, en), `internal/pagination`
  (curseurs opaques, pages bornées), `internal/api/problem` (RFC 9457),
  `api/openapi.yaml` (3.1.0 : `Problem`, `PageInfo`, paramètres `cursor` et `limit`,
  schémas de sécurité) et `internal/api/gen` (types générés).
- `web/` (gabarits et statiques embarqués) : `tokens.css`, `fonts.css`, `base.css`,
  composants `skip-link`, `topbar`, `shell` (et `sidenav`), `page-head`, `panel`, `btn`,
  `layout`, `site-footer` ; écran `home` ; polices et licences ; `js/theme.js` ;
  gabarits `layout`, `topbar`, `sidenav`, `footer`, `home/index`, `errors/error`.
- `internal/render` : jeux de gabarits par page et par langue, `Page`, `Render`, `Error`
  (404, 405, 429, 500), `Assets` (feuille concaténée, URL à empreinte, cache).
- `internal/web` : routeur et trois groupes de routes, pages d'erreur, gestion
  (`/healthz`, `/readyz`, `/metrics`), `Server` (TLS natif facultatif, mTLS, arrêt
  propre) ; `internal/web/middleware` ; `internal/web/webtest` (accessibilité, absence de
  code en ligne).
- `cmd/ogsbom-server` câblé ; test de bout en bout du binaire (deux instances
  simultanées, page en deux langues, métriques, SIGTERM, refus de démarrer).
- `docs/operations.md`, ADR 0009 et 0010, `architecture.md` à jour.

### Décisions

- Exécuteur de migrations (ADR 0010) **[à relire]** : rôle d'exécution lu dans
  `database.dsn` et déclaré aux migrations par `ogsbom.app_role` ; migrations du projet
  dans la transaction du verrou (tout ou rien, pas de `CONCURRENTLY`) ;
  `ogsbom_enforce_org_rls` ; refus de démarrer si une table à `org_id NOT NULL` n'a pas
  la RLS standard ou a une politique permissive étrangère à `ogsbom.org_id` ; sans
  `migration.dsn`, pas de migration et refus d'un schéma en retard.
- `001_init.sql` ne contient que les privilèges par défaut et la procédure : aucune table
  métier, pour que la première migration publiée reste minimale. `GRANT USAGE ON SCHEMA
  public` n'y figure pas (accordé à `PUBLIC` par défaut, et refusé si le propriétaire ne
  possède pas le schéma).
- Gabarits (ADR 0009) : un jeu par page et par langue préparé au démarrage, `T` et `Tn`
  liées à la langue ; jeton CSRF, thème et identifiant de requête dans `render.Page`,
  rempli par `Render`. Mesure : 69 µs contre 243 µs pour le clonage par requête.
- Configuration **[à relire]** : un fragment n'entre dans `Config` qu'avec le lot qui
  l'emploie (`Auth`, `MFA` en T03, `Workers` en T02…), pour que `--help` ne liste aucune
  variable sans effet ; fragment `HTTP` ajouté (délais, `shutdown_timeout`) ; `Database`
  embarque le fragment d'appconf (`yaml:",inline"`) et ajoute pool et
  `startup_timeout` ; écoute de gestion par défaut `127.0.0.1:8081`. Défauts du projet
  posés avant `appconf.Load` (pilote `postgres`, langue `fr`, journaux `info`).
- `secret.Box` **[à relire]** : `Seal(plaintext, aad)` et `Open(ciphertext, keyID, aad)`
  au lieu de `Seal(plaintext)` : les données associées lient le chiffré à sa ligne. Le nom
  de la clé entre aussi dans les données authentifiées. Clés en base64, noms
  `[a-z0-9][a-z0-9_-]{0,31}`, configuration `id:base64,…`.
- En-têtes **[à relire]** : CSP du § 14 complétée par `base-uri 'none'` ; CSP d'API
  `default-src 'none'` ; `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` et
  `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` qui coupe caméra,
  micro, géolocalisation, paiement… ; `Cache-Control: no-store` sur l'interface et
  l'API ; HSTS de deux ans **sans** `includeSubDomains`, seulement pour une requête en
  HTTPS (TLS natif ou `X-Forwarded-Proto` d'un mandataire de `web.trusted_proxies`).
- Thème **[à relire]** : couleurs en `light-dark()` (le thème suit le système sans JS) ;
  la bascule (système → clair → sombre) écrit `localStorage` **et** un cookie
  `ogsbom_theme` lu par le serveur pour rendre `data-theme` dès la première peinture,
  sans script en ligne ni flash. La préférence de thème du compte (`account_settings`,
  T03) pourra remplacer le cookie.
- Polices **[à relire]** : Atkinson Hyperlegible Next v7 et Mono v8, fichiers WOFF2
  variables (graisses 200 à 800) tels que servis par l'API Google Fonts le 31 octobre
  2026 (`fonts.gstatic.com`), sous-ensembles latin et latin étendu, **style droit
  seulement** (pas d'italique : 82 Kio au total) ; licences `OFL.txt` du dépôt
  `google/fonts` (`ofl/atkinsonhyperlegiblenext`, `ofl/atkinsonhyperlegiblemono`), copiées
  à côté des fichiers. Sources amont : `googlefonts/atkinson-hyperlegible-next` et
  `-next-mono`.
- Fichiers statiques sous `/static/<empreinte de l'ensemble>/<nom>` : les chemins
  relatifs entre fichiers (`url()` vers les polices, imports de modules) restent valides ;
  une autre empreinte (déploiement progressif) sert le fichier courant sans cache.
- Groupes d'API montés vides, sans CSRF ; tout chemin `/api/…` inconnu répond un
  problème 404 ; CORS seulement sur l'API utilisateur. Problème RFC 9457 : `type` = clé,
  `title`/`detail` traduits depuis `<clé>.title`/`.text`, `instance` = chemin,
  `request_id`.
- Identifiant de requête toujours généré par le serveur (celui du client est ignoré),
  renvoyé dans `X-Request-Id` et affiché sur les pages d'erreur. Le journal d'accès omet la
  chaîne de requête.
- `/readyz` passe à 503 dès le début d'un arrêt, pour que le répartiteur draine.
- Interface : pied de page `site-footer` créé (absent de la planche, tokens seulement)
  **[à relire]** ; la navigation latérale est portée mais n'apparaît qu'avec des entrées
  (T03) ; pas de sélecteur de langue (`?lang=` ne vaut que pour la requête ; la
  préférence du compte arrive en T03).
- Dépendances : aucune nouvelle dépendance tierce. `golang.org/x/net/html` (déjà dans le
  graphe par prometheus) sert à l'assistant d'accessibilité, en test ; `golang.org/x/text`
  et `gopkg.in/yaml.v3` deviennent directs. La directive `go` passe à 1.26.3, minimum
  d'open-go-base v1.0.1 (la chaîne reste 1.26.10).

### Écarts

- La fiche donnait `secret.Box.Seal(plaintext) (ciphertext, keyID)` : paramètre `aad`
  ajouté (voir Décisions).
- `deploy/compose.yaml` créait déjà les deux rôles depuis T00 : inchangé.

### Limites d'open-go-base relevées, pour T03

- `csrfx` répond 403 en texte français fixe (déjà au § 23).
- `appconf` : `--help` affiche les défauts des fragments, pas ceux que le projet pose
  avant le chargement ; `I18N_DIR` est listé alors que les traductions sont embarquées.
  Évolution possible : défauts surchargeables ou fragment sans `Dir` (non inscrite au
  § 23, à proposer à l'utilisateur).
- `ratelimit` ne publie pas son test « mandataire de confiance » : `middleware.TrustedProxies`
  le refait (netip) pour décider de HSTS. À factoriser si open-go-base l'expose.
- `appconf.Load` lit `os.Args` et termine le programme sur `--help` : les tests passent
  par un sous-processus.

### Pour les lots suivants

- T02 : `jobs.Enqueue` prend un `db.Querier` (implémenté par `*db.Tx` et `*db.OrgTx`).
  Le fragment `Workers` et la vérification de la base Grype dans `/readyz` (T06) restent
  à ajouter ; `web.NewReadiness` prend des `web.Check`.
- T03 : brancher `authx`/`mfax` par `db.MigrateOptions.Before` (via `db.StartOptions`),
  ajouter `Auth` et `MFA` à `Config`, insérer session, changement de mot de passe et garde
  d'organisation dans la chaîne `ui` de `internal/web/router.go` (aux places marquées),
  fournir `middleware.LanguageSources.Account`, recalculer la langue dans la garde.
  Tables d'organisation : `CALL ogsbom_enforce_org_rls('organizations', 'id')`.
- Écrans : modèle de vue qui embarque `render.Page`, `rd.Render(w, r, status, "écran/page",
  &vue)`, tests avec `webtest.AssertAccessible` et `webtest.AssertNoInlineCode`.
- Lecture d'un tableau PostgreSQL : `row.Scan(db.Array(&slice))`.

### Mesures

- Rendu de la page d'accueil : 69 µs, 284 allocations (jeu par langue) ; clonage par
  requête : 243 µs, 995 allocations.
- Couverture (unitaires et intégration) : `api/problem` 92 %, `config` 96 %, `db` 85 %,
  `locale` 92 %, `pagination` 97 %, `render` 95 %, `secret` 96 %, `tenant` 96 %, `web`
  97 %, `web/middleware` 89 %, `web/webtest` 89 %.

### ADR créés

0009, 0010.
