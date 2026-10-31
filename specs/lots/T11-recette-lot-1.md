# T11 — Recette du lot 1

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T07, T08, T09, T10 | Terminé (v0.1.0 à publier par l'utilisateur) |

## Objectif

Passer le critère du lot 1 : **un parc pilote inventorié et interrogé**. Durcir, mesurer,
documenter et publier une préversion.

## Périmètre

**Inclus**

- Écrans d'administration d'instance : traitements en échec (relancer, abandonner), état de
  la base de vulnérabilités (version cible, version de chaque instance, âge, dernière mise à
  jour) et import manuel d'une archive.
- Mesures consolidées des cibles du cahier des charges selon `docs/benchmarks.md` :
  ingestion et analyse de 5 000 composants, recherche, tableau de bord, scan de l'agent
  serveur.
- Revue de sécurité de tout le lot 1 par un relecteur distinct de l'auteur, gravité selon
  l'OWASP Risk Rating ; mise à jour du modèle de menace ; correction des constats.
- Audit RGAA de tous les écrans du lot 1 (grille consignée) ; corrections.
- Point sur les évolutions d'open-go-base du § 23 de l'architecture attendues avant ce lot
  (codes de secours de mfax).
- `docs/operations.md` complet pour le lot 1 ; guide de démarrage utilisateur (FR et EN).
- Déploiement pilote et recette sur le périmètre défini avec l'utilisateur.
- Préversion `v0.1.0` : `CHANGELOG.md`, étiquette, binaires.

**Exclu** : toute nouvelle fonction.

## Critères d'acceptation

- [x] Toutes les cibles chiffrées sont tenues au 95e centile sur la machine de référence,
      ou une nouvelle cible a été validée par l'utilisateur et reportée au cahier des
      charges. (Tenues sur 4 cœurs, machine moins puissante que la référence : 6,6 s pour
      30 s, 344 ms pour 2 s, 663 ms pour 1 s, agent 3 min 8 s et 921 Mio pour 5 min et
      1 Gio ; voir « Mesures consolidées ». Confirmation des cibles « proposées » du
      cahier des charges : action de l'utilisateur.)
- [x] Aucune faiblesse de gravité haute ou critique (OWASP Risk Rating) ouverte à l'issue de
      la revue. (Aucune trouvée ; les 3 Medium et 6 des 7 Low sont corrigés, voir « Revue de
      sécurité ».)
- [x] Grille RGAA remplie pour chaque écran, sans non-conformité bloquante
      ([grille](../../docs/accessibilite/grille-rgaa-lot1.md) : 100 % des critères
      applicables après corrections, aucune NC bloquante ni avant ni après).
- [x] Sur le parc pilote : tous les serveurs et dépôts prévus ont un instantané de moins de
      24 h. (Trois serveurs et quatre dépôts, analysés avec la base réelle ; dépôts servis
      par une forge simulée, essai sur une vraie forge : action de l'utilisateur.)
- [x] Pour trois CVE choisies avant la recette, la recherche renvoie exactement la liste de
      projets attendue, établie à la main au préalable. (CVE-2023-4911, CVE-2023-48795,
      CVE-2023-2650 : listes exactes à l'écran et par l'API.)
- [ ] `v0.1.0` publiée. (Prête : `CHANGELOG.md`, workflow `release.yml`, `make release`
      vérifié ; la pose de l'étiquette est refusée dans la session, action de
      l'utilisateur décrite dans `specs/avancement.md`.)

## Décisions

Prises le 31 octobre 2026 :

- Parc pilote de démonstration : conteneurs Debian, Rocky Linux (famille RHEL) et Alpine
  portant l'agent serveur, et dépôts publics sur GitHub et GitLab. La liste exacte et les
  CVE de contrôle sont fixées au début du lot, avant toute recherche.
- `v0.1.0` publiée en préversion sur GitHub Releases : étiquette, binaires des trois rôles,
  sommes de contrôle.

## Journal

Le lot est réalisé en deux parties : la partie 1 (branche `lot/T11-administration`)
livre les écrans d'administration d'instance et les corrections techniques en attente ;
la partie 2 (branche `lot/T11-recette`) traite la revue de sécurité, l'audit RGAA, les
mesures, le parc pilote et la préversion. Les critères d'acceptation ci-dessus relèvent
de la partie 2.

### Partie 1 — Administration de l'instance et corrections

Réalisée le 31 octobre 2026, branche `lot/T11-administration`.

#### Livré

- **Traitements en échec** (`/admin/jobs`, administrateurs d'instance) : compteurs de la
  file (en attente, en cours, en échec), jobs morts paginés (type, clé, organisation lue
  sous sa RLS, tentatives, date, dernière erreur), **Relancer** et **Abandonner** en `POST`
  avec CSRF ; chaque action verrouille le job (`jobs.GetDead … FOR UPDATE`), l'applique et
  écrit l'entrée d'audit d'instance (`job.retried`, `job.discarded`) dans la même
  transaction ; un double envoi répond 404 avec un message. `internal/jobs` :
  `GetDead`, `CountJobs`, `Active`.
- **État de la base de vulnérabilités** (`/admin/vulndb`) : âge de la cible ajouté ;
  **version chargée par chaque instance worker** (à jour, en retard, sans base, sans
  nouvelles ; date de construction et âge de la base chargée, date de chargement, dernier
  signal, erreur de synchronisation), rapportée par `vuln.Manager` après chaque
  synchronisation dans la nouvelle table globale `vulndb_instances`, retirée à l'arrêt.
- **Import manuel d'une archive** : formulaire multipart sur le même écran ; fichier lu
  en flux (`uploadGate`, jeton CSRF en première partie présenté à csrfx), rangé par blocs
  de 8 Mio dans PostgreSQL (`vulndb_imports`, `vulndb_import_chunks`), un bloc par
  transaction ; job `vulndb.import` (`Checker.ImportHandler`) qui recopie, vérifie,
  installe (`Checker.Import`) et fait de l'archive la cible ; un seul import à la fois ;
  imports bloqués abandonnés au suivant ; état des cinq derniers imports affiché ; demande
  et issue journalisées (`vulndb.import_requested`, `vulndb.imported`,
  `vulndb.import_failed`). Nouvelle erreur `vuln.ErrInvalidArchive`.
- **Purge des archives** qui ne sont pas la cible (`vuln.PurgeArchives`), formulaire avec
  case de confirmation, journalisée (`vulndb.archives_purged`) — écart laissé par T06.
- Migration **014** (`vulndb_instances`, `vulndb_imports`, `vulndb_import_chunks`,
  tables globales). Traductions fr et en (`admin_jobs.*`, `admin_vulndb.*`, `flash.*`,
  `audit.action.*`, `nav.admin_jobs`). CSS : `.input--file`.
- **Défaut mobile** (bande vide sous la navigation latérale à 390 px, toutes les pages à
  navigation) : `.shell` est en `flex-wrap: wrap` et `flex: 1` dans un `body` à hauteur
  d'écran ; sous 64rem la navigation passe sur sa propre ligne et `align-content` par
  défaut (`normal`, soit `stretch`) partage la hauteur libre entre les deux lignes.
  Correctif : `align-content: flex-start` dans `@container ogsbom (width < 64rem)`
  seulement (au-dessus, la ligne unique étirée garde la navigation sur toute la hauteur).
  Avec les deux défauts voisins signalés par l'audit RGAA : `min-width: 0` sur `.sidenav`
  dans le même bloc (défilement horizontal à 320/390 px) et `position: relative` sur
  `.table-wrap` (les `.visually-hidden` débordaient la zone défilante). Vérifié par
  captures Playwright (Chromium), thèmes clair et sombre, 390 et 1 280 px, pages
  `/o/<slug>`, membres, traitements, base : à 390 px, navigation de 47 px collée au
  contenu (122 px sur la page des membres en rétablissant `align-content: normal`, plus
  sur une page courte), aucun défilement horizontal ; à 1 280 px, navigation sur toute la
  hauteur.
- **Test instable `TestLostLeaseCancelsHandler`** : reproduit (3 échecs sur 30, « statut
  pending ») avec `-race`, `GOMAXPROCS=1` et `taskset -c 0` partagé avec 40 boucles
  actives. Cause **dans le test** : il simulait la reprise par un autre worker en changeant
  le seul jeton du bail, laissant `locked_until` expirer 300 ms plus tard ; sous charge,
  le même runner reprenait le job expiré (deuxième exécution du handler, `close` d'un
  canal déjà fermé, panique, nouvel essai) avant la vérification, faite après un
  `time.Sleep(50 ms)`. Le code est correct (la reprise d'un bail expiré est voulue).
  Correctif : l'autre worker pose son jeton **et** son bail (une heure) ; bail du test
  porté à 3 s (renouvelé chaque seconde) pour qu'un renouvellement retardé ne perde pas le
  bail avant la simulation ; attente déterministe de l'issue `lost` dans
  `ogsbom_job_runs_total` au lieu du `sleep` ; le test vérifie en plus le jeton, le bail,
  les tentatives, l'absence d'erreur enregistrée et une seule exécution du handler. Après
  correctif : 50 passages sur 50 dans les mêmes conditions. Ce que le test prouve est
  inchangé (annulation du handler sur perte de bail, résultat ignoré).
- **Point open-go-base § 23 (codes de secours de mfax)** : constaté **absent** — ni
  v1.0.1, ni la pseudo-version utilisée (`v1.0.2-0.20261031043924-3534c1429b63`, commit
  `3534c14`), ni `main` d'open-go-base ne contiennent de codes de secours (aucune
  occurrence de « recovery », « backup », « secours » dans `mfax`). Non nécessaire au
  critère du lot 1 : la récupération passe par la réinitialisation du TOTP par un
  administrateur d'instance (auditée) et par la procédure de secours (ADR 0013). Aucune
  évolution ouverte ; § 23 de l'architecture mis à jour (reporté à T18).
- Docs : ADR 0028, `architecture.md` (§ 8, § 12, § 14, § 23), `docs/operations.md`
  (traitements en échec, état des instances, import, purge, mandataire inverse),
  `config.example.yaml` et aide de `vulndb.download_timeout`, `doc.go` de `jobs` et
  `vuln`.

#### Tests

- `jobs` (intégration) : `CountJobs`, `Active`, `GetDead` ; `TestLostLeaseCancelsHandler`
  réécrit.
- `vuln` (intégration) : téléversement et job d'import (blocs, journal, second import
  refusé, installation sur une autre instance, blocs supprimés, rejeu, réimport du même
  fichier) ; refus (vide, trop gros, lecture interrompue : rien ne reste) ; imports
  bloqués abandonnés (téléversement interrompu, job disparu) et téléversement récent
  bloquant ; échecs du job (archive invalide sans nouvel essai, erreur passagère
  réessayée puis échec à la dernière tentative, charge illisible permanente, import
  inconnu) ; purge (cible gardée, octets comptés, journal, cible encore synchronisable) ;
  rapport et retrait de l'instance, ligne de plus de 7 jours supprimée.
- `web` (intégration) : écran des traitements (fr, en, accessibilité, absence de code en
  ligne, erreur échappée, relance, double relance, abandon, identifiants invalides, refus
  sans CSRF, journal) ; import (jeton faux, jeton après le fichier, sans fichier, compte
  ordinaire 404, trop gros 413, rien stocké après les refus ; import accepté, job en file,
  écran « en cours » sans formulaire, second import 409 ; installation par le job, écran et
  journal) ; purge (confirmation exigée, purge, journal) et états des instances ; nouvelles
  routes dans le parcours des routes d'administration (404 pour un compte ordinaire) et
  dans `TestEveryScreenIsAccessible` (fr, en, clair, sombre).

#### Décisions

- **ADR 0028** **[à relire]** : archive téléversée rangée dans PostgreSQL puis installée
  par un job (instance web et worker séparables) ; lecture en flux avec jeton CSRF en
  première partie présenté à csrfx par son en-tête (seule route dont le jeton n'est pas lu
  dans le corps par csrfx) ; un bloc par transaction ; un seul import à la fois ; archive
  importée cible **même plus ancienne** que la cible actuelle (retour arrière volontaire,
  annoncé à l'écran) ; 3 tentatives pour le job d'import, archive invalide refusée sans
  nouvel essai ; état par instance dans `vulndb_instances`, instance nommée hôte:PID,
  « sans nouvelles » au-delà de max(3 × `sync_interval`, 15 min), ligne oubliée après
  7 jours ; purge de **toutes** les archives non cibles, avec case de confirmation.
- `vulndb.download_timeout` borne aussi la durée d'un téléversement (pas de nouveau
  réglage) **[à relire]**.
- Abandon d'un traitement sans confirmation (action ciblée, réversible par une nouvelle
  mise en file de la donnée qui l'a produit) ; purge avec confirmation (irréversible)
  **[à relire]**.
- Codes de secours de mfax reportés à T18, sans évolution d'open-go-base pour le lot 1
  **[à relire]**.

#### Écarts

- Aucun pour le périmètre de la partie 1. `TestLeaseIsRenewedWhileHandlerRuns` garde un
  bail de 300 ms : il n'a pas échoué dans les mêmes conditions de charge, mais repose sur
  le même équilibre (voir `specs/lecons.md`).

#### ADR créés

0028.

### Revue de sécurité

Réalisée le 31 octobre 2026, branche `lot/T11-securite`. Revue indépendante (relecteur
distinct des auteurs, OWASP Risk Rating) de `main` à `8369ad0` (T00 à T10) ; chaque constat
a été vérifié dans le code avant correction. Bilan de la revue : 0 Critical, 0 High,
3 Medium, 7 Low, 4 Note ; aucune fuite entre organisations.

#### Constats

| Id | Titre | Gravité | Statut | Commit ou justification |
| --- | --- | --- | --- | --- |
| SEC-01 | TOTP forçable avec le mot de passe, seule borne par IP (IPv6 /128) | Medium | Corrigé | `9909ef9` : verrouillage par compte de mfax (open-go-base v1.3.0), IPv6 par /64 ; ADR 0029 |
| SEC-02 | Jetons personnels qui survivent à la réinitialisation, créés sans réauthentification | Medium | Corrigé | `9909ef9` : révocation d'office (réinitialisations, changement de mot de passe), compte en attente refusé, code TOTP à la création ; ADR 0029 |
| SEC-03 | Après réinitialisation du TOTP, le mot de passe seul enrôle un second facteur | Medium | Corrigé | `9909ef9` : mot de passe temporaire imposé (administrateur), `bootstrap.rescue_password` (secours) ; ADR 0029 |
| SEC-04 | Journal d'audit modifiable et effaçable par le rôle d'exécution | Low | Corrigé | `ea9d307` : migration 015 (`REVOKE UPDATE, DELETE, TRUNCATE`), contrôle au démarrage ; ADR 0030 |
| SEC-05 | Stockage sans quota : un jeton d'agent volé remplit la base | Low | Corrigé | `cd68184` : quotas par référence et par organisation (429, rien stocké) ; rétention : T17 ; ADR 0030 |
| SEC-06 | Réencodage de SBOM synchrone, non borné, ouvert à un lecteur | Low | Corrigé | `b29dd44` : `ingest.max_reencodes` (2), un par compte, 429 ; client parti ignoré ; ADR 0030 |
| SEC-07 | Exports : 4 places pour l'instance, monopolisables par un compte | Low | Corrigé | `b29dd44` : un export à la fois par compte ; ADR 0030 |
| SEC-08 | CSRF non lié à la session, cookies sans `__Host-`, session sans durée absolue | Low | Corrigé | `9909ef9` : `csrfx.WithSessionBinding` (open-go-base v1.3.0), `http.CrossOriginProtection`, `__Host-` avec `cookie_secure: on`, `login.session_max_age` ; ADR 0031 |
| SEC-09 | Un administrateur d'organisation énumère les comptes et ajoute sans consentement | Low | Accepté, reporté à T16 **[à relire]** | Une réponse uniforme sans invitation tromperait l'administrateur (« ajouté » pour un compte inexistant) ; l'invitation à accepter relève des équipes et droits (T16). Administrateurs d'organisation désignés par l'administrateur d'instance, ajouts audités ; consigné au modèle de menace |
| SEC-10 | Agent dépôt : identifiants plus larges que nécessaire, aucun périmètre côté agent | Low | Corrigé | `9dd1f8f` : `allowed_namespaces` obligatoire, jeton GitHub restreint au dépôt ; droits du jeton GitLab documentés ; ADR 0031 |
| SEC-11 | `decode_timeout` sans effet sur les étapes CPU | Note | Corrigé (en partie, documenté) | `efe7185` : lecture de `Precheck` interrompue, contexte vérifié entre les étapes ; validation et décodage de Syft vont au bout de l'étape (linéaires, bornés par le plafond par organisation) ; ADR 0030 |
| SEC-12 | `CREATE` non contrôlé, fonctions `SECURITY DEFINER` sans garde SQL | Note | Corrigé | `ea9d307` : `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, refus au démarrage ; absence de garde SQL de `ogsbom_list_organizations` et `ogsbom_org_id_by_slug` consignée (risque accepté, métadonnées seules) |
| SEC-13 | Jeton d'inscription : rattachement à un projet hôte orphelin par nom déclaré | Note | Accepté | Conforme à l'hypothèse « hôtes non compromis à l'inscription » (jetons d'inscription bornés en durée et usages, inscription auditée) ; changer le rattachement modifierait le parcours de T07 (ADR 0021) ; consigné au modèle de menace |
| SEC-14 | Divers (audit alimentable par un anonyme, `X-Real-IP`, base Grype non signée, webhook en clair, jetons d'agent sans expiration) | Note | Corrigé en partie, reste accepté | `9909ef9` (borne par /64 du journal des échecs) ; `X-Real-IP`, TLS du récepteur et droits GitLab documentés (`docs/operations.md`) ; base Grype non signée et extraction non bornée : risque amont accepté ; jetons d'agent sans expiration : ADR 0014 |

#### Autres points vérifiés

- **Nouvelles routes de la partie 1** (`/admin/jobs`, `POST /admin/jobs/{jobID}/{retry|discard}`,
  `POST /admin/vulndb/import`, `POST /admin/vulndb/purge`) : groupe `/admin` sous
  `requireInstanceAdmin` (404 sinon), CSRF sur chaque `POST` (le téléversement présente le
  jeton de sa première partie, désormais lié à la session : rien ne change pour lui),
  identifiants analysés avant usage, action et audit dans la même transaction, erreurs de
  job échappées. `uploadGate` n'élargit la borne qu'à un administrateur authentifié et ne
  lit que la première partie avant CSRF. Aucun correctif nécessaire.
- **staticcheck et go vet** passent désormais aussi sur les étiquettes `integration`,
  `integration,grypedb` et `measure` (`make lint`, `make vet`) ; le SA4010 de
  `runner_integration_test.go` est corrigé (`954eaf3`).

#### Livré

- open-go-base **v1.3.0** (PR #3 fusionnée en « squash », commit `9a7b91f`, étiquette
  créée localement, à pousser) : `mfax.WithLockout`, `LockoutStore` (table
  `mfa_lockouts`, migrations SQLite et PostgreSQL), `Confirm`, `CodeLocked`,
  `WithLockoutHook`, `WithChallengeCookieName` ; `csrfx.WithSessionBinding` ; réglages
  `appconf.MFA.Lockout*`. Rétrocompatible. Pseudo-version utilisée ici :
  `v1.0.2-0.20261031121913-9a7b91fdbbfe`.
- Migration **015** (`mfa_lockouts` accordée, journaux en ajout seul, index de quota,
  `CREATE` retiré sur `public`).
- Réglages : `mfa.lockout_threshold`, `lockout_window`, `lockout_duration`,
  `lockout_max_duration` ; `login.session_max_age` ; `bootstrap.rescue_password` ;
  `ingest.max_per_ref_per_day`, `max_org_storage_mib`, `max_reencodes` ; agent dépôt :
  `forges[].allowed_namespaces`. `config.example.yaml` passe `auth.cookie_secure` à `on`.
- Traductions (fr, en) : `login.error.locked`, `password.revoke_tokens`,
  `admin_password.totp_reset_heading`, `tokens.code`, `tokens.code_hint`,
  `tokens.error.invalid_code`, `tokens.error.locked`, `audit.action.account_locked`,
  `error.token.account_pending`, `error.ingest.quota`. Gabarits touchés (minimalement) :
  `account/password.html` (case « révoquer aussi mes jetons »), `account/tokens.html`
  (champ du code TOTP), `admin/temp_password.html` (titre par clé).
- Docs : ADR 0029 à 0031, `docs/security/threat-model.md` (version 2 : les onze mises à
  jour proposées par la revue, vérifiées), `docs/operations.md`, `specs/architecture.md`
  (§ 5, § 10, § 11, § 14, § 19, § 23), API (`429` de `createIngestion`).

#### Tests

- Tests de démonstration de la revue repris en non-régression, attentes inversées
  (`internal/web/secreview_integration_test.go`) : jeton révoqué après réinitialisation du
  mot de passe et du TOTP ; ancien mot de passe refusé après réinitialisation du TOTP,
  mot de passe temporaire puis changement imposé ; journal en ajout seul
  (`internal/db/db_integration_test.go`, `TestAuditIsAppendOnly`, et la table
  `audit_events` dans `TestRLSOnEveryOrgTable`). Le premier et le deuxième échouent sur
  `main` (jeton accepté, enrôlement réussi), le troisième aussi (UPDATE et DELETE
  acceptés).
- Nouveaux : verrouillage à travers les défis (10 codes faux, défi refusé, journal,
  levée par l'administrateur), réauthentification des jetons et verrouillage par la
  création, CSRF forgé par cookie posé et jeton d'une autre session refusés, durée
  absolue, cookies `__Host-`, protection inter-origines, limitation par /64,
  `CheckRuntimeRole` (CREATE, journal), quotas d'ingestion, délai du décodage, plafonds
  par compte (export, réencodage), périmètre de l'agent dépôt et jeton GitHub par dépôt,
  configuration. Côté open-go-base : verrouillage (sqlstore SQLite et service),
  `Confirm`, `DisablePOST` verrouillé, liaison CSRF, `__Host-`.

#### Décisions

- Verrouillage sur les seuls codes TOTP, pas sur le mot de passe (sinon verrouillage de
  n'importe quel compte par son e-mail) ; 10 codes en 15 min, 15 min doublées, 24 h au plus
  **[à relire]**.
- Réinitialiser le TOTP impose un mot de passe temporaire (plutôt qu'un jeton
  d'enrôlement) ; secours : `bootstrap.rescue_password` obligatoire **[à relire]**.
- Création d'un jeton personnel par code TOTP ; changement de mot de passe : révocation
  proposée cochée **[à relire]**.
- Durée absolue de session de 7 jours, dans le projet (pas dans authx) **[à relire]**.
- CSRF lié à la session et `http.CrossOriginProtection` ; `__Host-` seulement avec
  `cookie_secure: on`, valeur de l'exemple, défaut du code inchangé (`auto`) **[à relire]**.
- Quotas 200 envois par référence et par jour, 10 Gio par organisation ; 2 réencodages par
  instance, un export et un réencodage par compte **[à relire]**.
- `allowed_namespaces` obligatoire pour l'agent dépôt (configuration existante à
  compléter) **[à relire]**.
- SEC-09 et SEC-13 acceptés (voir le tableau) **[à relire]**.

#### Écarts

- SEC-09 (Low) n'est pas corrigé mais accepté jusqu'à T16 (voir le tableau).
- SEC-11 : la validation et le décodage de Syft ne sont pas interrompus en cours d'étape.

#### ADR créés

0029, 0030, 0031.
### Audit RGAA

Réalisé le 31 octobre 2026, branche `lot/T11-accessibilite`. Grille finale :
[`docs/accessibilite/grille-rgaa-lot1.md`](../../docs/accessibilite/grille-rgaa-lot1.md).

#### Résultat

Audit initial sur `main` (8369ad0) : 85,7 % (60 critères conformes sur 70 applicables),
13 constats, 0 bloquant, 4 majeurs, 9 mineurs. Après corrections : **100 %** (72 sur 72 ;
12.3 et 12.4 deviennent applicables avec le plan du site), aucun constat ouvert. Contre-audit
outillé sur 88 pages, les 11 pages de confirmation et le plan du site, en français et en
anglais, thèmes clair et sombre : axe-core sans aucun écart (368 rendus), aucun défilement
horizontal à 320 et 390 px ni à 200 % de texte, parcours clavier sans piège, captures de
contrôle des écrans corrigés dans les deux thèmes.

| NC | Gravité | Critère | Statut | Commit |
| --- | --- | --- | --- | --- |
| NC-01 navigation latérale trop large | majeure | 10.11 | corrigé, vérifié | PR #13 |
| NC-02 texte masqué hors des tableaux | majeure | 10.11 | corrigé, vérifié | PR #13 |
| bande vide sous la navigation | défaut | 10.11 | corrigé, vérifié | PR #13 |
| NC-03 menu d'organisation à 320 px | mineure | 10.11 | corrigé | 9bd0e4a |
| NC-04 PURL insécable | mineure | 10.11 | corrigé | 9bd0e4a |
| NC-05 compteurs de sévérité sans libellé | majeure | 3.1, 10.9, 10.10 | corrigé | 9bd0e4a |
| NC-06 ligne sélectionnée par la couleur | mineure | 3.1 | corrigé | 9bd0e4a |
| NC-07 version vulnérable par la couleur | mineure | 3.1 | corrigé | 9bd0e4a |
| NC-08 titres peu discriminants | mineure | 8.6 | corrigé | 9bd0e4a |
| NC-09 noms de langue sans `lang` | mineure | 8.7 | corrigé | 9bd0e4a |
| NC-10 bouton « Modifier » sans contexte | mineure | 11.9 | corrigé | 9bd0e4a |
| NC-11 format attendu masqué | mineure | 11.10 | corrigé | 9bd0e4a |
| NC-12 actions irréversibles en un clic | majeure | 11.12 | corrigé | 9bd0e4a |
| NC-13 un seul système de navigation | mineure | 12.1 | corrigé | 9bd0e4a |

#### Livré

- **Confirmation des actions irréversibles** (NC-12) : `GET` sur l'URL de l'action →
  page commune `confirm/action` (`internal/web/confirm_pages.go`), `POST` sur la même URL
  → action ; lien « Annuler ». Jetons d'agent, d'inscription et personnels, désactivation
  d'un agent, retrait d'un membre (texte propre pour soi-même), réinitialisation du mot de
  passe et du TOTP, abandon d'un traitement en échec. Les `POST` existants sont inchangés.
  Nouvelle lecture `org.Service.Member`.
- **Titres de page** (NC-08) : « écran — organisation » par le layout (organisation
  courante de l'en-tête), requête de la recherche, préfixe « Erreur : » posé par
  `render.Render` pour un écran rendu en 4xx (`render.Page.Failed`, jamais sur les pages
  d'erreur) ; `dashboard.title` ne répète plus le nom.
- **Plan du site** (NC-13) : `/sitemap`, lié du pied de page des sessions complètes
  (`render.Chrome.Authenticated`), construit par `orgNav` (selon le rôle dans chaque
  organisation), `accountNav` et `adminNav`.
- Présentation : sélecteur d'organisation (NC-03), en-tête de page (NC-04), compteurs de
  sévérité abrégés et repliables (NC-05), ligne sélectionnée (NC-06), répartition des
  versions (NC-07), `lang` des noms de langue (NC-09, option `option.Lang`), « Modifier le
  rôle » et colonne Actions des membres de nouveau lisible (NC-10 ; le bouton était
  recouvert par « Retirer »), aide des étiquettes visible (NC-11).
- Recommandations traitées : zones défilantes de tableau en `role="group"` nommé et
  focalisable partout (R-01, R-06), espaces entre texte masqué et visible (R-05), couleur
  des textes indicatifs (R-11), aide de l'import de la base liée au champ.
- Garde-fous : `webtest.CheckAccessibility` refuse une aide `aria-describedby` masquée
  visuellement et une option de `<select name="language">` sans `lang` égal à sa valeur ;
  tests d'intégration `TestIrreversibleActionsAreConfirmed` (lien, page sans effet,
  fr/en, accessibilité, `POST`, objet déjà révoqué, 404), `TestPageTitlesAreDistinct`,
  `TestSiteMap`, assertions de `TestFindingScreens` ; `TestRenderTitle` ; les nouvelles
  routes `GET` passent dans les harnais d'isolement par route et d'administration.
- Clés de traduction (fr, en) : `layout.title_org`, `layout.title_error`,
  `search.title_query`, `severity_short.*`, `component.this_version`,
  `snapshots.ref_shown`, `footer.sitemap`, `sitemap.*`, `confirm.*` ;
  `members.change_role` et `dashboard.title` modifiées.
- `architecture.md` § 14 : conventions issues de l'audit (actions irréversibles, titres,
  plan du site, zones de tableau).

#### Décisions

- **Page de confirmation plutôt que case « je confirme »** **[à relire]** : un seul
  gabarit et une seule fonction pour toutes les actions, l'objet et les conséquences
  écrits en toutes lettres, aucune modification des `POST` existants (moins de conflits
  avec la revue de sécurité menée en parallèle), et une case dans chaque ligne de tableau
  aurait alourdi les listes. Prix : un aller-retour de plus. La purge des archives garde
  sa case (partie 1), conforme elle aussi.
- **Abandon d'un traitement confirmé** **[à relire]** : il supprime le job et sa dernière
  erreur (irréversible pour l'administrateur) ; revient sur la décision de la partie 1
  (« sans confirmation »). « Relancer » reste en un clic.
- **NC-13 : plan du site** plutôt que la recherche comme second système **[à relire]** :
  la recherche transverse cherche des composants et des vulnérabilités, pas des pages ;
  elle ne satisfait pas 12.1. Plan simple, sans nouvelle donnée, réservé aux sessions
  complètes.
- **« Erreur : » sur tout écran rendu en 4xx** **[à relire]** : règle centrale dans
  `render` plutôt qu'écran par écran ; vaut aussi pour une recherche illisible (400) et
  l'écran des traitements renvoyé en 404 après un double envoi.
- **Abréviations des sévérités** (« Crit. », « Élev. », « Moy. », « Faible » ; « Crit »,
  « High », « Med », « Low ») avec le libellé complet en `title` et pour les lecteurs
  d'écran **[à relire]**.
- Pas d'ADR : pas de décision structurante au-delà des conventions consignées au § 14.
- Pas de test Playwright dans le dépôt : la CI n'a pas de navigateur et le brief exclut
  toute nouvelle dépendance ; la redistribution à 320 px reste vérifiée à l'audit
  (scripts hors dépôt), les règles statiques sont dans `webtest`.

#### Écarts

- Recommandations R-02, R-03, R-04, R-07, R-08, R-09, R-10 non traitées (hors grille,
  listées au § 6 de la grille).

#### ADR créés

Aucun.

### Recette

Réalisée le 31 octobre 2026, branche `lot/T11-recette`.

#### Parc pilote et CVE de contrôle (fixés avant toute recherche)

Fixés et commités **avant** le montage du serveur et toute recherche dans l'application.
Les listes attendues sont établies à la main : paquets réellement installés dans chaque
image (`dpkg-query`, `rpm -qa`, `/lib/apk/db/installed`), fichiers de dépendances de
chaque dépôt au commit retenu (`git show <commit>:go.mod`…), confrontés aux
enregistrements de la base Grype réelle (v6.1.10, construite le 30 octobre 2026 à
06:23 UTC) lus directement en SQLite, sans passer par l'application.

**Serveurs** (conteneurs portant l'agent serveur ; images anciennes à dessein, pour un
parc réaliste non mis à jour) :

| Projet attendu | Image | Empreinte | Paquets |
| --- | --- | --- | --- |
| `pilot-debian` | `debian:12.0-slim` | `sha256:9bd077d2f77c…` | 88 deb |
| `pilot-rocky` | `rockylinux:9.2-minimal` | `sha256:594c839a772e…` | 118 rpm |
| `pilot-alpine` | `alpine:3.18.0` | `sha256:02bb6f428431…` | 15 apk |

**Dépôts** (clones de dépôts publics réels, servis par une forge simulée : voir plus
bas) :

| Projet attendu | Dépôt public | Branche, commit retenu | Contenu |
| --- | --- | --- | --- |
| `cobra` | GitHub `spf13/cobra` | `main`, `adbc881` (11 juillet 2026) | `go.mod` sans `golang.org/x/crypto` |
| `sftp` | GitHub `pkg/sftp` | `master`, `5bdc2b0` (20 novembre 2023) | `go.mod` : `golang.org/x/crypto v0.1.0` |
| `gitlab-shell` | GitLab `gitlab-org/gitlab-shell` | `main`, `09ef3a7` (18 décembre 2023) | `go.mod` : `golang.org/x/crypto v0.16.0` ; `Gemfile.lock` |
| `jekyll` | GitLab `pages/jekyll` | `main`, `3137780` (30 avril 2025) | `Gemfile.lock` |

L'agent serveur lui-même (binaire Go, `golang.org/x/crypto v0.58.0`, Go 1.26.10) est
inventorié sur chaque hôte : il n'est touché par aucune des trois CVE.

**CVE de contrôle et listes attendues :**

1. **CVE-2023-4911** (glibc, « Looney Tunables », KEV) → **`pilot-debian`,
   `pilot-rocky`**.
   - `pilot-debian` : `libc6` et `libc-bin` 2.36-9 (source `glibc`) ; Debian 12 :
     corrigé en 2.36-9+deb12u3.
   - `pilot-rocky` : `glibc`, `glibc-common`, `glibc-minimal-langpack` 2.34-60.el9 ;
     RHEL 9.2 : corrigé en 2.34-60.el9_2.7 (Rocky lu comme RHEL par Grype).
   - Pas `pilot-alpine` (musl, pas de glibc), aucun dépôt.
2. **CVE-2023-48795** (« Terrapin », SSH ; GHSA-45x7-px36-x8w8 pour Go) →
   **`pilot-rocky`, `sftp`, `gitlab-shell`**.
   - `pilot-rocky` : `libssh` et `libssh-config` 0.10.4-8.el9 ; RHEL 9.2 : corrigé en
     0.10.4-9.el9_2.
   - `sftp` : `golang.org/x/crypto` v0.1.0 ; `gitlab-shell` : v0.16.0 ; corrigé en
     0.17.0 (plage GitHub `>=0.1.0,<0.17.0`).
   - Pas `pilot-debian` ni `pilot-alpine` (ni OpenSSH, ni libssh, ni dropbear), pas
     `cobra` (pas de `x/crypto`), pas `jekyll`.
3. **CVE-2023-2650** (OpenSSL, `OBJ_obj2txt`) → **`pilot-rocky`, `pilot-alpine`**.
   - `pilot-rocky` : `openssl` et `openssl-libs` 1:3.0.7-6.el9_2 ; RHEL 9.2 : corrigé en
     1:3.0.7-16.el9_2.
   - `pilot-alpine` : `libcrypto3` et `libssl3` 3.1.0-r4 (origine `openssl`) ; Alpine
     3.18 : corrigé en 3.1.1-r0.
   - Pas `pilot-debian` (`debian:12.0-slim` n'installe pas OpenSSL), aucun dépôt (aucune
     gemme `openssl`).

Contrôles négatifs implicites : `cobra` et `jekyll` n'apparaissent dans aucune liste ;
chaque serveur manque à au moins une liste.

#### Montage du serveur pilote

Machine : environnement de réalisation (4 cœurs Intel Xeon 2,8 GHz, 15 Gio, Linux 6.18,
PostgreSQL 16.15 local, Docker 29.9). Binaires de `make build` au commit `8639f13`.

- Base `ogsbom_t11r_cc6902` et rôles jetables `ogsbom_owner_cc6902` (`BYPASSRLS`) et
  `ogsbom_app_cc6902` créés selon « Rôles et droits » de `docs/operations.md` ; les
  15 migrations passent au premier démarrage, le contrôle du rôle d'exécution aussi.
- TLS natif par une autorité de test (certificat `sbom.pilot.test`), **mTLS exigé**
  (`tls.client_ca_file` : autorité des agents distincte), `auth.cookie_secure: on`,
  `vulndb.offline: true`.
- Premier administrateur par `OGSBOM_BOOTSTRAP_ADMIN_*` ; connexion, enrôlement TOTP et
  changement du mot de passe temporaire pilotés par l'interface (formulaires, jeton CSRF
  lié à la session, code TOTP calculé), comme un navigateur.
- **Base Grype réelle importée par l'écran d'administration** : archive tar.gz de la base
  v6.1.10 du 30 octobre 2026 (618 Mio), téléversée en 21 s, installée par le job
  `vulndb.import` puis chargée (`/readyz` : `vulndb ok`) en 70 s.
- Organisation « Parc pilote » (`pilote`), quatre projets de dépôt, un agent dépôt, un jeton
  d'inscription (3 usages, 24 h), tous créés par l'interface.

#### Parc pilote : résultat

- **Serveurs** : agent installé par son **paquet deb** (Debian) et **rpm** (Rocky), qui
  créent l'utilisateur `ogsbom-agent` sans systemd ; lancé sous cet utilisateur avec la
  seule capacité `CAP_DAC_READ_SEARCH` (`setpriv`, comme l'unité), en démon (`poll_interval`
  30 s). Alpine : binaire et configuration, root, mode `oneshot`. Les trois s'inscrivent
  en mTLS (certificat client par hôte) et envoient leur SBOM en 3 à 5 s (288 à 392
  composants : paquets du système et modules Go de l'agent lui-même).
- **Dépôts** : l'agent dépôt réel (`ogsbom-repo-agent` dans un conteneur `alpine/git`)
  contre une **forge simulée** locale qui sert l'API de GitHub (JWT RS256 de l'application
  vérifié, jeton d'installation restreint au dépôt et à `contents: read`) et de GitLab
  (`Private-Token`), et git HTTP intelligent (`git http-backend`) sur des **clones nus des
  dépôts publics réels** (`git clone --bare` depuis github.com et gitlab.com par le
  mandataire), têtes de branche placées aux commits retenus. Premier rattrapage : les
  quatre SBOM envoyés en 4 s.
- **Instantanés et analyses** (relus en base par le propriétaire, pas par la recherche) :
  les sept projets ont un instantané courant daté du 31 octobre 2026 entre 14:48 et 14:51
  UTC (moins de 24 h) et une analyse par la base du 30 octobre (0 à 711 correspondances).
- **Scan à la demande** : « Scanner maintenant » sur `pilot-debian` à 14:53:19, cycle
  « inventaire inchangé, confirmé » à 14:53:26.
- **mTLS** : sans certificat client, 401 `error.client_cert_required` ; certificat d'une
  autre autorité, refus à la négociation TLS ; certificat valide et jeton faux, 401
  `error.token.invalid` ; l'interface reste accessible sans certificat.
- **Webhooks et push** : webhook GitLab au secret faux refusé (401) ; la branche `master`
  de `pkg/sftp` avancée au commit `22452ea` (montée de `x/crypto` en 0.17.0), webhook
  GitHub signé accepté (202), sa relivraison ignorée (200) ; l'agent analyse le commit
  intermédiaire manqué puis la tête.
- **Sauvegarde et restauration** : `pg_dump -Fc` par le propriétaire (600 Mio, 71 s),
  `pg_restore --no-owner --role=…` dans une base neuve (26 s, sans erreur), serveur
  démarré dessus (schéma à jour, rôle d'exécution accepté : retraits du journal en ajout
  seul restaurés), connexion et trois recherches identiques. Procédure reportée dans
  `docs/operations.md`.

#### CVE de contrôle : verdict

Recherche par l'écran (`/o/pilote/search?q=…`, projets des groupes de résultats) et par
l'API utilisateur (jeton personnel, `GET /api/v1/orgs/pilote/search`), comparée aux listes
fixées plus haut :

| CVE | Attendu | Écran | API | Occurrences | Verdict |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-4911 | `pilot-debian`, `pilot-rocky` | identique | identique | 5 : `libc6`, `libc-bin` 2.36-9 ; `glibc`, `glibc-common`, `glibc-minimal-langpack` 2.34-60.el9 | **exact** |
| CVE-2023-48795 | `pilot-rocky`, `sftp`, `gitlab-shell` | identique | identique | 4 : `libssh`, `libssh-config` 0.10.4-8.el9 ; `golang.org/x/crypto` v0.1.0 et v0.16.0 | **exact** |
| CVE-2023-2650 | `pilot-rocky`, `pilot-alpine` | identique | identique | 4 : `openssl`, `openssl-libs` 1:3.0.7-6.el9_2 ; `libcrypto3`, `libssl3` 3.1.0-r4 | **exact** |

Aucun écart, jusqu'au composant près (les occurrences sont exactement les paquets
identifiés à la main). Après le push de `pkg/sftp` : CVE-2023-48795 et
GHSA-45x7-px36-x8w8 renvoient `pilot-rocky`, `gitlab-shell` (sftp sorti), à l'écran et par
l'API ; `pkg:golang/golang.org/x/crypto vers:golang/<0.17.0` renvoie `gitlab-shell` et
4 occurrences hors plage. Les mêmes résultats sont relus sur la base restaurée.

#### Mesures consolidées

Machine : environnement de réalisation (4 cœurs Xeon 2,8 GHz, 15 Gio), **moins puissante
que la machine de référence** (16 cœurs, 30 Go) : selon `docs/benchmarks.md`, une cible
tenue ici vaut pour la référence. Protocole de `docs/benchmarks.md` (RLS active, 95e
centile, froid et chaud), conteneurs du parc suspendus pendant les mesures.

| Mesure (commande) | Cible | Résultat (p95) | Verdict |
| --- | --- | --- | --- |
| Ingestion et analyse de 5 000 composants, vraie base (`make bench-ingest`) | 30 s | **6,61 s** (froid 5,90 s, p50 6,07 s, dont ingestion 0,73 s) | tenue |
| Recherche, pire cas : page suivante du nom large (`make bench-search`) | 2 s | **344 ms** (nom large 288 ms, vulnérabilité 35 ms, plage 35 ms) | tenue |
| Export CSV de 16 675 lignes | — | 985 ms | — |
| Tableau de bord, 12 mois (`make bench`) | 1 s | **663 ms** (90 jours : 626 ms ; fiche projet 34 ms) | tenue |
| Scan de l'agent serveur, `/` sans `/root`, `/home`, `/tmp` (protocole de T07, `measure`) | 5 min de CPU, 1 Gio | **3 min 8 s de CPU, 921 Mio** au plus sur 6 cycles (médiane 2 min 27 s) | tenue |
| Scan de l'agent serveur, conteneurs du parc (300 à 400 composants) | idem | 3 à 5 s de bout en bout | tenue |

Les cibles du cahier des charges restent marquées « proposées (à valider) » : leur
confirmation est une décision de l'utilisateur **[à relire]**. Rien n'a été mesuré sur la
machine de référence elle-même (facultatif, mêmes commandes).

#### Documentation et préversion

- `docs/operations.md` relu de bout en bout et complété : sommaire, **installation de
  production** (archive, unité systemd du serveur, fichier d'environnement des secrets,
  clé TLS par credential, premier administrateur, plusieurs instances), **autorité privée
  et certificats des agents** (mTLS), agent serveur **sans systemd** (conteneurs, Alpine),
  **installation de l'agent dépôt**, **recette sur une vraie forge** (procédure pas à pas),
  **sauvegarde et restauration** (vérifiées), **mise à jour** (ordre, migration,
  retour arrière), **supervision** (tableau des signaux et règles Prometheus).
- Guides de démarrage **`docs/demarrage.md`** (français) et **`docs/getting-started.md`**
  (anglais), reliés depuis le README ; `docs/utilisation.md` reste le guide détaillé de
  la recherche. Les exemples de requêtes des guides ont été rejoués sur le parc pilote.
- **`CHANGELOG.md`** (Keep a Changelog, en français) : section `[0.1.0]` par lot
  technique, liens vers les PR #1 à #16.
- **`.github/workflows/release.yml`** et **`scripts/release.sh`** (`make release`),
  **`deploy/systemd/ogsbom-server.service`** (vérifiée par `systemd-analyze verify`),
  `make bench-ingest` ; ADR 0032. Construction vérifiée en local
  (`make release VERSION=v0.1.0 RELEASE_DIR=…`, répertoire temporaire) : six archives
  (trois rôles × amd64, arm64 ; binaire statique, `--version` donne `v0.1.0`, configuration
  d'exemple et unités), quatre paquets (`ogsbom-host-agent_0.1.0_amd64.deb`…, version
  `0.1.0`), `SHA256SUMS` vérifié par `sha256sum -c` ; deux constructions donnent des
  archives identiques octet pour octet (les paquets diffèrent par l'horodatage de nfpm) ;
  une version mal formée (`0.1`) est refusée. Extraction des notes de version rejouée.
- `v0.1.0` **non publiée** : le mandataire git de la session refuse les pushs d'étiquettes.
  Marche à suivre exacte : `specs/avancement.md`, « Actions pour l'utilisateur ».

#### Décisions

- **Parc pilote en conteneurs** plutôt qu'en machines virtuelles, images anciennes
  épinglées (vulnérabilités connues et corrigées depuis), agents lancés par `setpriv` hors
  systemd **[à relire]** : la décision de la fiche dit « conteneurs » ; l'unité systemd
  elle-même a été vérifiée en T07.
- **Forge simulée** pour les dépôts, servant de vrais clones de dépôts publics : sans
  GitHub App ni compte GitLab dans la session, c'est le maximum vérifiable ; l'essai sur
  une vraie forge est une action de l'utilisateur **[à relire]**.
- **CVE de contrôle** choisies pour couvrir trois distributions, deux forges, un mélange
  hôte et dépôt, une KEV et un identifiant GHSA ramené au CVE, chaque hôte manquant à au
  moins une liste **[à relire]**.
- **Outillage de recette hors dépôt** (forge simulée, client de l'interface, scripts de
  parc, dans le répertoire temporaire de la session) : code de test non maintenu, qui
  aurait demandé ses propres tests ; la procédure est décrite ici et dans
  `docs/operations.md` **[à relire]**.
- **Cible tenue sur 4 cœurs = tenue sur la référence**, critère coché sur cette base ;
  l'agent serveur mesuré sur 6 cycles (3 envois, 3 confirmations), pas 20, chaque cycle
  coûtant 2 à 3 min de CPU : la cible est un plafond par scan, tenu sur chaque cycle avec
  37 % de marge en CPU et 10 % en mémoire (921 Mio pour 1 Gio) **[à relire]**.
- **Publication** (ADR 0032) : étiquette sur `main`, préversions seulement jusqu'à T26,
  archives tar.gz par rôle et architecture avec configuration et unités, paquets deb et
  rpm, `SHA256SUMS`, notes tirées de `CHANGELOG.md` ; **unité systemd du serveur** ajoutée
  (`DynamicUser`, secrets par fichier d'environnement) — livrable d'exploitation, pas une
  fonction **[à relire]**.
- **Guides de démarrage séparés** (`demarrage.md`, `getting-started.md`) plutôt que dans
  `utilisation.md` : parcours court, bilingue ; l'usage détaillé reste en français
  **[à relire]**.
- `CHANGELOG.md` daté du 31 octobre 2026 ; à ajuster au jour de la pose de l'étiquette
  **[à relire]**.

#### Écarts

- `v0.1.0` non publiée (action de l'utilisateur) : critère non coché.
- Agent dépôt non essayé sur une vraie forge (action de l'utilisateur, procédure écrite).
- Aucun défaut du produit trouvé par la recette : aucun correctif de code.
- Une base jetable orpheline d'un autre lot (`ogsbom_t_3fc4057fe7b5`, 10:43 UTC) reste sur
  le PostgreSQL partagé de la session ; non supprimée (elle n'est pas de ce lot).

#### ADR créés

0032.
