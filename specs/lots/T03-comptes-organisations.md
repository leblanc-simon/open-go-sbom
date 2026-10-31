# T03 — Comptes, TOTP et organisations

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T01 | Terminé |

## Objectif

Se connecter avec un compte local protégé par un TOTP obligatoire, appartenir à une ou
plusieurs organisations avec un rôle, et ne jamais voir les données d'une autre
organisation. Poser le journal d'audit, la garde d'organisation et l'enregistrement de la
méthode d'authentification que tous les lots suivants utilisent.

## Périmètre

**Inclus**

- Câblage d'`authx` et `mfax` (stores SQL ; leurs `Migrate` dans le verrou de migration de
  T01) ; enrôlement TOTP obligatoire ; implémentation des `Renderer` : connexion, second
  facteur, configuration du TOTP avec QR, profil, changement de mot de passe.
- `internal/account` : écriture des comptes dans `users` (création avec
  `authx.HashPassword`, désactivation via `is_active`, réinitialisation du mot de passe,
  rôle d'instance via `role`) ; application de `must_change_pwd` par un middleware, puisque
  ni authx ni mfax ne le font.
- Table `session_auth` : pour chaque session ouverte, méthode `local_totp` (et, en T25,
  `sso` avec l'organisation du fournisseur). La garde d'organisation la lit.
- Premier administrateur depuis `bootstrap.*` ; changement de mot de passe et enrôlement
  TOTP à la première connexion. Avertissement s'il n'existe qu'un administrateur
  d'instance ; procédure de secours (variable d'environnement lue au démarrage, auditée)
  pour réinitialiser le TOTP d'un administrateur.
- Administration d'instance : comptes (création avec mot de passe temporaire, désactivation,
  réinitialisation du mot de passe et du TOTP), promotion administrateur d'instance,
  organisations (création, renommage, langue par défaut, archivage).
- Organisation : membres (ajout d'un compte existant, rôle, retrait) par ses
  administrateurs ; sélecteur d'organisation dans l'en-tête ; organisation par défaut du
  compte.
- `internal/tenant` : type `OrgID`, contexte, middleware `/o/{slug}`, contrôle
  d'appartenance, `RequireOrgRole`.
- `internal/audit` : table, `audit.Record`, écran de consultation (instance et organisation).
- `account_settings` : langue, thème, organisation par défaut ; la préférence de langue
  s'insère dans l'ordre du § 18.
- Limitation de débit dédiée (paquet `ratelimit` d'open-go-base) sur `/login` et
  `/login/2fa`.
- Premières tables d'organisation, sous RLS forcée (§ 9 de l'architecture) :
  `organizations`, `org_memberships`, `audit_events`. Les événements d'instance (sans
  organisation) vont dans la table globale `instance_audit_events`.
- Premières fonctions de `internal/db/crossorg` : résolution d'un slug et de l'appartenance
  pour la garde, liste des organisations d'un compte pour le sélecteur. La garde n'accède
  aux tables d'organisation qu'à travers elles tant que l'organisation n'est pas déclarée.
- Harnais de tests d'isolement réutilisé par chaque lot : parcours des routes avec un compte
  d'une autre organisation, et tests SQL de RLS (requêtes sans filtre dans `InOrg`, requêtes
  hors `InOrg`) qu'il suffit d'étendre à chaque nouvelle table.

**Exclu** : SSO (T25), équipes (T16), envoi de courriels (T15).

## Conception

- Rôles d'organisation : `viewer`, `analyst`, `admin`, dans `org_memberships`
  (`user_id bigint`). L'administrateur d'instance est le rôle `admin` d'authx ; c'est un
  rôle privilégié assumé : il ne voit pas les données d'une organisation dont il n'est pas
  membre, mais il peut réinitialiser les identifiants de n'importe quel compte, et chaque
  réinitialisation est auditée.
- Accès à une organisation dont on n'est pas membre : **404**.
- Politique de mot de passe : 12 caractères minimum, sans règle de composition, refus des
  mots de passe égaux à l'e-mail.
- Les messages d'erreur d'authx, mfax et csrfx sont en français dans open-go-base (§ 23 de
  l'architecture). Avant d'écrire les écrans, proposer l'évolution « erreurs sous forme de
  clés » ; tant qu'elle n'est pas disponible, le `Renderer` traduit à partir de la nature de
  l'erreur et non du texte reçu.
- ADR « isolement des organisations » : RLS obligatoire, schéma par organisation écarté
  (raisons du § 9 de l'architecture), liste initiale des fonctions de `crossorg` et règle de
  revue de tout ajout.

## Livrables

Écrans de connexion, second facteur, configuration TOTP, profil, administration d'instance,
membres d'organisation, journal d'audit ; migrations avec politiques RLS ; fonctions de
`crossorg` ; ADR d'isolement ; harnais d'isolement ; procédure de secours dans
`docs/operations.md`.

## Critères d'acceptation

- [x] Un compte local sans TOTP enrôlé ne peut ouvrir aucune session applicative.
- [x] Un compte avec `must_change_pwd` ne peut atteindre aucune page avant d'avoir changé
      son mot de passe.
- [x] Le premier administrateur est créé une seule fois ; `bootstrap.*` est ignoré ensuite.
- [x] Un membre de l'organisation A reçoit 404 sur toute URL de l'organisation B.
- [x] Dans `InOrg(A)`, des requêtes sans filtre sur `organizations`, `org_memberships` et
      `audit_events` ne lisent ni n'écrivent rien de B ; hors `InOrg`, elles échouent.
- [x] Un `viewer` ne peut modifier ni les membres ni les paramètres de l'organisation.
- [x] Chaque action d'administration produit un événement d'audit lisible.
- [x] Les erreurs de connexion sont génériques, traduites et à temps de réponse égalisé.
- [x] La procédure de secours rend l'accès à un administrateur qui a perdu son TOTP, et
      laisse une trace d'audit.
- [x] Tous les écrans passent l'assistant d'accessibilité, en français et en anglais.

## Tests attendus

Intégration de bout en bout du parcours de connexion (mot de passe, TOTP avec horloge
simulée, rejeu de code refusé), du bootstrap, du changement de mot de passe imposé, des
rôles, de l'isolement, de la procédure de secours.

## Décisions

Prises le 31 octobre 2026 :

- Mot de passe : 12 caractères minimum.
- Évolutions d'open-go-base (erreurs sous forme de clés, gestionnaire d'échec de csrfx)
  réalisées dans open-go-base : branche, PR fusionnée quand la CI est verte, étiquette
  semver ; open-go-sbom passe ensuite à cette version.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T03-comptes-organisations`, en parallèle de T02
(fusionné dans la branche avant la version finale).

### Livré

- **open-go-base** (évolutions du § 23) : erreurs d'authx et de mfax sous forme de codes
  stables (`ErrorCode`, `LoginView.Code`, `VerifyView.Code`, `SetupView.Code`),
  `ErrorHandler` configurable pour les 400, 403 et 500 (la cause n'est plus jamais
  renvoyée au client), `csrfx.WithFailureHandler`, `mfax.ChallengeCookieName`. PR #1
  d'open-go-base, fusionnée (squash, commit `b9ccc67`). Pas de CI sur ce dépôt :
  `go vet ./...` et `go test -race ./...` verts en local, seule vérification possible.
  Étiquette `v1.1.0` annotée créée dans le clone, **pas poussée** (voir Écarts) :
  open-go-sbom utilise la pseudo-version `v1.0.2-0.20261031034511-b9ccc67d239a`.
- **Stores PostgreSQL d'authx et de mfax** exécutés pour la première fois sur
  PostgreSQL 16 (sonde jetable, puis tous les tests d'intégration de ce lot) : migrations
  idempotentes, les quatre stores, anti-rejeu et plafond de tentatives. **Aucun défaut**.
- `internal/db` : `Migrate` joue toujours authx puis mfax sous le verrou (`external.go`) ;
  migrations **003** (droits sur les tables d'authx et de mfax, `account_settings`,
  `session_auth` et son déclencheur de nettoyage, `instance_audit_events`), **004**
  (`organizations`, `org_memberships`, `audit_events`, RLS standard) et **005**
  (fonctions de `crossorg`).
- `internal/db/crossorg` : `Access`, `UserOrgs`, `ListOrganizations`, `OrgIDBySlug`.
- `internal/tenant` : `Role` (`viewer` < `analyst` < `admin`), `Access` et son contexte.
- `internal/audit` : `RecordOrg`, `RecordInstance` (dans la transaction de l'action),
  `ListOrg`, `ListInstance` (curseurs), catalogue des actions et leurs phrases traduites.
- `internal/account` : seul écrivain de `users` (création à mot de passe temporaire,
  activation, rôle d'instance, réinitialisations, changement de mot de passe),
  préférences, `SessionRecorder` (méthode de session et journal des connexions),
  `SealedTOTPStore` (secrets TOTP chiffrés) et rechiffrement, bootstrap, procédure de
  secours, `Startup`, purge horaire (`auth.purge` sur la file de T02), état du visiteur.
- `internal/org` : organisations (création, nom, langue, archivage) et membres (ajout d'un
  compte existant, rôle, retrait), toujours par `InOrg`.
- `internal/config` : fragments `Auth`, `MFA` (appconf), `Login`, `Bootstrap` ; clés de
  secrets obligatoires.
- `internal/web` : identité (authx, mfax, visiteur, gardes), pages de connexion, compte,
  organisation et administration ; `render.Chrome` (en-tête : compte, sélecteur
  d'organisation) ; page d'erreur 400/403 et `ErrorWithKey`.
- Écrans (fr, en, clair, sombre) : connexion, second facteur, enrôlement TOTP avec QR,
  compte (langue, thème, organisation par défaut), mot de passe, vue d'ensemble de
  l'organisation, membres, paramètres de l'organisation, journal d'audit (organisation et
  instance), comptes, compte, mot de passe temporaire, organisations, organisation.
  Composants portés depuis `ogs.css` : champs (`form.css`), `callout`, tableau,
  `status`/`chip`, `avatar`/`org-switcher`, `kv` ; écran `auth.css` (pas de planche :
  carte construite sur panneau et champs).
- Harnais d'isolement : SQL (`internal/db/orgtables_integration_test.go`, contrôlé contre
  le catalogue) et routes (`internal/web/isolation_integration_test.go`, `chi.Walk`).
- ADR 0012 (isolement des organisations) et 0013 (comptes et second facteur) ;
  `architecture.md`, `docs/operations.md` (comptes, secours, rôle `BYPASSRLS`, clés),
  modèle de menace, `config.example.yaml`.

### Décisions

- **Propriétaire `BYPASSRLS`** (ADR 0012) **[à relire]** : sous RLS forcée, une fonction
  `SECURITY DEFINER` du propriétaire ne voit rien sans organisation déclarée.
  L'attribut ne lui donne rien qu'il n'ait déjà (il peut désactiver la RLS de ses tables).
  Exige `ALTER ROLE ogsbom_owner BYPASSRLS` sur une base existante ; `initdb` et `dbtest`
  le posent.
- **Secrets TOTP chiffrés** par `internal/secret` (ADR 0013) **[à relire]** : écart à
  mfax, qui les stocke en clair ; `secrets.keys` devient obligatoire ; rechiffrement par
  la clé active au démarrage.
- **Procédure de secours par ticket** (ADR 0013) **[à relire]** : deux variables
  (`bootstrap.rescue_totp_email`, `bootstrap.rescue_ticket`) au lieu d'une, appliquées une
  fois par couple (compte, ticket), pour qu'une variable oubliée ne retire pas le TOTP à
  chaque redémarrage.
- **Ordre du premier login** **[à relire]** : enrôlement du TOTP (session de configuration
  de mfax), puis changement de mot de passe imposé.
- **Administration** : une page refusée à un non-administrateur d'instance répond **404**
  (comme une page absente) ; une action refusée à un membre de l'organisation répond 403
  (il connaît l'organisation). Le journal de l'organisation et ses paramètres sont
  réservés à ses administrateurs **[à relire]**. Les administrateurs de l'organisation en
  gèrent le nom et la langue ; l'archivage et la création reviennent à l'administrateur
  d'instance, qui peut aussi nommer un administrateur d'organisation (cas d'une
  organisation sans administrateur).
- **Garde-fous** : le dernier administrateur d'instance actif ne peut être ni désactivé
  ni rétrogradé ; un administrateur ne se désactive pas lui-même ; une organisation garde
  au moins un administrateur.
- **Journal** : événements d'instance (comptes, connexions, organisations) dans
  `instance_audit_events` ; événements d'organisation (membres, paramètres) dans
  `audit_events` ; création, renommage et archivage d'une organisation dans les deux.
  Échecs de connexion journalisés avec l'adresse saisie. Préférences du compte
  journalisées aussi.
- **IP des sessions** : `X-Forwarded-For` réécrit avec l'IP résolue par les mandataires de
  confiance avant authx (qui lit l'en-tête sans vérifier le pair).
- **Désactivation du TOTP par l'utilisateur** non montée : le TOTP est obligatoire ; pour
  changer d'appareil, un administrateur le réinitialise (codes de secours en T11).
- **Thème du compte** : le cookie de la bascule l'emporte ; la préférence s'applique faute
  de cookie, et l'enregistrer pose le cookie.
- `jobs.org_id` reste **sans** clé étrangère vers `organizations` : les tests de T02
  mettent en file des jobs d'organisations fictives ; à poser avec le premier lot qui met
  en file des jobs d'organisation réels (T05) **[à relire]**.
- Purge des sessions et défis expirés : job horaire `auth.purge` de la file de T02.

### Écarts

- **Étiquette `v1.1.0` d'open-go-base non poussée** : le mandataire git de la session
  refuse les pushs d'étiquettes (HTTP 403, branches acceptées). L'étiquette annotée existe
  dans `/home/user/open-go-base` (sur `b9ccc67`). À faire par l'utilisateur :
  `git -C ../open-go-base push origin v1.1.0`, puis
  `go get leblanc.io/open-go-base@v1.1.0 && go mod tidy` ici (même code).
- `internal/tenant` ne porte pas le middleware `/o/{slug}` ni `RequireOrgRole` : `tenant`
  est un paquet métier, interdit de `net/http` (§ 4). La garde (`orgGuard`) et
  `requireOrgRole` vivent dans `internal/web/identity.go` ; `tenant` porte les types
  (`Role`, `Access`) et le contexte.
- Handlers et modèles de vue dans `internal/web` (un fichier par famille d'écrans), comme
  la page d'accueil de T01, plutôt qu'un sous-paquet par écran.
- Horloge simulée du TOTP : mfax n'injecte pas d'horloge ; les tests produisent des codes
  pour les pas −30 s, 0 et +30 s (tolérance de mfax), ce qui couvre l'avancée du temps et
  le rejeu.

### Mesures

- Couverture (unitaires et intégration) : `account` 84,5 %, `org` 85,7 %, `audit`
  87,3 %, `db/crossorg` 80,4 %, `tenant` 97,6 %, `db` 84,8 %, `web` 82,3 %, `render`
  90,0 %, `config` 97,2 %.
- Requêtes par page authentifiée : session et compte (authx, 3 dont le glissement de
  session), état du visiteur (1 transaction : méthode, TOTP, préférences, organisations),
  garde d'organisation (1 fonction).

### Pour les lots suivants

- Nouvelle table d'organisation : `CALL ogsbom_enforce_org_rls(...)` **et** une entrée
  dans `orgTables` (`internal/db/orgtables_integration_test.go`), sinon les tests
  échouent. Nouvelle route de données d'organisation : sous `/o/{slug}` (le harnais de
  routes la teste seul) ; ailleurs, l'ajouter à `globalRoutes` en connaissance de cause.
- Handler d'organisation : `tenant.AccessFrom(ctx)` (organisation, slug, rôle) ;
  `id.requireOrgRole(tenant.RoleAnalyst)` pour le triage ; auteur pour l'audit :
  `id.actor(r)`, puis `audit.RecordOrg(ctx, tx, actor, …)` dans la même `InOrg`
  (nouvelle action : constante dans `audit`, phrase `audit.action.*` en fr et en).
- Messages de réussite : redirection `?done=<code>` (liste fermée `flashes`) ; erreurs de
  saisie : `account.ValidationError{Field, Key}`.
- T04 (jetons personnels) : la garde d'API utilisateur pourra réutiliser
  `crossorg.Access`. T25 : `session_auth.method = 'sso'` et `sso_org_id` existent déjà ;
  `loadViewer` est l'endroit où imposer le SSO d'une organisation.
- T11 : codes de secours de mfax (§ 23), et `docs/operations.md` § Comptes à compléter.
