# T04 — Projets, agents et jetons

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T03 | Terminé |

## Objectif

Déclarer les projets (dépôts et serveurs) et les agents qui les alimentent, délivrer et
révoquer leurs jetons, et ouvrir les premières routes de l'API agent : inscription, signal
de vie, liste des projets confiés.

## Périmètre

**Inclus**

- Projets : création, modification, archivage ; type `repo` ou `host` ; nom, description,
  étiquettes `clé=valeur` ; pour un dépôt, URL de forge et références suivies ; pour un
  serveur, la référence unique de l'hôte.
- Agents : type `host` ou `repo`, nom, version et date du dernier contact, projets confiés.
- Jetons d'inscription : durée de validité, nombre d'usages, étiquettes appliquées aux
  projets créés à l'inscription.
- Jetons d'agent (format du § 10), affichés une seule fois, révocables.
- API agent : `POST /api/v1/agent/enroll`, `POST /api/v1/agent/heartbeat`,
  `GET /api/v1/agent/projects` (projets et références confiés ; T05 y ajoute le commit du
  dernier instantané).
- Limitation de débit **par jeton** sur `/api/v1/agent/*` (`internal/ratelimit`, ou
  `ratelimit` d'open-go-base si l'évolution du § 23 de l'architecture est disponible).
- Écrans : liste et fiche de projet (onglets prévus pour les instantanés et les constats),
  liste et fiche d'agent, création de jeton d'inscription.
- Audit : création, modification, archivage, jetons créés et révoqués.

**Exclu** : réception des SBOM (T05), conteneurs en projets enfants (T13), équipes (T16).

## Conception

- À l'inscription d'un agent `host`, le serveur crée le projet de l'hôte (nom d'hôte,
  étiquettes du jeton) et le lui confie, si le jeton l'autorise ; sinon il le rattache à un
  projet existant désigné par le jeton.
- Un agent `repo` reçoit un jeton créé dans l'interface ; les dépôts lui sont confiés depuis
  la fiche du projet.
- La réponse du signal de vie peut porter `scan_requested` (utilisé en T07).
- Les jetons d'agent n'ouvrent que les routes `/api/v1/agent/*` et seulement pour les
  projets confiés à l'agent.
- Slug de projet unique dans l'organisation, utilisé dans les URL.

## Livrables

Migrations, stores, écrans, routes d'API et leur description OpenAPI, tests d'isolement.

## Maquettes

Planches « 3 · Projets », « 8 · Agents et jetons » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Un jeton d'inscription expiré ou épuisé est refusé avec une erreur traduisible.
- [x] Un jeton d'agent révoqué est refusé à la requête suivante.
- [x] Un agent ne voit et ne peut écrire que les projets qui lui sont confiés.
- [x] Le secret d'un jeton n'apparaît qu'une fois à l'écran et jamais dans les journaux.
- [x] Un agent qui dépasse sa limite reçoit 429 sans gêner un autre agent de même IP.
- [x] Les routes et écrans passent le harnais d'isolement et l'assistant d'accessibilité.

## Tests attendus

Unitaires : format, hachage et comparaison des jetons. Intégration : inscription, signal de
vie, révocation, création automatique du projet d'hôte, droits par rôle.

## Décisions

Prises le 31 octobre 2026 :

- Un agent serveur couvre un seul hôte.
- Limitation par jeton : évolution de `ratelimit` réalisée dans open-go-base, selon le même
  processus qu'en T03.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T04-projets-agents`.

### Livré

- **open-go-base** (évolution du § 23) : `ratelimit.WithKeyFunc(func(*http.Request)
  string)`, clé de limitation configurable (clé vide → IP ; clés et IP dans des espaces de
  compteurs distincts), tests et exemple, README et CLAUDE.md. PR #2 d'open-go-base,
  fusionnée (squash, commit `3534c14`) ; pas de CI sur ce dépôt : `gofmt`, `go vet ./...`
  et `go test -race ./...` verts en local. Étiquette annotée `v1.2.0` créée dans le clone,
  **pas poussée** (mandataire git, voir `specs/avancement.md`, « Actions pour
  l'utilisateur ») : open-go-sbom utilise la pseudo-version
  `v1.0.2-0.20261031043924-3534c1429b63`.
- Migrations **006** (`agents`, `projects`, `tracked_refs`, `agent_tokens`,
  `enrollment_tokens`, RLS standard, clés étrangères composites portant la nature) et
  **007** (`ogsbom_agent_token_org`, `ogsbom_enrollment_token_org`).
- `internal/db/crossorg` : `AgentTokenOrg`, `EnrollmentTokenOrg` (justifiées ci-dessous,
  ADR 0014, tableau de l'ADR 0012 complété).
- `internal/project` : projets (création, modification, archivage, liste filtrée par nom,
  type et étiquette, paginée), étiquettes `clé=valeur`, références suivies (branches,
  étiquettes git, hôte) retirées sans perte d'historique, slug dérivé et unique,
  affectation d'un agent dépôt ; `CreateHost`, `ListForAgent`, `RefForAgent` pour l'API.
- `internal/agent` : jetons (`NewToken`, `ParseToken`, `SecretHash.Matches`,
  `DisplayPrefix`), agents dépôt, jetons d'agent (création, rotation, révocation,
  expiration), désactivation, jetons d'inscription (durée, usages, étiquettes, projet
  désigné), `Authenticate`, `Enroll`, `Heartbeat`, `AssignedProjects`, état d'un agent
  (`pending`, `active`, `silent` après 3 jours sans contact, `disabled`).
- `internal/audit` : actions `project.*`, `agent.*`, `agent_token.*`, `enrollment_token.*`.
- API : `api/openapi.yaml` (`enroll`, `heartbeat`, `listAgentProjects`, schéma de sécurité
  `enrollmentToken`), premier code généré : serveur strict et adaptateur chi
  (`internal/api/gen/agent.gen.go`), client des agents (`internal/agentclient/gen`) ;
  `github.com/oapi-codegen/runtime` v1.8.0 ajouté (validé, ADR 0006).
- `internal/api` : `MountAgent` (corps JSON borné à 64 Kio, authentification, limitation
  par jeton, nature de jeton exigée par opération, erreurs RFC 9457 traduites) ;
  `problem.WriteValidation`, clés `error.invalid_request`, `error.validation`,
  `error.unauthorized`.
- Configuration : fragment `AgentAPI` (`agent_api.rate_limit` 120/min/jeton,
  `agent_api.failure_rate_limit` 30/min/IP), validé et documenté.
- Écrans (fr, en, clair, sombre), planches « 3 · Projets » et « 8 · Agents et jetons » :
  liste des projets (filtres nom, type, étiquette, archivés), création, fiche (onglets
  extensibles par `projectTabs`, présentation, références, agent), paramètres et
  archivage ; liste des agents (filtres type, désactivés) et des jetons d'inscription,
  fiche d'agent (projets, jetons, création, révocation, désactivation), nouvel agent
  dépôt, nouveau jeton d'inscription, page « jeton affiché une seule fois ». Composants
  portés : `breadcrumb`, `tabs`, `ptype`, `silent-flag`, `version`, `token-once`.
- Tests : unitaires (format, hachage, comparaison et forme canonique des jetons ;
  étiquettes, slugs, références, hôtes, URL de forge) ; intégration (inscription, refus
  expiré, épuisé, révoqué, organisation archivée, rattachement, réinscription après
  désactivation, rotation et révocation, expiration, isolement agent par agent et
  organisation par organisation, contraintes de schéma, API de bout en bout, 429 par
  jeton, écrans et droits par rôle, absence des jetons dans les journaux) ; harnais SQL et
  par route étendus, nouveau test de ressources d'une autre organisation.
- ADR 0014 ; `architecture.md` (§ 3, 5, 6, 9, 10, 23), `docs/operations.md` (« Agents et
  jetons »), modèle de menace, `config.example.yaml`.

### Décisions

- **ADR 0014** **[à relire]** : format `ogsbom_<nature>_<id public base32>_<secret
  base32>` ; organisation du jeton résolue par deux fonctions `crossorg` qui ne renvoient
  que l'identifiant d'une organisation active ; refus uniforme `error.token.invalid`
  avant vérification du secret, cause précise ensuite ; dernier usage écrit une fois par
  minute au plus ; `projects.agent_id` (un agent par projet, même nature, un seul hôte par
  agent serveur) plutôt qu'une table d'affectation.
- **Nouvelles fonctions `crossorg`** (changement de sécurité, à relire) :
  `ogsbom_agent_token_org(public_id)` et `ogsbom_enrollment_token_org(public_id)`. Seul
  moyen de connaître l'organisation d'un jeton avant `InOrg` ; elles ne renvoient que
  l'identifiant, et rien pour une organisation archivée ; l'identifiant public (128 bits
  aléatoires) ne se devine pas. Alternatives écartées dans l'ADR 0014.
- **Limitation** : évolution d'open-go-base (décision de la fiche) plutôt qu'un limiteur
  local ; `internal/ratelimit` supprimé (§ 3 et `archtest` à jour). Jetons refusés comptés
  par IP sur le seul chemin du refus **[à relire]**.
- **Inscription** **[à relire]** : un hôte déjà suivi par un agent actif est refusé (409
  `error.enrollment.host_taken`) ; un projet qui suit ce nom d'hôte sans agent actif est
  rattaché ; le jeton d'agent issu d'une inscription n'expire pas (l'agent serveur n'a pas
  de rotation automatique avant T07) et porte le nom du jeton d'inscription. Le nom
  d'hôte (100 caractères au plus, minuscules) sert de nom à l'agent, au projet et de
  référence d'hôte.
- **Droits** : écriture (projets, agents, jetons) réservée aux administrateurs de
  l'organisation ; lecteurs et analystes consultent ; la liste des jetons d'inscription
  n'est montrée qu'aux administrateurs **[à relire]**.
- **Références retirées** conservées (`removed_at`), réactivées si on les réajoute ; la
  référence d'un hôte est renommée sur place.
- **Slug d'un projet** immuable après création ; « new » réservé (segment d'URL).
- **Muet** : après 3 jours sans **contact** (pas encore d'instantané avant T05) **[à
  relire]**.
- Valeurs par défaut **[à relire]** : jeton d'agent 90 jours (30, 90, 180, 365 jours ou
  sans expiration) ; jeton d'inscription 24 heures (1 h, 24 h, 7 j, 30 j), 1 usage
  (10 000 au plus) ; 120 requêtes par minute et par jeton, 30 refus par minute et par IP.
- Le secret s'affiche dans la réponse au `POST` (pas de redirection), comme le mot de
  passe temporaire de T03 ; la page n'est pas mise en cache (`no-store`).
- Jetons personnels (`ogsbom_pat_`) : hors périmètre de la fiche (API utilisateur),
  préfixe réservé.

### Écarts

- La fiche propose `internal/ratelimit` *ou* open-go-base : open-go-base retenu (décision
  de la fiche), paquet local supprimé.
- Écran de la liste des projets : colonnes « dernier instantané », constats, risque et
  équipe de la planche absentes (T05, T06, T16) ; colonne « dernier contact de l'agent »
  à la place.
- Agent dépôt : pas d'étiquettes ni d'assistant d'installation sur la fiche (la commande
  de l'agent n'existe pas avant T07 et T08).

### ADR créés

0014 (et tableau de l'ADR 0012 complété).

### Mesures

- Couverture (unitaires et intégration) : `agent` 85,3 %, `project` 88,4 %,
  `db/crossorg` 81,4 %, `db` 84,8 %, `web` 80,4 %, `api/problem` 86,2 %.
- Requête authentifiée d'un agent : une fonction `crossorg`, puis une transaction `InOrg`
  (lecture du jeton et de l'agent, écriture du dernier usage au plus une fois par minute).

### Pour les lots suivants

- T05 : contrôle d'écriture d'un envoi par `project.RefForAgent(ctx, tx, agentID,
  projectID, kind, name)` dans la transaction `InOrg` de l'ingestion ; route
  `POST /api/v1/agent/ingestions` à ajouter au tag `agent` d'`api/openapi.yaml` (la
  nature de jeton se déclare dans `operationKinds` de `internal/api/agent.go`) ; le corps
  multipart n'est pas borné par `limitJSON` (JSON seulement) : poser ses propres bornes.
  Les clés étrangères de `snapshots` vers `tracked_refs` : une référence n'est jamais
  supprimée (`removed_at`). Ajouter le commit du dernier instantané à `AgentProject`.
  L'état « muet » pourra se fonder sur le dernier instantané (`agent.StateOf`).
- T07 : `scan_requested` vaut toujours `false` (colonne à ajouter) ; le client généré
  est dans `internal/agentclient/gen` ; jeton d'inscription en `Authorization: Bearer`.
- T08 : un agent dépôt reçoit un jeton créé dans l'interface ; ses dépôts viennent de
  `GET /api/v1/agent/projects` (pagination par curseur, 200 au plus).
- T13 : `projects.kind` à étendre à `container` (contrainte `CHECK`), clé étrangère de
  nature à revoir pour les conteneurs (sans agent propre).
- T16 : filtre d'équipe sur `project.List`.
