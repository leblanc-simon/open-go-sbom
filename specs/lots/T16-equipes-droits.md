# T16 — Équipes et droits

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T11 | Terminé |

## Objectif

Rattacher chaque projet à une équipe et limiter la visibilité et les droits de chacun aux
projets de ses équipes, sans affaiblir l'isolement entre organisations.

C'est le **premier lot du lot 2** : il touche tous les stores et toutes les surfaces de
lecture. T12, T13, T14 et T17 en dépendent pour ne pas modifier les mêmes fichiers en
parallèle.

## Périmètre

**Inclus**

- Équipes dans une organisation, membres et rôle par équipe, projet rattaché à une équipe.
- Matrice des droits documentée (`docs/security/permissions.md`) : qui voit, trie, modifie
  quoi selon le rôle d'organisation et le rôle d'équipe.
- Application de la matrice dans les stores (filtre d'équipe) et les handlers, avec tests
  générés à partir de la matrice.
- Jetons d'inscription et agents rattachables à une équipe : les projets créés héritent de
  l'équipe.
- Écrans : équipes, membres, rattachement des projets.
- Audit : création, modification et suppression des équipes, changements de membres et de
  rattachement des projets.

**Exclu** : SSO et correspondance de groupes (T25).

## Conception

- Les administrateurs d'organisation voient tout. Les autres membres voient les projets de
  leurs équipes.
- La recherche, le tableau de bord, les exports et l'API respectent le filtre d'équipe : un
  même test vérifie chaque surface.
- Migration de l'existant : équipe « Général » par organisation (voir Décisions).

## Livrables

Migrations, stores, écrans, matrice des droits, tests dérivés de la matrice.

## Critères d'acceptation

- [x] Un membre sans équipe ne voit aucun projet rattaché à une équipe.
- [x] Recherche, tableau de bord, exports et API respectent la matrice.
- [x] La matrice documentée et les tests sont générés depuis la même source.
- [x] Chaque modification d'équipe produit un événement d'audit.

## Tests attendus

Tests en table dérivés de la matrice, sur chaque route et chaque surface d'agrégat.

## Décisions

Prises le 1er novembre 2026 :

- Migration de l'existant : une équipe « Général » est créée dans chaque organisation ;
  tous les projets existants y sont rattachés et tous les membres actuels en deviennent
  membres avec leur rôle d'organisation actuel. Tout projet a ensuite toujours une équipe
  (pas de projet sans équipe).
- Rôles : le rôle d'organisation se réduit à « membre » ou « administrateur »
  (l'administrateur voit et gère tout). Les droits sur les projets viennent uniquement du
  rôle dans l'équipe : lecteur, analyste (trie les constats) ou administrateur d'équipe.
  Les `viewer` et `analyst` actuels deviennent membres de l'organisation, avec le même
  rôle dans l'équipe « Général ».
- SEC-09 corrigé : l'ajout d'un membre à une organisation crée une invitation, que le
  compte doit accepter avant d'être membre ; la réponse est identique que le compte
  existe ou non.

## Journal

Réalisé le 1er novembre 2026, branche `lot/T16-equipes-droits`, en autonomie (lot 2
enchaîné sans attendre l'utilisateur) : les décisions marquées **[à relire]** n'ont pas
été validées explicitement.

### Livré

- Migration **016** (`016_teams.sql`) : tables `teams`, `team_members` (clé composite vers
  `org_memberships`), `org_invitations`, toutes sous la RLS standard et ajoutées au
  harnais SQL ; équipe « Général » (« General » en anglais) par organisation avec tous les
  projets, jetons d'inscription et agents serveur, chaque membre y entrant avec son ancien
  rôle ; `org_memberships.role` ramené à `member`/`admin` ; `projects.team_id`
  obligatoire, `agents.team_id` facultatif (`ON DELETE SET NULL (team_id)`),
  `enrollment_tokens.team_id` obligatoire ; fonction `lotor_team_visible` ; fonction
  `crossorg` `lotor_user_invitations`.
- `internal/tenant` : rôles d'organisation et d'équipe, `Access` (rôles d'équipe, `Can`,
  `CanAny`, `TeamsWith`, `Visibility`), `Visibility` (valeur zéro fermée), **matrice des
  droits** (`Matrix`, `Allowed`, `Subjects`) et `PermissionsDocument`, dont
  `docs/security/permissions.md` est la sortie exacte (`TestPermissionsDocument`).
- `internal/db` : option `db.Visible` (réglage `lotor.teams` de la transaction) ; options
  de transaction internes (`txConfig`).
- `internal/org` : `Access` (garde de l'interface et de l'API), équipes (création,
  renommage, suppression d'une équipe sans projet, membres et rôles), invitations
  (`Invite`, `Invitations`, `RevokeInvitation`, `PendingInvitations`,
  `AcceptInvitation`, `DeclineInvitation`), équipe par défaut à la création d'une
  organisation ; `crossorg.UserInvitations`.
- Stores filtrés par équipe : `project` (équipe du projet, `Get`/`List` visibles, filtre
  par équipe, `SetTeam`, agent d'équipe réservé à son équipe), `agent` (équipe des agents
  et des jetons d'inscription, héritage à l'inscription, `List`/`Get`/`Team`/
  `Enrollments` visibles, `RepoAgents` par équipe, `Silent` filtrable), `search`
  (recherche, export, étiquettes), `dashboard` (indicateurs, tendance additionnée par
  projet, agents muets), `finding` (fiches vulnérabilité et composant), `inventory`
  (fiche composant, 404 pour un composant jamais vu d'une équipe visible).
- `internal/web` : table unique des routes de l'organisation avec leur permission et la
  ressource qui porte l'équipe (`orgRoutes`, `guard.go`), garde unique (404 ressource
  invisible, 403 droit manquant) ; écrans **Équipes** et **Équipe** (membres, rôles,
  renommage, suppression avec confirmation), invitations sur la page des membres
  (révocation avec confirmation), **Mon compte → Invitations** (accepter, décliner avec
  confirmation), choix de l'équipe à la création d'un projet, d'un agent et d'un jeton
  d'inscription, rattachement d'un projet dans ses paramètres, colonnes et filtre
  d'équipe ; traductions FR et EN.
- `internal/api` : la garde de l'API utilisateur lit les rôles d'équipe ; recherche et
  export limités aux équipes du propriétaire du jeton.
- Audit : `team.created`, `team.renamed`, `team.deleted`, `team_member.added`,
  `team_member.role_changed`, `team_member.removed`, `project.team_changed`,
  `member.invited`, `invitation.revoked`, `invitation.accepted`, `invitation.declined`.
- Docs : ADR 0034 ; `architecture.md` (§ 3, 8, 9, 10, 13, 14, 19) ;
  `docs/security/permissions.md` (généré) ; modèle de menace (SEC-09 corrigé, quatre
  menaces nouvelles) ; revue de sécurité de T11 (SEC-09 corrigé) ; `docs/operations.md`
  (membres, équipes, invitations, effet de la migration) ; `docs/utilisation.md`
  (équipes, rôles, invitations) ; `api/openapi.yaml` (portée des résultats) ;
  `CHANGELOG.md` ; `doc.go` de `tenant`, `db`, `org`, `project`, `agent`, `dashboard`,
  `search`.

### Tests

- `internal/tenant` : ordre des rôles, règles de la matrice nommées, `Access.Can` et
  visibilité, valeurs zéro fermées, document généré à jour.
- `internal/db` : harnais RLS étendu aux trois tables ; `TestTeamVisibilityFailsClosed`
  (sans équipes déclarées, échec sur connexion neuve et réutilisée ; « * », liste, liste
  vide, valeur zéro).
- `internal/org` : cycle de vie des équipes et journal, contraintes (nom, membre de
  l'organisation, équipe avec projets), retrait de l'organisation qui retire des équipes ;
  invitations (réponse identique, renouvellement, autre compte, seconde acceptation,
  expiration, déclin, révocation, organisation archivée) ; **migration** des données
  existantes vers « Général » (base migrée jusqu'à la migration précédente, peuplée, puis
  migrée).
- `internal/project`, `internal/agent` : visibilité, rattachement (dépôt qui perd un agent
  d'une autre équipe, serveur qui emmène le sien), héritage de l'équipe du jeton
  d'inscription, agents d'organisation, suppression d'une équipe.
- `internal/dashboard` : indicateurs, tendance et agents muets d'une équipe ; membre sans
  équipe vide.
- `internal/web` : **`TestRoutePermissionsFollowMatrix`** (chaque route de la table ×
  chaque sujet de la matrice, attentes tirées de `tenant.Allowed`, chaîne réelle avec
  gestionnaires remplacés, table identique au routeur ; vérifié en cassant la garde :
  102 échecs) ; **`TestTeamFilterOnEverySurface`** (liste et fiches des projets,
  recherche, export CSV, tableau de bord, fiches vulnérabilité et composant, API et son
  export JSON, agents, équipes, pour un administrateur, deux membres d'équipes
  différentes et un membre sans équipe ; vérifié en retirant le filtre de la recherche) ;
  écrans des équipes et des invitations (deux langues, accessibilité, CSP, journal) ;
  rôles dans l'organisation réécrits pour les invitations (SEC-09 : même réponse pour un
  compte connu et inconnu) ; harnais d'isolement par route étendu aux nouvelles routes.

### Décisions

Décisions de la fiche appliquées telles quelles (équipe « Général », rôles, invitation).
Décisions prises pendant le lot, toutes **[à relire]** :

- **Filtre d'équipe déclaré à la transaction** (`db.Visible`, réglage `lotor.teams`,
  fonction `lotor_team_visible` qui échoue sans déclaration) plutôt que des politiques RLS
  par équipe ou un paramètre de requête ([ADR 0034](../../docs/adr/0034-equipes-et-droits.md)).
- **Matrice** : permissions et rôles minimaux de `docs/security/permissions.md` ; les
  membres voient la liste des membres de l'organisation ; un administrateur d'équipe gère
  les membres de son équipe, ses projets, ses agents et ses jetons d'inscription, mais ni
  les équipes, ni les membres de l'organisation ; rattacher un projet exige le droit dans
  les deux équipes ; `finding.triage` déclaré pour T14 (ADR 0034).
- **404 pour une ressource d'une équipe invisible**, 403 pour un droit manquant sur une
  ressource visible (ADR 0034).
- **Agents** : équipe facultative (agent d'organisation géré par ses seuls
  administrateurs, qui sert toutes les équipes) ; agents serveur existants dans
  « Général », agents dépôt existants d'organisation ; une équipe supprimée rend ses
  agents à l'organisation et emporte ses jetons d'inscription ; un dépôt rattaché à une
  autre équipe perd un agent d'équipe, un serveur emmène le sien (ADR 0034).
- **Nouvelle organisation** : reçoit aussi une équipe « Général » (ADR 0034).
- **Nom de l'équipe migrée** selon la langue de l'organisation : « Général » ou
  « General » (migration 016).
- **Invitations** : 30 jours, 200 en attente par organisation, une par adresse
  (renouvelée), sans équipe (l'équipe se donne après l'acceptation), adresse déjà membre
  non invitée, ajout direct conservé pour l'administration de l'instance ; nouvelle
  fonction `crossorg` `lotor_user_invitations` (ADR 0034).
- **Tableau de bord d'un membre** : tendance additionnée des statistiques par projet
  (rattachés à leur équipe actuelle) ; fiche composant en 404 si le composant n'a jamais
  figuré dans un instantané d'un projet visible ; l'agent serveur d'un projet visible est
  lu sans filtre d'équipe pour sa fiche (ADR 0034).
- **Point d'essai des gardes** : champ non exporté `routeStub` d'`IdentityOptions`, posé
  seulement par les tests du paquet, qui remplace les gestionnaires derrière leur garde
  pour éprouver la matrice sans effet de bord.

### Écarts

- Captures d'écran en thèmes clair et sombre non faites : les écrans nouveaux ne
  réutilisent que des composants existants (panneaux, tableaux, formulaires en ligne),
  sans CSS nouvelle ; leur accessibilité est vérifiée par `webtest` en deux langues.
  L'audit RGAA du lot 2 (T18) les couvrira.
- Le cahier des charges cite un filtre « équipe » dans la recherche : non livré dans ce
  lot (la recherche est filtrée par les équipes visibles, et la liste des projets a un
  filtre d'équipe) ; à reprendre avec les filtres de T14 ou T18.

### ADR créés

- [0034 — Équipes et droits](../../docs/adr/0034-equipes-et-droits.md).

### Nouvelle fonction `crossorg` (relue comme un changement de sécurité)

- `lotor_user_invitations(user_id)` : `SECURITY DEFINER`, `search_path` fixé ; renvoie les
  invitations non expirées adressées à l'e-mail du compte (actif), d'organisations
  actives dont il n'est pas membre, 50 au plus, avec le strict nécessaire (identifiant,
  organisation, rôle, dates). Elle ne prend aucun e-mail en paramètre : un compte ne peut
  lire que ses invitations. Testée (autre compte, expirée, archivée).
