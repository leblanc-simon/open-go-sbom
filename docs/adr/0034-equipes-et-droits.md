# 0034 — Équipes et droits : rôle d'organisation membre ou administrateur, droits par équipe, filtre d'équipe déclaré à la transaction, invitations

- Statut : Accepté
- Date : 2026-11-01
- Lot : T16

## Contexte

Au lot 1, le rôle d'organisation (`viewer`, `analyst`, `admin`) donnait les droits sur
toute l'organisation, et chaque membre voyait tous ses projets. Le cahier des charges
(§ 9) veut des droits par équipe — lecteur, analyste, administrateur — et un
administrateur d'organisation qui voit tout. Les décisions du 1er novembre 2026
(fiche T16) fixent le modèle : rôle d'organisation réduit à « membre » ou
« administrateur », droits sur les projets venus du seul rôle d'équipe, équipe
« Général » pour l'existant, projet toujours rattaché à une équipe, et ajout d'un membre
par une invitation à accepter, la réponse étant la même que le compte existe ou non
(SEC-09). C'est un écart au § 10 de l'architecture, mise à jour dans le même commit.

Le filtre d'équipe touche toutes les surfaces de lecture (listes, fiches, recherche et
ses exports, tableau de bord et ses statistiques, pages des vulnérabilités et des
composants, API utilisateur, agents), sans jamais relâcher l'isolement entre
organisations, qui reste la RLS sur `lotor.org_id`.

## Décision

### Modèle

- `org_memberships.role` vaut `member` ou `admin`. Tables d'organisation nouvelles, sous
  la RLS standard : `teams` (nom unique sans casse dans l'organisation), `team_members`
  (rôle `reader`, `analyst`, `admin` ; clé étrangère composite vers `org_memberships`,
  donc un membre d'équipe est forcément membre de l'organisation et le retrait de
  l'organisation le retire de ses équipes), `org_invitations`.
- `projects.team_id` est obligatoire ; une équipe qui a des projets ne peut pas être
  supprimée (clé étrangère sans cascade). Rattacher un projet à une autre équipe exige le
  droit de rattachement dans les deux équipes ; un dépôt confié à un agent d'une autre
  équipe le perd, un serveur emmène son agent.
- `agents.team_id` est facultatif : sans équipe, c'est un **agent d'organisation**, géré
  par ses seuls administrateurs, qui peut servir les projets de toutes les équipes (un
  agent dépôt sert toute une organisation, § 2) ; un agent d'équipe ne sert que les
  projets de son équipe. Une équipe supprimée rend ses agents à l'organisation.
- `enrollment_tokens.team_id` est obligatoire : le projet créé à l'inscription et
  l'agent inscrit en héritent (rattaché à un projet existant, l'agent prend l'équipe du
  projet, qui doit être celle du jeton). Une équipe supprimée emporte ses jetons
  d'inscription.
- Migration 016 : une équipe « Général » (« General » pour une organisation en anglais)
  par organisation ; tous les projets et jetons d'inscription y sont rattachés, les agents
  serveur aussi ; les agents dépôt restent d'organisation ; chaque membre en devient
  membre avec son rôle (`viewer` → `reader`, `analyst` → `analyst`, `admin` → `admin`),
  puis `viewer` et `analyst` deviennent `member`. Une organisation créée ensuite reçoit
  aussi une équipe « Général », pour que ses premiers projets en aient une.

### Matrice des droits, source unique

`internal/tenant/permission.go` décrit la matrice : chaque permission, sa portée
(organisation ou équipe), le rôle minimal et sa description. `tenant.Allowed` l'applique,
`tenant.Access.Can(permission, équipe)` l'interroge pour une requête. Le document
`docs/security/permissions.md` en est la sortie exacte (`TestPermissionsDocument` échoue
s'il diffère ; `-update` le régénère). Dans l'interface, chaque route de `/o/{slug}` est
déclarée **une seule fois** avec sa permission et la ressource qui porte l'équipe
(`orgRoutes`, `internal/web/guard.go`) ; une garde unique résout l'équipe (projet, agent,
équipe, jeton d'inscription), répond **404** pour une ressource d'une équipe invisible,
comme pour une autre organisation, et **403** pour un droit manquant sur une ressource
visible. Le test `TestRoutePermissionsFollowMatrix` parcourt cette table et en dérive
ses attentes de la matrice, pour chaque rôle.

### Filtre d'équipe : déclaré à la transaction, fermé par défaut

- `tenant.Visibility` désigne les équipes visibles : toutes pour un administrateur
  d'organisation, celles dont le compte est membre sinon. Sa valeur zéro ne voit rien.
- Une lecture pour un compte ouvre `InOrg` avec l'option `db.Visible(vis)`, qui déclare
  `set_config('lotor.teams', …, true)` (« * » ou un tableau d'uuid), et filtre ses
  projets (et agents, équipes, jetons d'inscription) par la fonction SQL
  `lotor_team_visible(team_id)`, simple fonction `STABLE` que le planificateur
  incorpore à la requête. **Sans déclaration, la fonction échoue** (paramètre inconnu sur
  une connexion neuve, `''` illisible comme tableau sur une connexion réutilisée) : un
  appelant qui oublie la visibilité obtient une erreur, jamais tous les projets — même
  principe d'échec franc que la RLS (§ 9). Les traitements (ingestion, analyse,
  statistiques) n'appellent pas ces lectures, ou déclarent explicitement toutes les
  équipes (statistiques quotidiennes).
- Les stores reçoivent la visibilité en paramètre (`Projects.List/Get`, `Agents.List/Get`,
  `Search.Search/Export/Labels`, `Dashboard.Org`, `Findings.Vulnerability/Component`,
  `Inventory.Component`, `Orgs.Teams/Team`). Les lectures d'un projet déjà résolu
  (constats, instantanés, SBOM) restent indexées par l'identifiant du projet, que la garde
  a vérifié.
- Le tableau de bord d'un membre additionne les statistiques quotidiennes des projets
  visibles (`project_daily_stats`, gardées 400 jours), rattachés à leur équipe actuelle ;
  celui d'un administrateur lit celles de l'organisation. Un composant qui n'a jamais
  figuré dans un instantané d'un projet visible répond 404.

### Invitations (SEC-09)

- Un administrateur d'organisation **invite** une adresse ; la réponse et le journal sont
  les mêmes que l'adresse ait un compte ou non. L'invitation (30 jours, 200 en attente au
  plus par organisation, une par adresse, renouvelée par une nouvelle invitation) n'est
  pas liée à `users` : un compte créé plus tard peut l'accepter. Une adresse déjà membre
  n'est pas invitée (la liste des membres est déjà connue de l'administrateur).
- Le compte voit ses invitations sur `/account/invitations` et les accepte ou les
  décline ; il ne devient membre qu'en acceptant. L'ajout direct reste réservé à
  l'administration de l'instance, dont l'administrateur connaît déjà les comptes.
- **Nouvelle fonction `crossorg`** : `lotor_user_invitations(user_id)`, `SECURITY
  DEFINER`, qui renvoie les invitations non expirées adressées à l'e-mail du compte
  (actif), des organisations actives dont il n'est pas membre : identifiant, organisation
  (identifiant, slug, nom), rôle, dates, 50 au plus. Elle ne révèle rien d'autre que ce
  qu'une invitation adressée au compte doit lui montrer. L'acceptation se fait ensuite
  dans `InOrg`, sous la RLS, après une nouvelle vérification de l'e-mail et de l'échéance
  sous verrou.

## Conséquences

- Aucune donnée d'organisation ne sort de son organisation : la RLS, les clés composites
  et `InOrg` restent inchangés ; le filtre d'équipe s'y ajoute à l'intérieur.
- Une nouvelle surface de lecture doit déclarer la visibilité et filtrer par
  `lotor_team_visible`, sinon elle échoue dès son premier test ; le test des surfaces
  (`TestTeamFilterOnEverySurface`) vérifie chacune avec un membre de A, un membre de B, un
  membre sans équipe et un administrateur.
- Les rôles `viewer` et `analyst` disparaissent des URL, des formulaires et de l'API ;
  les jetons personnels voient à chaque requête ce que voit leur propriétaire.
- Le tri des constats (T14) utilisera `finding.triage`, déjà dans la matrice.

## Alternatives écartées

- **Politiques RLS restrictives par équipe** sur `projects` et sur chaque table qui en
  dépend : il aurait fallu une sous-requête vers `projects` dans la politique de chaque
  table (constats, instantanés, références…), qui sous la RLS empêche l'usage des index
  et pèse sur les recherches au million de liens ; la validation du démarrage refuse par
  ailleurs toute politique étrangère à `lotor.org_id`. Le filtre d'équipe n'est pas une
  frontière d'isolement entre clients, mais une règle de visibilité à l'intérieur d'une
  organisation.
- **Paramètre de requête explicite** (`team_id = ANY($n)`) dans chaque store : même
  effet, mais une requête qui oublie le paramètre renverrait tous les projets en
  silence ; le réglage de transaction et la fonction échouent au contraire.
- **Projet sans équipe** visible des seuls administrateurs : écarté par la décision du
  1er novembre 2026 (tout projet a une équipe).
- **Invitation avec équipe et rôle d'équipe** : l'invitation ne porte que le rôle
  d'organisation ; l'équipe se donne après l'acceptation (un administrateur d'équipe ne
  voit que les membres de l'organisation), ce qui garde l'invitation indépendante des
  équipes supprimées entre-temps.
