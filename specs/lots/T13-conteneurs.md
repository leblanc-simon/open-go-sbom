# T13 — Conteneurs en projets enfants

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | Terminé |

## Objectif

Chaque conteneur qui tourne sur un serveur suivi devient un projet enfant du projet de
l'hôte, avec son propre SBOM, et disparaît proprement quand le conteneur n'existe plus.

## Périmètre

**Inclus**

- Agent serveur : découverte des conteneurs en cours d'exécution via les sockets Docker et
  Podman (configurables), contexte (nom, image, empreinte d'image, étiquettes Compose,
  date de démarrage), scan Syft de l'image par empreinte avec cache (une image partagée par
  plusieurs conteneurs n'est analysée qu'une fois), envoi par conteneur.
- Serveur : type de projet `container`, `parent_id` vers l'hôte, création automatique à la
  première apparition (le projet enfant hérite de l'équipe de l'hôte), archivage après
  N jours d'absence (job), vue d'ensemble des enfants sur la fiche hôte avec agrégats,
  filtre « inclure les conteneurs » dans les listes et la recherche.
- Droits : l'accès à la socket d'un moteur de conteneurs équivaut à root. L'inventaire des
  conteneurs est donc **désactivé par défaut** ; la documentation explique l'option, son
  impact, et privilégie une socket Podman sans root quand c'est possible.

**Exclu** : analyse des images dans un registre (hors périmètre du cahier des charges) ;
containerd seul, sans Docker ni Podman (renvoyé à T22).

## Conception

- L'identité d'un projet enfant (point ouvert) décide quand un conteneur recréé reste le
  même projet. Elle est encapsulée dans une seule fonction de l'agent, testée en table.
- L'agent envoie un SBOM par conteneur sur une référence propre ; le serveur crée le projet
  enfant s'il n'existe pas, sous l'hôte de l'agent uniquement.
- containerd seul (sans Docker ni Podman) : hors du lot 2 (voir Décisions), renvoyé à T22.

## Livrables

Évolution de l'agent et du serveur, migrations, écrans, documentation.

## Maquettes

Planches « 4b · Fiche projet — serveur » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Trois conteneurs de services distincts sur deux images : trois projets enfants, deux
      scans d'image ; deux répliques d'un même service Compose : un seul projet enfant.
      (`TestContainersCycle`, `TestWorkloads`, `TestContainersEndToEnd`)
- [x] Un conteneur arrêté depuis plus de N jours voit son projet archivé ; il réapparaît
      s'il redémarre. (`TestContainerArchiving`, `TestArchiverJobs`,
      `TestContainersEndToEnd`)
- [x] La fiche hôte agrège les constats de ses enfants en comptant les couples distincts
      (projet, vulnérabilité) : une même CVE sur l'hôte et sur deux conteneurs compte trois
      fois, une même CVE sur deux composants d'un même conteneur compte une fois.
      (`TestFamilyCountsProjectVulnerabilityPairs`)
- [x] Sans option explicite, l'agent n'ouvre aucune socket de moteur de conteneurs.
      (`TestNoSocketWithoutOption`, `TestEnginesDisabledByDefault`)
- [x] Un agent ne peut créer d'enfant que sous son propre hôte. (`TestReportContainers`,
      `TestContainerChildren` ; vérifiés en cassant le contrôle de `RefForAgent`)

## Tests attendus

API Docker simulée (`httptest` sur socket Unix) ; tests en table de l'identité ;
intégration serveur des cycles création et archivage.

## Décisions

Prises le 1er novembre 2026 :

- Identité d'un projet enfant : projet Compose et service quand les étiquettes Compose
  sont présentes (les répliques d'un même service forment un seul projet), sinon nom du
  conteneur.
- Durée N avant archivage : 7 jours par défaut, réglable.
- containerd seul (sans Docker ni Podman) : exclu du lot 2, renvoyé au lot 3 (T22).

## Journal

Réalisé le 1er novembre 2026, branche `lot/T13-conteneurs`, en autonomie (lot 2 enchaîné
sans attendre l'utilisateur), en parallèle de T12, T14 et T17 : les décisions marquées
**[à relire]** n'ont pas été validées explicitement.

### Livré

- **Migration 020** (`020_containers.sql`, 017 avant la fusion de T17, T14 et T12) : `projects.kind` admet `container` ;
  `parent_id`/`parent_kind`, `container_key`, `container` (contexte `jsonb`), `seen_at`,
  `archived_absent` avec une contrainte de forme ; **clé étrangère composite
  `(org_id, parent_id, parent_kind, team_id)` vers l'hôte, `ON UPDATE CASCADE`** (l'enfant
  garde l'équipe de l'hôte, ADR 0034) ; identité unique par hôte ; références de nature
  `container` (une par conteneur). Aucune nouvelle table ni fonction `crossorg`.
- **`internal/project`** : `KindContainer`, `RefContainer`, `Project.Parent` et
  `Project.Container` (agent d'un conteneur : celui de son hôte), `SightContainers`
  (création sous l'hôte de l'agent seul, contexte, signalement, retour d'un conteneur
  archivé pour absence, journal), `ArchiveAbsent` et `Archiver` (échéance horaire et job
  par organisation), `Children`, `Filter.Containers`, `RefForAgent` étendu aux conteneurs,
  `SetTeam` refusé pour un conteneur seul, réactivation à la main refusée pour un
  conteneur archivé pour absence.
- **`internal/agent`** : `ReportContainers` (agent serveur seulement, validation,
  signal de vie, comptes rendus d'inventaire par `inventory.Confirm`), clés
  `error.agent.no_host_project`, `validation.containers_not_host`.
- **`internal/inventory`, `internal/ingest`** : une référence de conteneur suit la règle
  d'un hôte (sans commit, inventaire identique : date de dernière analyse seule).
- **API** : `POST /api/v1/agent/containers` (`reportContainers`, corps borné à 1 Mio),
  `IngestionContext.ref.kind` `container`, `containers=1` et `SearchProject.parent` dans
  l'API utilisateur ; code régénéré ; `agentclient.ReportContainers`.
- **`internal/dashboard`** : `Family` (vulnérabilités distinctes par projet de la
  famille, total des couples projet × vulnérabilité, conteneurs archivés hors du total).
- **`internal/search`** : `Filters.Containers`, natures retenues toujours posées
  (conteneurs écartés par défaut), parent d'un conteneur dans les groupes.
- **Agent serveur** (`internal/hostagent`, `cmd/lotor-host-agent`) : configuration
  `containers.*` (désactivé par défaut), `SocketEngine` (API Docker sur socket Unix,
  détection Docker ou Podman, réponses bornées), `Identity` et `Workloads`,
  `SyftImageScanner` (source `docker-archive`, hors ligne), cycle des conteneurs
  (signalement, scan une fois par image, envoi, inventaires d'images gardés dans
  `state.json`), échecs comptés sans faire échouer le cycle ; catalogueurs hors ligne
  appliqués aussi au scan de l'hôte.
- **Serveur** : fragment de configuration `containers.archive_after` (168 h), jobs
  `project.archive_containers_all` et `project.archive_containers`.
- **Écrans** (fr, en) : fiche d'un hôte avec « Conteneurs et constats par périmètre »
  (image, état, vulnérabilités ouvertes par sévérité, KEV, risque, total) et nombre de
  conteneurs ; fiche d'un conteneur (fil d'Ariane par l'hôte, panneau « Conteneur »,
  archivage pour absence) ; paramètres d'un conteneur (équipe de l'hôte, archivage) ;
  filtre « Inclure les conteneurs » de la liste des projets et de la recherche ; type
  « Conteneur » (pictogramme rond) ; tableau de bord qui compte les conteneurs.
- **Docs** : ADR 0040 et 0041 ; `architecture.md` (§ 5, 6, 8, 13, 16, 17) ;
  `docs/operations.md` (« Conteneurs » : option, équivalence root, Podman sans root,
  complément d'unité, disque, archivage) ; `docs/utilisation.md` (« Conteneurs des
  serveurs ») ; modèle de menace (quatre menaces) ; `config.example.yaml` du serveur et de
  l'agent ; `CHANGELOG.md` ; `doc.go` de `project`, `dashboard`, `hostagent`, `search`.

### Tests

- Unitaires : `TestIdentity` (table de l'identité), `TestWorkloads` (répliques, deux
  images, deux moteurs, seize noms), `TestSocketEngine` (fausse API Docker et Podman en
  `httptest` sur socket Unix : conteneurs en cours, date de démarrage, empreinte sans
  préfixe, export borné, socket absente), `TestSyftImageScanner` (vraie image
  docker-archive construite en test, scannée par Syft, empreinte stable),
  `TestContainersCycle`, `TestContainersFailures`, `TestNoSocketWithoutOption` (aucune
  connexion sans l'option), validation des identités et contextes, filtres de liste et de
  recherche, configuration.
- Intégration : `project` (enfants, autre hôte, contrôle d'écriture, hôte archivé, listes,
  équipe en cascade et refus par la base, archivage et retour, archivage à la main, jobs),
  `agent` (signalement, journal, ingestion et confirmation d'un conteneur, envoi d'un
  autre agent refusé, refus de validation), `dashboard` (couples projet × vulnérabilité),
  `web` : **`TestContainersEndToEnd`** (vrai `lotor-host-agent` en HTTPS contre le
  serveur de test, moteur Docker simulé : trois projets enfants, deux scans d'image,
  confirmation sans scan, analyse, fiches en fr et en, accessibilité et CSP, listes,
  recherche, isolement, archivage après 7 jours et retour), `TestContainersAPI` (corps de
  plus de 64 Kio, 501 identités, jeton d'inscription refusé).
- Les tests « un agent ne crée d'enfant que sous son propre hôte » ont été vérifiés en
  cassant `RefForAgent` (contrôle de l'agent neutralisé) : `TestReportContainers` et
  `TestContainerChildren` échouent.

### Décisions

Décisions de la fiche appliquées telles quelles (identité Compose sinon nom, 7 jours
réglables, Docker et Podman seulement, inventaire désactivé par défaut). Décisions prises
pendant le lot, toutes **[à relire]** :

- **Client HTTP sur socket Unix** plutôt que le client moby du graphe de stereoscope que
  citait le § 5 (écart mis à jour) ; détection Docker ou Podman par `/version`
  ([ADR 0041](../../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- **Scan de l'image exportée** (`docker save`, source `docker-archive` de Syft) plutôt
  que des sources `docker`/`podman` de Syft ou du système de fichiers du conteneur ;
  image bornée à 4 096 Mio ; empreintes d'images gardées par l'agent et confirmées par le
  serveur, jamais de SBOM sur le disque (ADR 0041).
- **Catalogueurs hors ligne pour l'hôte aussi** (Syft n'exécute plus `go list` sous `/`),
  correction d'un risque laissé par T07 ; un hôte qui porte des modules Go renvoie une
  fois son SBOM (ADR 0041).
- **Équipe imposée par clé étrangère en cascade**, conteneur sans agent propre, nom
  `hôte/identité`, slug `hôte-identité`
  ([ADR 0040](../../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- **Signalement dédié** `POST /agent/containers` (liste complète, 500 identités, 1 Mio),
  qui vaut signal de vie et porte les comptes rendus d'inventaire ; l'hôte vient du
  jeton, jamais de la requête (ADR 0040).
- **Archivage à la main d'un conteneur** : il reste archivé et l'agent l'ignore ; un
  conteneur archivé pour absence revient de lui-même et ne se réactive pas à la main
  (ADR 0040).
- **Conteneurs écartés par défaut** des listes et de la recherche, ajoutés par
  `containers=1` qui s'additionne à `type` ; **comptés** dans le tableau de bord de
  l'organisation (ADR 0040).
- **Agrégat de la fiche hôte** : vulnérabilités distinctes par projet, à la plus haute
  sévérité de leurs constats, conteneurs archivés montrés hors du total ; état « absent »
  d'un conteneur non signalé depuis le dernier inventaire de l'hôte (à une heure près)
  (ADR 0040).
- Identité vue sur deux moteurs (même nom chez Docker et Podman) : un seul projet, le
  conteneur démarré le plus récemment donne l'image (ADR 0041).

### Écarts

- Captures d'écran en thèmes clair et sombre non faites : les écrans nouveaux
  réutilisent les composants existants (panneau, tableau de données, pastilles de
  sévérité, statuts) ; seule CSS nouvelle, le modificateur `ptype--container` (forme
  ronde, couleur héritée). Accessibilité et CSP vérifiées par `webtest` en deux langues ;
  l'audit RGAA du lot 2 (T18) les couvrira.
- Podman non essayé (absent de l'environnement de réalisation) : son API compatible est
  simulée par les tests (`httptest` sur socket Unix, détection par `/version`). Docker 29
  (magasin d'images containerd) a été essayé pour de vrai (voir Mesures). Un essai de
  Podman sans root et de docker compose sur un hôte réel reste à faire en recette (T18).
- Purge des projets de conteneurs archivés depuis longtemps : non traitée (à décider avec
  la rétention, T18) ; la fiche d'un hôte en montre 500 au plus, actifs d'abord.

### Mesures

Docker Engine 29.9.2 (API 1.56, magasin d'images containerd), quatre conteneurs : deux
répliques d'un service Compose `shop/web` et un service `shop/api` sur
`alpine:3.18.0`, un conteneur `cache` sur `busybox:1.36.1` ;
`LOTOR_TEST_ENGINE_SOCKET=/var/run/docker.sock go test -tags measure -run TestRealEngine ./internal/hostagent/` :

| Identités | Images scannées | alpine:3.18.0 (archive 3,4 Mo) | busybox:1.36.1 (archive 2,2 Mo) |
| --- | --- | --- | --- |
| 3 (`cache`, `shop/api`, `shop/web` à deux répliques) | 2 | export 0,35 s, scan 1,8 s, 15 composants | export 0,26 s, scan 2,5 s, 1 composant |

L'export `docker save` d'un identifiant d'image par l'API fonctionne avec le magasin
containerd de Docker 29, et la source `docker-archive` de Syft le lit.

### ADR créés

- [0040 — Conteneurs en projets enfants](../../docs/adr/0040-conteneurs-en-projets-enfants.md).
- [0041 — Inventaire des conteneurs par l'agent serveur](../../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md).

### Pour les lots suivants

- **T14 (triage)** : un conteneur est un projet comme un autre (constats par référence
  `container`) ; une décision de triage par image partagée entre conteneurs n'existe pas
  encore.
- **T15 (politiques)** : les conteneurs ont `Project.Parent` ; une politique « par hôte »
  peut agréger avec `dashboard.Family`.
- **T17 (différences)** : les instantanés d'un conteneur suivent la règle d'un hôte (pas
  de commit).
- **T18 (recette)** : essai sur un hôte réel avec Docker et Compose, puis Podman sans
  root ; purge des conteneurs archivés ; captures.
- **T22 (containerd)** : un `ContainerEngine` de plus (`hostagent.Engines`), et
  `project.EngineContainerd` côté serveur (validation du moteur).
