# 0040 — Conteneurs en projets enfants : modèle, signalement par l'agent, archivage, agrégats par périmètre

- Statut : Accepté
- Date : 2026-11-01
- Lot : T13

## Contexte

Le cahier des charges (§ 3, § 6) fait de chaque conteneur qui tourne sur un serveur suivi
un projet enfant du projet de l'hôte, avec son propre SBOM, archivé quand il a disparu
depuis N jours. Les décisions du 1er novembre 2026 (fiche T13) fixent l'identité d'un
projet enfant (projet Compose et service quand les étiquettes Compose sont présentes,
les répliques d'un même service formant un seul projet, sinon le nom du conteneur), la
durée N (7 jours, réglable) et le périmètre (Docker et Podman ; containerd seul en T22).
Le lot doit aussi garantir qu'un agent ne crée d'enfant que sous son propre hôte, que
l'enfant hérite de l'équipe de l'hôte (T16, ADR 0034), et que la fiche de l'hôte agrège
les constats de ses enfants en comptant les couples distincts (projet, vulnérabilité).
L'inventaire côté agent fait l'objet de l'ADR 0041.

## Décision

### Modèle (migration 017)

- `projects.kind` admet `container`. Un conteneur porte `parent_id` (l'hôte, de nature
  `host`), `container_key` (son identité dans l'hôte), `container` (contexte en `jsonb` :
  moteur, noms des répliques, nombre de répliques, image et son empreinte, projet et
  service Compose, démarrage ; 8 Kio au plus), `seen_at` (dernier signalement) et
  `archived_absent` (archivé pour absence). Une contrainte de forme lie ces colonnes à la
  nature, et un conteneur n'a jamais d'agent propre : il est inventorié par l'agent de son
  hôte (`coalesce(p.agent_id, hôte.agent_id)` partout où l'agent compte).
- **L'équipe de l'hôte est imposée par le schéma** : la clé étrangère composite
  `(org_id, parent_id, parent_kind, team_id)` vise `(org_id, id, kind, team_id)` de
  l'hôte, `ON UPDATE CASCADE ON DELETE CASCADE`. Rattacher l'hôte à une autre équipe y
  emmène ses conteneurs sans code ; rattacher un conteneur seul est refusé
  (`validation.container_team`), et la base refuse de toute façon un enfant dans une autre
  équipe que son hôte. Les actions référentielles s'exécutent comme propriétaire de la
  table, sans la RLS (comme les cascades existantes).
- Une identité désigne un seul enfant par hôte (index unique partiel), archivé ou non :
  un conteneur qui réapparaît retrouve son projet et son historique. L'identité est aussi
  le nom de l'unique référence suivie de l'enfant, de nature `container`
  (`tracked_refs`), qui suit la règle d'instantané d'un hôte : pas de commit, un
  inventaire identique ne fait qu'avancer la date de dernière analyse (§ 11).
- Nom affiché `hôte/identité`, slug dérivé de `slug-de-l-hôte-identité`, rendu unique.

### Signalement par l'agent : `POST /api/v1/agent/containers`

- L'agent serveur envoie à chaque cycle la liste des conteneurs en cours d'exécution, un
  élément par identité (500 au plus, corps borné à 1 Mio au lieu de 64 Kio). Il ne désigne
  jamais l'hôte : le serveur prend **le projet d'hôte actif confié à cet agent**, le
  verrouille, puis crée ou met à jour chaque enfant sous lui seul. Un agent sans hôte
  actif reçoit 409 `error.agent.no_host_project`. Les envois de SBOM d'un conteneur
  passent par `createIngestion` sur la référence de l'enfant, dont `project.RefForAgent`
  vérifie qu'il est actif, que son hôte l'est aussi et que l'agent est celui de l'hôte.
- Comptes rendus d'inventaire : quand l'agent connaît déjà l'inventaire de l'image d'un
  conteneur, il joint son empreinte ; le serveur la compare à l'ensemble courant de
  l'enfant (`inventory.Confirm`, comme le signal de vie d'un hôte, ADR 0020) et répond
  `current` (seule la date de dernière analyse avance) ou `outdated` (l'agent envoie le
  SBOM). Le signalement vaut signal de vie.
- Création journalisée (`project.created`, nature `container`, hôte, acteur : préfixe
  du jeton d'agent) ; retour d'un conteneur archivé pour absence journalisé
  (`project.unarchived`, motif `reappeared`).

### Archivage et retour

- Échéance horaire `project.archive_containers_all`, qui met en file
  `project.archive_containers` par organisation active (liste par `crossorg`, § 16) :
  tout enfant actif dont `seen_at` a plus de `containers.archive_after` (7 jours par
  défaut, une heure au moins) est archivé avec `archived_absent`, journalisé par
  l'acteur système (motif `absent`). Idempotent.
- Un conteneur archivé pour absence **revient de lui-même** au signalement suivant (et
  ne se réactive pas à la main, `validation.container_absent`). Un conteneur **archivé
  par un utilisateur** reste archivé même s'il tourne : le serveur le dit « ignoré » et
  l'agent ne l'inventorie plus ; le réactiver à la main le rend à l'agent (et l'absence
  se compte de nouveau depuis son dernier signalement).

### Lectures

- Listes des projets et recherche (écran et API) : les conteneurs sont **écartés par
  défaut** et ajoutés par le filtre « inclure les conteneurs » (`containers=1`), qui
  s'additionne aux types retenus (`type=host&containers=1` : serveurs et conteneurs). Le
  type `container` n'est pas une valeur de `type`, réservé aux natures de premier niveau.
- Fiche d'un hôte : tableau « Conteneurs et constats par périmètre » (hôte, chaque
  conteneur, total). Chaque projet compte ses **vulnérabilités ouvertes distinctes**, à la
  plus haute sévérité de leurs constats ; le total additionne ces couples (projet,
  vulnérabilité) pour l'hôte et ses conteneurs actifs (`dashboard.Family`). Un conteneur
  archivé garde sa ligne, hors du total.
- Tableau de bord de l'organisation : les conteneurs actifs comptent comme des projets
  (décompte « N conteneurs », projets exposés, statistiques quotidiennes) : ce sont des
  logiciels en service, exposés comme l'hôte.
- État d'un conteneur sur les fiches : « en cours » s'il a été signalé depuis le dernier
  inventaire de l'hôte (à une heure près), « absent » sinon, « archivé » ensuite.

## Conséquences

- Une nouvelle surface de lecture des projets doit décider si elle montre les
  conteneurs ; la liste et la recherche les écartent par défaut.
- Le nombre d'enfants archivés d'un hôte croît avec les conteneurs éphémères (noms
  aléatoires hors Compose) ; la fiche de l'hôte en montre 500 au plus, actifs d'abord.
  Une purge des enfants archivés depuis longtemps reste à décider (rétention, T18).
- Les identités Compose rendent stable le projet d'un service recréé à chaque
  déploiement ; un conteneur lancé sans Compose et sans nom fixe crée un projet par nom
  généré (choix de la décision : le nom du conteneur).
- Le tableau de bord additionne hôtes et conteneurs : une CVE d'une image partagée par
  dix conteneurs y compte dix fois, comme dix serveurs.

## Alternatives écartées

- **Identité calculée par le serveur** à partir des étiquettes brutes : la fiche veut la
  règle dans une seule fonction de l'agent ; le serveur ne reçoit que l'identité, qu'il
  valide (forme `projet/service` ou nom).
- **Agent désignant l'hôte** dans le signalement : inutile (un agent serveur a un seul
  hôte) et dangereux (un agent pourrait viser un autre hôte) ; l'hôte vient du jeton.
- **Équipe de l'enfant tenue par le code** (copie à la création, mise à jour dans
  `SetTeam`) : une écriture oubliée laisserait un conteneur visible d'une autre équipe ;
  la clé étrangère en cascade le rend impossible.
- **Agent propre au conteneur** (`agent_id` renseigné) : la clé étrangère
  `(agent_id, kind)` des projets exige la même nature que l'agent ; une colonne
  supplémentaire aurait dupliqué ce que donne l'hôte.
- **Table séparée des conteneurs** : une jointure de plus sur toutes les lectures de
  projets pour quelques colonnes ; `parent_id` sur `projects` était déjà prévu (§ 8).
- **Archivage par absence du dernier signalement** (immédiat) : un redémarrage ou une
  mise à jour ferait clignoter les projets ; la décision fixe 7 jours.
- **Constats comptés par composant** sur la fiche de l'hôte : une même CVE sur deux
  composants d'un conteneur compterait deux fois, contrairement au critère de la fiche.
