# 0041 — Inventaire des conteneurs par l'agent serveur : désactivé par défaut, API Docker sur socket Unix, scan de l'image exportée

- Statut : Accepté
- Date : 2026-11-01
- Lot : T13

## Contexte

L'agent serveur (T07, ADR 0020 et 0021) inventorie l'hôte en excluant les stockages de
conteneurs. T13 lui fait découvrir les conteneurs en cours d'exécution via les sockets
Docker et Podman (configurables), lire leur contexte (nom, image, empreinte d'image,
étiquettes Compose, date de démarrage), scanner l'image de chacun par empreinte avec un
cache (une image partagée n'est analysée qu'une fois) et envoyer un SBOM par conteneur.
Contraintes : l'accès à la socket d'un moteur équivaut à root ; l'agent tourne sous un
utilisateur dédié avec la seule capacité `CAP_DAC_READ_SEARCH` ; il ne dépend d'aucun
paquet serveur ; le § 5 de l'architecture prévoyait « le client de l'API Docker du
graphe de stereoscope s'il y est, sinon HTTP sur socket Unix », et les consignes du lot
préfèrent un client HTTP sans nouvelle dépendance. Le côté serveur fait l'objet de
l'ADR 0040.

## Décision

### Désactivé par défaut

- `containers.enabled` (faux par défaut) : sans lui, `hostagent.Engines` ne renvoie
  aucun moteur et **l'agent n'ouvre aucune socket** (vérifié par un test qui sert une
  fausse API Docker et compte ses connexions). L'option, son impact (équivalent root) et
  la préférence pour une socket **Podman sans root** sont documentés dans
  `docs/operations.md` ; l'unité systemd n'est pas modifiée : l'accès se donne par un
  complément (`SupplementaryGroups=docker`, ou ACL sur la socket Podman d'un compte).
- `containers.sockets` : vide, `/run/docker.sock` puis `/run/podman/podman.sock`, une
  socket absente étant ignorée en silence ; configurée, son absence est signalée. Le
  moteur est reconnu par `/version` (Podman s'y nomme). containerd seul n'est pas pris
  en charge (T22).

### Client HTTP sur socket Unix, sans bibliothèque cliente

- Quatre appels de l'API Docker, servie aussi par Podman (API compatible), sans préfixe
  de version : `/version`, `/containers/json` (conteneurs en cours seulement),
  `/containers/{id}/json` (date de démarrage), `/images/{id}/get` (export
  `docker save`). Transport `net/http` sur `unix`, jamais de mandataire ni de
  redirection, délai par appel (`containers.timeout`, 30 s), réponses bornées (16 Mio
  pour la liste, 1 Mio pour le reste), export borné à `containers.max_image_mib`
  (4 096 Mio).

### Identité et regroupement

- Une seule fonction, `hostagent.Identity`, testée en table : `projet/service` si les
  étiquettes `com.docker.compose.project` (ou `io.podman.compose.project`) et
  `com.docker.compose.service` sont présentes et lisibles, sinon le premier nom lisible du
  conteneur ; un conteneur sans nom lisible ou sans empreinte d'image `sha256:` est écarté
  et compté. Les conteneurs d'une même identité (répliques, ou même nom sur deux moteurs)
  forment un seul élément : image et démarrage du conteneur démarré le plus récemment,
  noms de tous (16 au plus), nombre de répliques.

### Scan de l'image exportée, une fois par image

- L'image est exportée au format docker-archive dans `containers.work_dir`
  (`<state_dir>/images`, 0700), scannée par Syft depuis ce fichier (source
  `docker-archive` seule : aucun accès au moteur ni au registre), puis l'archive est
  supprimée. Catalogueurs d'une image, sans catalogage de fichiers, et **hors ligne** :
  aucun outil exécuté ni accès réseau sur un contenu d'image tiers (mêmes réglages que
  l'agent dépôt, T08). Ces réglages hors ligne s'appliquent désormais aussi au scan de
  l'hôte, qui laissait Syft lancer `go list` sur les modules Go trouvés sous `/`.
- Une image partagée par plusieurs conteneurs n'est exportée et scannée qu'une fois par
  cycle. Entre deux cycles, l'agent garde dans `state.json` l'empreinte d'inventaire
  rangée ou confirmée de chaque image des conteneurs qui tournent (pour sa version
  seulement : une autre version de Syft peut inventorier autrement) ; il la joint au
  signalement, et le serveur répond `current` sans que l'image soit exportée ni scannée.
  Un SBOM n'est jamais gardé sur le disque.

### Déroulement d'un cycle et échecs

- Après l'hôte (envoi ou confirmation), si l'inventaire est activé : découverte,
  signalement, puis, pour chaque conteneur non confirmé ni ignoré, scan de son image et
  envoi de son SBOM (Syft JSON, gzip) sur la référence de son projet enfant. Un moteur
  injoignable, une image trop grosse, un scan ou un envoi en échec sont journalisés et
  comptés sans arrêter les autres conteneurs ni faire échouer le cycle : l'inventaire de
  l'hôte est rangé, et le cycle suivant reprend les conteneurs.

## Conséquences

- Activer l'option donne à l'agent l'équivalent de root sur l'hôte (Docker, Podman avec
  root) : le choix revient à l'exploitant, documenté ; une socket Podman sans root ne
  donne que les droits de son compte.
- L'export d'une image demande sur le disque la taille de l'image, plus l'extraction de
  ses couches par Syft (stereoscope) dans le répertoire temporaire du processus
  (`TMPDIR`, privé sous l'unité fournie) ; à dimensionner, documenté.
- Le premier cycle scanne toutes les images ; les suivants ne scannent que les images
  nouvelles ou réclamées par le serveur.

## Alternatives écartées

- **Client `github.com/moby/moby/client`**, présent dans le graphe (via stereoscope) :
  bibliothèque en v0 dont l'API change d'une version à l'autre, négociation de version
  et variables `DOCKER_*` de l'environnement, sans borne sur les réponses ; quatre appels
  HTTP en `net/http` suffisent et se testent par un `httptest` sur socket Unix. Écart au
  § 5, mis à jour.
- **Sources `docker` et `podman` de Syft (stereoscope)** : elles trouvent la socket par
  l'environnement et passent par ce même client, sans borne de taille configurable ; la
  source `docker-archive` ne lit qu'un fichier.
- **Scanner le système de fichiers du conteneur** (`/proc/<pid>/root` ou le répertoire
  `merged` d'overlay) : exige des capacités supplémentaires (`CAP_SYS_PTRACE`, lecture
  des stockages de moteur), mêle à l'image ce que le conteneur a écrit, et perd le
  partage par image ; la fiche demande le scan de l'image par empreinte.
- **Garder le SBOM de chaque image sur le disque** : plusieurs Mio par image pour éviter
  un rescan rare (serveur qui a perdu l'inventaire) ; l'empreinte suffit au cas courant.
- **containerd par sa propre API (gRPC)** : hors du lot 2 (décision du 1er novembre 2026),
  T22.
