# T13 — Conteneurs en projets enfants

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | À faire |

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

**Exclu** : analyse des images dans un registre (hors périmètre du cahier des charges).

## Conception

- L'identité d'un projet enfant (point ouvert) décide quand un conteneur recréé reste le
  même projet. Elle est encapsulée dans une seule fonction de l'agent, testée en table.
- L'agent envoie un SBOM par conteneur sur une référence propre ; le serveur crée le projet
  enfant s'il n'existe pas, sous l'hôte de l'agent uniquement.
- containerd seul (sans Docker ni Podman) : étudié en début de lot, réalisé seulement si le
  coût en dépendances est raisonnable.

## Livrables

Évolution de l'agent et du serveur, migrations, écrans, documentation.

## Maquettes

Planches « 4b · Fiche projet — serveur » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [ ] Trois conteneurs sur deux images : trois projets enfants, deux scans d'image.
- [ ] Un conteneur arrêté depuis plus de N jours voit son projet archivé ; il réapparaît
      s'il redémarre.
- [ ] La fiche hôte agrège les constats de ses enfants en comptant les couples distincts
      (projet, vulnérabilité) : une même CVE sur l'hôte et sur deux conteneurs compte trois
      fois, une même CVE sur deux composants d'un même conteneur compte une fois.
- [ ] Sans option explicite, l'agent n'ouvre aucune socket de moteur de conteneurs.
- [ ] Un agent ne peut créer d'enfant que sous son propre hôte.

## Tests attendus

API Docker simulée (`httptest` sur socket Unix) ; tests en table de l'identité ;
intégration serveur des cycles création et archivage.

## Points à trancher

- Identité d'un projet enfant : nom du conteneur, service Compose ou image ?
- Durée N avant archivage (7 jours proposé).
- containerd seul dans le périmètre ?

## Journal

_À remplir pendant la réalisation._
