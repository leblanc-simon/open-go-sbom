# T04 — Projets, agents et jetons

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T03 | À faire |

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

- [ ] Un jeton d'inscription expiré ou épuisé est refusé avec une erreur traduisible.
- [ ] Un jeton d'agent révoqué est refusé à la requête suivante.
- [ ] Un agent ne voit et ne peut écrire que les projets qui lui sont confiés.
- [ ] Le secret d'un jeton n'apparaît qu'une fois à l'écran et jamais dans les journaux.
- [ ] Un agent qui dépasse sa limite reçoit 429 sans gêner un autre agent de même IP.
- [ ] Les routes et écrans passent le harnais d'isolement et l'assistant d'accessibilité.

## Tests attendus

Unitaires : format, hachage et comparaison des jetons. Intégration : inscription, signal de
vie, révocation, création automatique du projet d'hôte, droits par rôle.

## Décisions

Prises le 31 octobre 2026 :

- Un agent serveur couvre un seul hôte.
- Limitation par jeton : évolution de `ratelimit` réalisée dans open-go-base, selon le même
  processus qu'en T03.

## Journal

_À remplir pendant la réalisation._
