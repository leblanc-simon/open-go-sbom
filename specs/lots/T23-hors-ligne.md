# T23 — Mode hors ligne

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Couvrir les réseaux isolés : les agents écrivent leurs SBOM dans des fichiers, transportés
à la main jusqu'au serveur, qui les importe comme des envois ordinaires.

## Périmètre

**Inclus**

- Agents : sortie « fichier » (SBOM + contexte dans une archive unique, nom horodaté) à la
  place ou en plus de l'envoi réseau.
- Serveur : import d'archives depuis l'écran du projet et par l'API, avec les mêmes contrôles
  que l'ingestion ; import en lot depuis un répertoire surveillé.
- Documentation complète d'un site isolé : agents, transport, import, base Grype hors ligne
  (déjà possible depuis T06).

**Exclu** : synchronisation automatique entre deux serveurs.

## Conception

- L'archive porte l'identité de l'agent émetteur ; à l'import, le serveur vérifie que cet
  agent appartient à l'organisation et qu'il est autorisé pour la référence. Avec T24,
  la signature est vérifiée.
- Une archive importée deux fois ne crée qu'un instantané.

## Critères d'acceptation

- [ ] Une archive produite par l'agent serveur et importée donne le même instantané qu'un
      envoi réseau.
- [ ] Une archive d'un agent d'une autre organisation est refusée.
- [ ] Le guide « site isolé » est déroulé de bout en bout sur une machine sans réseau.

## Tests attendus

Aller-retour agent → archive → import ; import en double ; isolement.

## Points à trancher

Aucun.

## Journal

_À remplir pendant la réalisation._
