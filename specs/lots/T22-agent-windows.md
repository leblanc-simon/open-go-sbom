# T22 — Agent serveur Windows

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Porter `lotor-host-agent` sur Windows Server avec les mêmes garanties que sous Linux.

## Périmètre

**Inclus**

- Étude préalable : ce que Syft inventorie sous Windows à la version épinglée (paquets de
  langages, binaires, programmes installés ?) ; si l'inventaire des programmes installés
  manque, lecture du registre de désinstallation par l'agent, encodée en composants
  `generic` signalés.
- Service Windows (démarrage, arrêt, journal des événements), planification interne.
- Répertoire d'état protégé par ACL (compte de service et administrateurs seulement).
- Installeur MSI ; documentation.

**Exclu** : postes de travail (le cahier des charges vise les serveurs).

## Critères d'acceptation

- [ ] L'étude préalable est validée par l'utilisateur avant toute réalisation, et fixe la
      liste des composants attendus sur un Windows Server de référence.
- [ ] Sur ce Windows Server de référence, le SBOM contient exactement cette liste.
- [ ] Le service survit au redémarrage et respecte les mêmes règles d'envoi que sous Linux.
- [ ] Le jeton d'agent n'est lisible que par le compte de service.

## Tests attendus

Tests unitaires portables en CI sur un exécuteur Windows ; recette manuelle consignée.

## Points à trancher

- Versions de Windows Server supportées.

## Journal

_À remplir pendant la réalisation._
