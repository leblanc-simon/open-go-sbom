# T19 — Compatibilité Dependency-Track

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Option C du cahier des charges : les agents savent aussi envoyer leurs SBOM à un
Dependency-Track, et le serveur accepte les envois des outils configurés pour
Dependency-Track.

## Périmètre

**Inclus**

- Agents : sortie supplémentaire « Dependency-Track » (URL, clé d'API, correspondance
  projet et version, création automatique), en plus ou à la place de lotor.
- Serveur : point d'envoi compatible avec celui de Dependency-Track (corps JSON avec SBOM en
  base64 et formulaire multipart, clé `X-Api-Key`), qui crée une ingestion ordinaire, et
  route de suivi du traitement au format attendu par les clients. Ces routes vivent sous le
  préfixe `/dt/` : un client Dependency-Track se configure avec l'URL de base
  `https://<serveur>/dt`, et l'espace `/api/v1` du projet reste à lui.
- Correspondance : clé d'API → jeton d'agent ; nom de projet → projet de l'organisation ;
  version de projet → référence suivie ; création automatique si le jeton l'autorise.
- Documentation : migration depuis Dependency-Track et usage conjoint.

**Exclu** : reproduction du reste de l'API de Dependency-Track.

## Conception

- Étude préalable : routes et formats exacts de Dependency-Track 5.x, différences avec la
  4.x ; résultat consigné.
- Le point compatible ne contourne aucun contrôle : mêmes bornes, même file, mêmes droits
  que l'ingestion native. Quand T24 imposera la signature, un envoi non signé par ce point
  sera refusé comme tout autre.

## Critères d'acceptation

- [ ] Un SBOM envoyé par un agent arrive dans un Dependency-Track 5 de test.
- [ ] Une requête enregistrée d'un client Dependency-Track réel est acceptée par le serveur
      et produit un instantané.
- [ ] Une clé d'API inconnue ou révoquée est refusée.

## Tests attendus

Tests de contrat sur des requêtes et réponses enregistrées ; intégration avec un
Dependency-Track en conteneur, hors CI par défaut.

## Points à trancher

Aucun.

## Journal

_À remplir pendant la réalisation._
