# T20 — Licences avec Grant

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Connaître les licences de chaque composant, les confronter à une politique d'organisation
et les rendre cherchables.

## Périmètre

**Inclus**

- `internal/license/grant` : adaptateur Grant (classification et évaluation des licences),
  seul paquet qui l'importe.
- Politique de licences par organisation : licences autorisées, interdites, à revoir ;
  expressions SPDX (`MIT OR Apache-2.0`) évaluées correctement.
- Constats de licence par référence, avec le même cycle de vie que les constats de
  vulnérabilité.
- Activation du modèle de règle « licence AGPL dans un produit distribué » (T15).
- Écrans : licences d'un projet, politique, constats ; filtre et recherche par licence
  enrichis.

**Exclu** : détection de licence dans le code source (au-delà de ce que fournissent Syft et
Grant).

## Conception

- Étude préalable : API de Grant utilisable en bibliothèque à la version épinglée ; à défaut,
  évaluation des expressions SPDX dans le projet et Grant limité à la classification.
- Une licence inconnue n'est jamais considérée comme autorisée.

## Critères d'acceptation

- [ ] `MIT OR GPL-3.0-only` est conforme si l'une des deux est autorisée.
- [ ] Une licence interdite produit un constat et peut déclencher une règle.
- [ ] La recherche `license:AGPL-3.0-only` renvoie les projets concernés.

## Tests attendus

Tables d'expressions SPDX ; intégration sur des SBOM d'exemple ; isolement.

## Points à trancher

- Politique par défaut d'une nouvelle organisation.

## Journal

_À remplir pendant la réalisation._
