# T24 — SBOM signés

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T19, T23 | À faire |

## Objectif

Garantir qu'un SBOM provient bien de l'agent qui le revendique et n'a pas été modifié en
chemin, y compris lors d'un transport hors ligne.

## Périmètre

**Inclus**

- ADR du mécanisme. Proposition : une paire de clés Ed25519 générée par chaque agent à
  l'inscription, clé publique enregistrée par le serveur, signature détachée de l'empreinte
  du SBOM et du contexte. Sigstore sans clé est écarté car inutilisable hors ligne.
- Signature par les deux agents (réseau et fichier, T23), vérification à l'ingestion.
- Point compatible Dependency-Track (T19) : ses clients ne signent pas ; quand la signature
  est obligatoire, leurs envois sont refusés avec une erreur explicite.
- Politique d'organisation « signature obligatoire » ; statut de vérification affiché sur
  chaque instantané.
- Rotation de la clé d'un agent et révocation.

**Exclu** : signature des binaires et des paquets (T26).

## Critères d'acceptation

- [ ] Un SBOM modifié après signature est refusé quand la signature est obligatoire, et
      signalé sinon.
- [ ] Une clé révoquée invalide les envois suivants de l'agent.
- [ ] Une archive hors ligne signée est vérifiée à l'import.

## Tests attendus

Vecteurs de test de signature ; altérations (SBOM, contexte, clé) ; isolement.

## Points à trancher

- Valider le mécanisme proposé dans l'ADR.

## Journal

_À remplir pendant la réalisation._
