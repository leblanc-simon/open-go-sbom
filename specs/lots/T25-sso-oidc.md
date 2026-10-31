# T25 — SSO OIDC

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | À faire |

## Objectif

Se connecter par le fournisseur d'identité de son organisation, la double authentification
étant alors de sa responsabilité ; les comptes locaux gardent le TOTP obligatoire.

## Périmètre

**Inclus**

- Décision préalable : composant `oidcx` ajouté à open-go-base (réutilisable par les autres
  projets open-go) ou paquet propre à open-go-sbom.
- Un fournisseur par organisation : émetteur, identifiant client, secret chiffré, portées,
  domaines d'e-mail associés.
- Flux « authorization code » avec PKCE, `state` et `nonce`, validation complète du jeton
  d'identité (signature par JWKS, émetteur, audience, expiration, `nonce`).
- Création du compte à la première connexion (e-mail vérifié requis), rattachement à
  l'organisation avec un rôle par défaut ; correspondance facultative groupes → rôles.
- Page de connexion : choix de l'organisation par domaine d'e-mail ou par slug.
- Option d'organisation « connexion locale interdite pour ses membres ».
- Audit des connexions SSO et des créations de comptes.

**Exclu** : SAML.

## Conception

- Une session SSO n'exige pas de TOTP local ; une session locale l'exige toujours.
- Un compte local existant avec le même e-mail n'est rattaché à l'identité SSO qu'après une
  connexion locale réussie (pas de prise de contrôle par simple égalité d'e-mail).

## Critères d'acceptation

- [ ] Connexion de bout en bout avec un fournisseur de test (Keycloak ou Dex en conteneur).
- [ ] Un jeton d'identité altéré, expiré ou d'une autre audience est refusé.
- [ ] Un membre d'une organisation à connexion locale interdite ne peut plus se connecter
      par mot de passe.
- [ ] Un compte local garde le TOTP obligatoire.

## Tests attendus

Fournisseur simulé pour les tests unitaires (clés générées, jetons forgés) ; intégration
avec un vrai fournisseur en conteneur, hors CI par défaut.

## Points à trancher

- Emplacement du code OIDC (open-go-base ou ici).
- Dépendances : `golang.org/x/oauth2` et une bibliothèque de validation OIDC, ou
  implémentation minimale.

## Journal

_À remplir pendant la réalisation._
