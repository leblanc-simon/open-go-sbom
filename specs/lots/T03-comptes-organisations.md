# T03 — Comptes, TOTP et organisations

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T01 | À faire |

## Objectif

Se connecter avec un compte local protégé par un TOTP obligatoire, appartenir à une ou
plusieurs organisations avec un rôle, et ne jamais voir les données d'une autre
organisation. Poser le journal d'audit, la garde d'organisation et l'enregistrement de la
méthode d'authentification que tous les lots suivants utilisent.

## Périmètre

**Inclus**

- Câblage d'`authx` et `mfax` (stores SQL ; leurs `Migrate` dans le verrou de migration de
  T01) ; enrôlement TOTP obligatoire ; implémentation des `Renderer` : connexion, second
  facteur, configuration du TOTP avec QR, profil, changement de mot de passe.
- `internal/account` : écriture des comptes dans `users` (création avec
  `authx.HashPassword`, désactivation via `is_active`, réinitialisation du mot de passe,
  rôle d'instance via `role`) ; application de `must_change_pwd` par un middleware, puisque
  ni authx ni mfax ne le font.
- Table `session_auth` : pour chaque session ouverte, méthode `local_totp` (et, en T25,
  `sso` avec l'organisation du fournisseur). La garde d'organisation la lit.
- Premier administrateur depuis `bootstrap.*` ; changement de mot de passe et enrôlement
  TOTP à la première connexion. Avertissement s'il n'existe qu'un administrateur
  d'instance ; procédure de secours (variable d'environnement lue au démarrage, auditée)
  pour réinitialiser le TOTP d'un administrateur.
- Administration d'instance : comptes (création avec mot de passe temporaire, désactivation,
  réinitialisation du mot de passe et du TOTP), promotion administrateur d'instance,
  organisations (création, renommage, langue par défaut, archivage).
- Organisation : membres (ajout d'un compte existant, rôle, retrait) par ses
  administrateurs ; sélecteur d'organisation dans l'en-tête ; organisation par défaut du
  compte.
- `internal/tenant` : type `OrgID`, contexte, middleware `/o/{slug}`, contrôle
  d'appartenance, `RequireOrgRole`.
- `internal/audit` : table, `audit.Record`, écran de consultation (instance et organisation).
- `account_settings` : langue, thème, organisation par défaut ; la préférence de langue
  s'insère dans l'ordre du § 18.
- Limitation de débit dédiée (paquet `ratelimit` d'open-go-base) sur `/login` et
  `/login/2fa`.
- Premières tables d'organisation, sous RLS forcée (§ 9 de l'architecture) :
  `organizations`, `org_memberships`, `audit_events`. Les événements d'instance (sans
  organisation) vont dans la table globale `instance_audit_events`.
- Premières fonctions de `internal/db/crossorg` : résolution d'un slug et de l'appartenance
  pour la garde, liste des organisations d'un compte pour le sélecteur. La garde n'accède
  aux tables d'organisation qu'à travers elles tant que l'organisation n'est pas déclarée.
- Harnais de tests d'isolement réutilisé par chaque lot : parcours des routes avec un compte
  d'une autre organisation, et tests SQL de RLS (requêtes sans filtre dans `InOrg`, requêtes
  hors `InOrg`) qu'il suffit d'étendre à chaque nouvelle table.

**Exclu** : SSO (T25), équipes (T16), envoi de courriels (T15).

## Conception

- Rôles d'organisation : `viewer`, `analyst`, `admin`, dans `org_memberships`
  (`user_id bigint`). L'administrateur d'instance est le rôle `admin` d'authx ; c'est un
  rôle privilégié assumé : il ne voit pas les données d'une organisation dont il n'est pas
  membre, mais il peut réinitialiser les identifiants de n'importe quel compte, et chaque
  réinitialisation est auditée.
- Accès à une organisation dont on n'est pas membre : **404**.
- Politique de mot de passe : 12 caractères minimum, sans règle de composition, refus des
  mots de passe égaux à l'e-mail.
- Les messages d'erreur d'authx, mfax et csrfx sont en français dans open-go-base (§ 23 de
  l'architecture). Avant d'écrire les écrans, proposer l'évolution « erreurs sous forme de
  clés » ; tant qu'elle n'est pas disponible, le `Renderer` traduit à partir de la nature de
  l'erreur et non du texte reçu.
- ADR « isolement des organisations » : RLS obligatoire, schéma par organisation écarté
  (raisons du § 9 de l'architecture), liste initiale des fonctions de `crossorg` et règle de
  revue de tout ajout.

## Livrables

Écrans de connexion, second facteur, configuration TOTP, profil, administration d'instance,
membres d'organisation, journal d'audit ; migrations avec politiques RLS ; fonctions de
`crossorg` ; ADR d'isolement ; harnais d'isolement ; procédure de secours dans
`docs/operations.md`.

## Critères d'acceptation

- [ ] Un compte local sans TOTP enrôlé ne peut ouvrir aucune session applicative.
- [ ] Un compte avec `must_change_pwd` ne peut atteindre aucune page avant d'avoir changé
      son mot de passe.
- [ ] Le premier administrateur est créé une seule fois ; `bootstrap.*` est ignoré ensuite.
- [ ] Un membre de l'organisation A reçoit 404 sur toute URL de l'organisation B.
- [ ] Dans `InOrg(A)`, des requêtes sans filtre sur `organizations`, `org_memberships` et
      `audit_events` ne lisent ni n'écrivent rien de B ; hors `InOrg`, elles échouent.
- [ ] Un `viewer` ne peut modifier ni les membres ni les paramètres de l'organisation.
- [ ] Chaque action d'administration produit un événement d'audit lisible.
- [ ] Les erreurs de connexion sont génériques, traduites et à temps de réponse égalisé.
- [ ] La procédure de secours rend l'accès à un administrateur qui a perdu son TOTP, et
      laisse une trace d'audit.
- [ ] Tous les écrans passent l'assistant d'accessibilité, en français et en anglais.

## Tests attendus

Intégration de bout en bout du parcours de connexion (mot de passe, TOTP avec horloge
simulée, rejeu de code refusé), du bootstrap, du changement de mot de passe imposé, des
rôles, de l'isolement, de la procédure de secours.

## Points à trancher

- Longueur minimale du mot de passe (12 proposé).

## Journal

_À remplir pendant la réalisation._
