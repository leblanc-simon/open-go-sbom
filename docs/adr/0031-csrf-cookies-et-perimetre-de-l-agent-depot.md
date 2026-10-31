# 0031 — CSRF lié à la session, cookies `__Host-`, protection inter-origines ; périmètre de l'agent dépôt

- Statut : Accepté
- Date : 2026-10-31
- Lot : T11

## Contexte

La revue de sécurité du lot 1 (T11) a relevé :

- **SEC-08** (Low) : le jeton CSRF de csrfx était une double soumission simple : qui sait
  écrire le cookie (sous-domaine du même site, réponse HTTP en clair si `cookie_secure`
  vaut `auto` sans détection de HTTPS) pose le cookie et le champ à la même valeur.
  `SameSite=Lax` ne bloque pas le même site. Les cookies n'avaient pas le préfixe
  `__Host-`.
- **SEC-10** (Low) : les dépôts analysés par l'agent dépôt sont choisis par le serveur,
  c'est-à-dire par un administrateur d'organisation qui saisit une URL de forge ; l'agent
  analysait tout ce que ses identifiants pouvaient lire, et le jeton d'installation GitHub
  valait pour tous les dépôts de l'installation.

## Décision

- **Jeton CSRF lié à la session** (open-go-base v1.3.0, `csrfx.WithSessionBinding`,
  accord de l'utilisateur) : le jeton présenté est `HMAC-SHA256(clé = cookie, message =
  jeton de session)`. Sans le secret de session de la victime (cookie `HttpOnly`), aucun
  couple valable ne se forge. Liaison active dès que l'interface a des sessions.
- **Protection inter-origines** de la bibliothèque standard
  (`http.CrossOriginProtection`) avant csrfx, sur l'interface seulement : une requête
  mutante dont `Sec-Fetch-Site` n'est ni `same-origin` ni `none`, ou dont `Origin` ne
  correspond pas à l'hôte, est refusée (403). Elle couvre aussi la connexion, sans session.
- **Cookies `__Host-`** quand `auth.cookie_secure` vaut `on` : `__Host-ogsbom_session`
  (nom configuré préfixé), `__Host-csrf_token`, `__Host-mfa_challenge`
  (`mfax.WithChallengeCookieName`). Le préfixe exige `Secure` : en `auto` ou `off`, les
  noms restent sans préfixe et un avertissement est journalisé au démarrage.
  `config.example.yaml` passe à `on` (les navigateurs acceptent les cookies `Secure` sur
  `http://localhost`) ; la valeur par défaut du code reste `auto` pour ne pas casser une
  configuration existante.
- **Périmètre de l'agent dépôt** : `forges[].allowed_namespaces`, **obligatoire** :
  propriétaires GitHub ou groupes GitLab (sous-groupes compris, sans casse), ou `*`
  explicitement. Un dépôt hors périmètre n'est pas reconnu : jamais cloné ni analysé.
  C'est la décision de l'exploitant de l'agent, pas du serveur.
- **Jeton GitHub restreint au dépôt** : demandé avec `repositories: [nom]` et mis en
  cache par dépôt.

## Conséquences

- Un formulaire affiché avant une connexion ou une déconnexion est refusé (403 « formulaire
  expiré ») : il faut recharger la page.
- Derrière un mandataire, l'en-tête `Host` doit être transmis tel quel (repli de la
  protection inter-origines sur `Origin` pour les navigateurs sans `Sec-Fetch-Site`).
- Une configuration d'agent dépôt existante sans `allowed_namespaces` est refusée au
  démarrage : à compléter à la mise à jour (lot 1 non encore publié).
- Un dépôt GitHub de plus coûte une demande de jeton par heure.

## Alternatives écartées

- **Vérifier seulement `Origin`/`Sec-Fetch-Site`** sans lier le jeton : ne protège pas un
  navigateur ancien ni un client qui omet ces en-têtes ; les deux se complètent.
- **HMAC par une clé du serveur** plutôt que par le cookie : demande une clé de plus à
  configurer et à faire tourner, pour la même propriété (le secret de session suffit).
- **`cookie_secure: on` par défaut dans le code** : casse silencieusement la connexion d'un
  accès en clair autre que localhost ; l'exemple et l'avertissement suffisent.
- **Périmètre facultatif (tout par défaut)** : laisserait le comportement dangereux par
  défaut ; `*` reste possible, mais explicite.
