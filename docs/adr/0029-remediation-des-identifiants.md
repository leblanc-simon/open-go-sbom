# 0029 — Identifiants : verrouillage par compte, révocation d'office, réinitialisation avec mot de passe, durée absolue de session

- Statut : Accepté
- Date : 2026-10-31
- Lot : T11

## Contexte

La revue de sécurité du lot 1 (T11) a relevé trois faiblesses de gravité moyenne sur les
identifiants, toutes vérifiées dans le code et par des tests :

- **SEC-01** : la seule borne du TOTP était le débit par IP. Le plafond de mfax
  (`max_attempts`) vaut par défi, et un nouveau défi s'obtient en rejouant le mot de
  passe : avec le mot de passe, environ 65 % de chances de forcer le TOTP en 30 jours
  depuis une seule IPv4, quelques heures avec un /64 IPv6 (compté comme 2^64 IP).
- **SEC-02** : un jeton personnel (365 jours au plus) survivait à la réinitialisation du
  mot de passe et du TOTP, et se créait avec la seule session : une session volée un
  instant devenait un accès durable aux API de toutes les organisations du compte.
- **SEC-03** : après réinitialisation du TOTP (ou procédure de secours), le mot de passe
  seul ouvrait l'enrôlement : quiconque le connaît enrôlait **son** TOTP avant le
  titulaire.

S'y ajoute un point de SEC-08 : la session d'authx glisse de 12 h à chaque requête, sans
durée absolue.

## Décision

- **Verrouillage par compte, dans mfax** (open-go-base v1.3.0, PR #3, accord de
  l'utilisateur) : `WithLockout` compte les codes faux par compte, tous défis confondus,
  dans la table `mfa_lockouts`. Au-delà de `mfa.lockout_threshold` (10) dans
  `mfa.lockout_window` (15 min), le compte est verrouillé `mfa.lockout_duration` (15 min),
  durée doublée à chaque récidive jusqu'à `mfa.lockout_max_duration` (24 h). Compte
  verrouillé : le mot de passe n'ouvre plus de défi, un défi en cours est abandonné sans
  examen du code ; message générique, entrée d'audit `account.locked`. Un code juste
  efface le compteur ; la réinitialisation du TOTP aussi (levée par un administrateur).
- **Seuls les codes TOTP comptent**, pas les mots de passe : un verrouillage sur le mot de
  passe laisserait n'importe qui verrouiller n'importe quel compte connu par son e-mail.
  Le mot de passe reste borné par le débit par IP, une IPv6 comptant pour son /64
  (`ratelimit.WithKeyFunc`, sans évolution d'open-go-base).
- **Révocation d'office des jetons personnels**, dans la transaction de
  `ResetPassword`, de la réinitialisation du TOTP (administrateur et procédure de
  secours) et de `ChangePassword` quand le titulaire laisse cochée « révoquer aussi mes
  jetons » (cochée par défaut ; toujours pour un mot de passe temporaire). Une entrée
  `personal_token.revoked` par jeton, avec sa cause (`reason`).
- **Compte en attente refusé** : `AuthenticateToken` refuse un compte au mot de passe
  temporaire ou sans TOTP actif (`error.token.account_pending`), même si un jeton
  échappait à la révocation.
- **Réauthentification à la création d'un jeton personnel** : un code TOTP est exigé
  (`mfax.Service.Confirm` : anti-rejeu, codes faux comptés dans le verrouillage).
- **Réinitialiser le TOTP réinitialise le mot de passe** : mot de passe temporaire tiré,
  `must_change_pwd`, montré une fois à l'administrateur comme pour `ResetPassword`. La
  procédure de secours exige `bootstrap.rescue_password` (choisi par l'exploitant, validé
  par la politique, changé à la connexion).
- **Durée absolue de session** dans le projet (`login.session_max_age`, 7 jours par
  défaut, 0 pour aucune) : `loadViewer` ferme toute session authentifiée dont
  l'authentification (`session_auth.created_at`) est plus ancienne. Pas d'évolution
  d'authx : la date d'authentification est déjà enregistrée par le projet.

## Conséquences

- Qui connaît le mot de passe peut verrouiller le compte (jusqu'à 24 h par palier) : c'est
  voulu, le verrouillage est journalisé et signale une compromission du mot de passe ;
  l'administrateur le lève en réinitialisant le TOTP (ce qui impose aussi un nouveau mot
  de passe).
- La création d'un jeton consomme un code TOTP : au plus un jeton par pas de 30 s.
- Après réinitialisation, l'administrateur doit transmettre un mot de passe temporaire par
  un canal sûr, y compris pour une réinitialisation du TOTP seule.
- Une session ouverte depuis plus de 7 jours oblige à se reconnecter, même active.
- Nouvelle table `mfa_lockouts` (créée par le `Migrate` de mfax) ; ses droits sont accordés
  par la migration 015.

## Alternatives écartées

- **Verrouillage maison dans le projet** (enveloppe du `ChallengeStore`, comptage dans le
  `Renderer`) : possible, mais fragile (le comptage dépendrait du rendu d'une page) et
  utile à tous les projets d'open-go-base.
- **Jeton d'enrôlement à usage unique transmis hors bande** au lieu d'un mot de passe
  temporaire : plus de code (nouvelle route, nouveau secret) pour la même garantie ; le
  mot de passe temporaire réutilise le parcours existant (`must_change_pwd`).
- **Réauthentification par mot de passe** pour créer un jeton : le mot de passe est
  justement ce qui a pu fuir ; le code TOTP prouve la possession du second facteur.
- **Durée absolue dans authx** : demandait une évolution d'open-go-base alors que le
  projet connaît déjà la date d'authentification de chaque session.
