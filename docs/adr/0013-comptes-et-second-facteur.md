# 0013 — Comptes et second facteur : secrets TOTP chiffrés, méthode de session, secours par ticket

- Statut : Accepté
- Date : 2026-10-31
- Lot : T03

## Contexte

T03 branche authx et mfax (open-go-base), dont les stores écrivent en base les jetons de
session et les secrets TOTP **en clair**, sans contexte ni transaction partagée. Le § 10
de l'architecture demande en plus d'enregistrer la méthode d'authentification de chaque
session (`session_auth`), une procédure de secours pour un administrateur unique qui
perd son TOTP (variable lue au démarrage, auditée, à retirer ensuite), et le journal des
connexions et de leurs échecs.

## Décision

- **Secrets TOTP chiffrés** **[à relire]** : `account.SealedTOTPStore` enveloppe le store
  de mfax et chiffre chaque secret avec `internal/secret` (AES-256-GCM), données
  associées `mfa_totp:<id du compte>` (un chiffré recopié sur un autre compte ne s'ouvre
  pas), format `s1:<clé>:<base64>`. Un secret en clair est refusé. `secrets.keys` devient
  donc obligatoire. Au démarrage, les secrets chiffrés par une ancienne clé sont
  rechiffrés par la clé active : l'ancienne peut être retirée au démarrage suivant.
- **Méthode de session** : `account.SessionRecorder` enveloppe le store de sessions
  d'authx ; toute session *authentifiée* qu'il crée reçoit sa ligne `session_auth`
  (`local_totp`) et l'événement de connexion, sinon elle est supprimée. Avec mfax en
  enrôlement obligatoire, une session authentifiée ne s'ouvre qu'après le TOTP.
  L'interface refuse une session authentifiée sans méthode, ou dont le compte n'a plus de
  TOTP actif (réinitialisé entre-temps). Un déclencheur sur `sessions` emporte la ligne
  de `session_auth` (clé : SHA-256 du jeton).
- **Procédure de secours par ticket** **[à relire]** : deux variables,
  `LOTOR_BOOTSTRAP_RESCUE_TOTP_EMAIL` et `LOTOR_BOOTSTRAP_RESCUE_TICKET` (référence
  d'incident, 8 caractères au moins). Au démarrage, le TOTP de cet administrateur
  d'instance actif est retiré et ses sessions fermées, **une fois par couple (compte,
  ticket)** (journal d'audit) ; laissées en place, les variables n'ont plus d'effet et le
  serveur rappelle de les retirer. Un seul identifiant ne suffisait pas : on ne distingue
  pas une variable oubliée d'un second incident.
- **Journal des connexions** : succès (enveloppe de session), échec du mot de passe
  (rendu de la page, avec l'adresse saisie), code TOTP refusé (rendu de la page, compte
  retrouvé par le cookie du défi), enrôlement, déconnexion. Aucun mot de passe, code ou
  secret n'est journalisé.
- **Ordre du premier login** : mot de passe temporaire → enrôlement du TOTP (session de
  configuration de mfax) → changement de mot de passe imposé (`must_change_pwd`, appliqué
  par un middleware du projet) → application.
- **IP des sessions** : authx lit `X-Forwarded-For` sans vérifier le pair ; un middleware
  réécrit l'en-tête avec l'IP résolue par les mandataires de confiance avant authx.

## Conséquences

- Une lecture de la base ne suffit plus à produire des codes TOTP ; les jetons de session
  restent en clair dans `sessions` (choix d'authx, noté au modèle de menace).
- La perte de toutes les clés de `secrets.keys` impose de réinitialiser le TOTP de tous
  les comptes.
- La purge des sessions et défis expirés est un job horaire (`auth.purge`) de la file de
  T02.

## Alternatives écartées

- **Secrets TOTP en clair** (comportement de mfax) : contraire au principe « secrets
  chiffrés » du § 1 ; une fuite de sauvegarde annulerait le second facteur.
- **Chiffrement dans open-go-base** : hors du § 23 ; l'enveloppe du projet suffit et
  n'impose rien aux autres projets.
- **Déclencheur SQL pour `session_auth` à l'insertion** : la méthode deviendrait
  implicite et SSO (T25) devrait la corriger après coup.
- **Variable de secours unique (e-mail seul)** : rejouée à chaque redémarrage tant
  qu'elle reste en place.
