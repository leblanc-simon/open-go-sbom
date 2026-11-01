# 0048 — Codes de secours du second facteur

- Statut : Accepté
- Date : 2026-11-01
- Lot : T18

## Contexte

Le TOTP est obligatoire (ADR 0013). Jusqu'ici, un compte qui perdait son application
dépendait d'un administrateur d'instance (réinitialisation, ADR 0029). La décision du
1er novembre 2026 (fiche T18, § 23 de l'architecture) demande des codes de secours à usage
unique, hachés et régénérables, livrés par une évolution de mfax dans open-go-base, sans
dupliquer le second facteur dans lotor.

## Décision

### Dans open-go-base (mfax v1.4.0, PR #5, commit `a0f777f`)

- Option `WithRecoveryCodes(RecoveryStore)`, **facultative** : sans elle, rien ne change
  (projets existants). Interface `RecoveryStore` (Replace, Use, Remaining, Delete) et
  implémentation `database/sql` SQLite et PostgreSQL, table `mfa_recovery_codes`
  (migration `004`), comme les autres stores de mfax.
- **Format** : 16 caractères de l'alphabet de Crockford (80 bits), affichés
  `xxxx-xxxx-xxxx-xxxx` ; saisie tolérante (casse, espaces, tirets, `o`→`0`, `i`/`l`→`1`).
  **[à relire]**
- **Hachage** : SHA-256 de l'utilisateur et du code (pas de bcrypt) : 80 bits d'aléa
  rendent la recherche exhaustive hors ligne hors de portée, et l'empreinte déterministe
  permet une consommation atomique par `UPDATE … WHERE used_at = 0` ; liée au compte, une
  ligne recopiée ailleurs ne vaut rien. **[à relire]**
- **Nombre** : `mfa.recovery_codes`, 10 par défaut (5 à 50 dans lotor). **[à relire]**
- **Parcours** : `EnablePOST` génère le jeu à l'enrôlement et le montre une fois par
  `RecoveryRenderer` (interface facultative, pour ne pas casser `Renderer`) ; `VerifyPOST`
  accepte le champ `recovery_code` ; un code faux compte dans le plafond du défi **et**
  dans le verrouillage par compte, un compte verrouillé refuse aussi les codes de secours ;
  `RegenerateRecoveryPOST`/`GenerateRecoveryCodes` remplacent le jeu (l'ancien devient
  caduc, codes utilisés compris) ; `ConfirmRecovery` réauthentifie par un code de secours ;
  `WithRecoveryHook` (audit) et `WithRecoveryLanding` (page d'arrivée).

### Dans lotor

- Codes montrés **une seule fois** à l'enrôlement (`auth/recovery_codes`, réponse
  `no-store`), puis sur demande depuis **Mon compte › Second facteur** après un **code
  TOTP** (comme la création d'un jeton personnel) ; nombre restant affiché, alerte à trois
  ou moins.
- Connexion par code de secours : formulaire replié (`<details>`) sous la saisie du code
  TOTP ; arrivée sur la page du second facteur, qui dit qu'un code a servi.
- **Reconfiguration par le titulaire** (au-delà de la fiche) : un code TOTP ou un code de
  secours retire le secret, les défis et les codes, ferme toutes les sessions ; la
  connexion suivante (mot de passe) impose un nouvel enrôlement, donc un nouveau jeu. Mot
  de passe et jetons personnels gardés (le titulaire a prouvé un facteur ; la
  réinitialisation par un administrateur, elle, les change). Sans cette action, un code de
  secours ne servirait qu'à se connecter, une fois, et la perte du téléphone exigerait
  encore un administrateur. Pas de page de confirmation : le code exigé en tient lieu et
  l'action se rattrape par l'enrôlement. **[à relire]**
- **Audit** (journal de l'instance) : `account.recovery_codes_generated` (nombre, contexte),
  `auth.recovery_code_used` (codes restants), `auth.recovery_code_failed`,
  `account.totp_reconfigured`. Jamais un code dans un journal.
- Codes supprimés avec le TOTP : réinitialisation par un administrateur, procédure de
  secours, reconfiguration. Migration `022` : droits du rôle d'exécution sur
  `mfa_recovery_codes`.
- Comptes enrôlés avant la mise à jour : aucun code ; la page du second facteur les invite
  à en générer (pas de bannière sur toutes les pages). **[à relire]**

## Conséquences

- Un titulaire qui a perdu son application la remplace seul ; l'administrateur n'intervient
  plus que si l'application et les codes sont perdus.
- Un attaquant qui connaît le mot de passe a désormais deux familles de codes à deviner,
  sous le même verrouillage : 10 codes de 80 bits n'ajoutent rien de mesurable à une force
  brute bornée à 10 essais par 15 minutes.
- La reconfiguration depuis une session volée exige un facteur, puis le mot de passe pour
  le nouvel enrôlement.

## Alternatives écartées

- **Codes de secours dans lotor**, sans toucher à mfax : duplication du second facteur et
  du verrouillage, contraire au § 23.
- **bcrypt par code** : vérification d'un code contre chaque empreinte (10 × bcrypt) sans
  consommation atomique simple ; inutile à 80 bits d'aléa.
- **Même champ que le code TOTP** à la connexion : ambiguïté de saisie et de message
  d'erreur ; deux champs explicites restent clairs pour les lecteurs d'écran.
- **Désactivation du TOTP par le titulaire** (`DisablePOST` de mfax) : contraire au TOTP
  obligatoire ; la reconfiguration retire et impose aussitôt un nouvel enrôlement.
