# T18 — Recette du lot 2

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T12, T13, T14, T15, T16, T17 | En cours (partie 1, compléments, faite) |

## Objectif

Passer le critère du lot 2 : **aucun composant ajouté par l'IA sans preuve vérifiée**, avec
un taux de faux positifs mesuré et tenu, et publier une préversion `v0.2.0` durcie.

## Périmètre

**Inclus**

- Évaluation finale de l'enrichissement IA sur le corpus annoté étendu et sur un
  échantillon annoté des dépôts pilotes ; rapport (précision, rappel, taux de faux positifs,
  coût, motifs de rejet).
- Revue de sécurité ciblée par un relecteur distinct de l'auteur, gravité selon l'OWASP Risk
  Rating : agent dépôt (injection d'instructions, sorties vers le fournisseur, secrets des
  forges), notifications (webhooks, SMTP), droits par équipe ; mise à jour du modèle de
  menace.
- Audit RGAA des écrans du lot 2.
- Nouvelle mesure des cibles de performance avec les équipes et les conteneurs, selon
  `docs/benchmarks.md`.
- Codes de secours TOTP : évolution de mfax dans open-go-base (§ 23 de l'architecture :
  codes à usage unique, hachés, régénérables ; étiquette semver), puis adoption dans lotor.
- Documentation utilisateur et exploitation du lot 2 ; `CHANGELOG.md` ; `v0.2.0`.

**Exclu** : toute autre nouvelle fonction.

## Critères d'acceptation

- [ ] Zéro composant d'origine IA accepté sans preuve vérifiée, sur le corpus et le pilote.
- [ ] Taux de faux positifs et rappel dans les seuils validés en T12, sur le corpus et sur
      l'échantillon pilote annoté.
- [ ] Aucune faiblesse de gravité haute ou critique ouverte.
- [ ] Grille RGAA remplie pour chaque nouvel écran, sans non-conformité bloquante.
- [x] Un utilisateur peut se connecter avec un code de secours, à usage unique
      (partie 1, `TestRecoveryCodes`).
- [ ] `v0.2.0` publiée.

## Décisions

Prises le 1er novembre 2026 :

- Seuils de l'enrichissement IA : faux positifs inférieurs ou égaux à 5 %, rappel
  supérieur ou égal à 80 % (décidés pour T12).
- Codes de secours TOTP livrés dans ce lot, par une évolution de mfax dans open-go-base.

## Journal

### Partie 1 — compléments

Réalisée le 1er novembre 2026, branche `lot/T18-complements`, en autonomie (lot 2
enchaîné sans attendre l'utilisateur, après la fusion de T12 à T17) : les décisions
marquées **[à relire]** n'ont pas été validées explicitement. Les parties suivantes (revue
de sécurité, audit RGAA, mesures, évaluation de l'IA, recette et `v0.2.0`) sont confiées à
d'autres agents.

#### Livré

- **open-go-base v1.4.0** (PR #5, fusionnée en squash, commit `a0f777f`, étiquette
  `v1.4.0` créée en local, à pousser) : codes de secours dans mfax, facultatifs
  (`WithRecoveryCodes`, `RecoveryStore` et son implémentation `database/sql` SQLite et
  PostgreSQL, migration `004`, `RecoveryRenderer` facultative, champ `recovery_code` de
  `VerifyPOST`, `RegenerateRecoveryPOST`, `GenerateRecoveryCodes`, `RecoveryRemaining`,
  `ConfirmRecovery`, `DisablePOST` qui accepte un code de secours, `WithRecoveryHook`,
  `WithRecoveryLanding`, `appconf.MFA.RecoveryCodes`) ; codes faux comptés dans le plafond
  du défi et dans le verrouillage par compte ; tests (`go vet ./...`, `go test -race ./...`
  verts), exemple testable, `doc.go`, README, CLAUDE.md.
- lotor monté sur la pseudo-version du commit fusionné
  (`v1.3.1-0.20261101100848-a0f777f827c9`) ; migration **022** (droits du rôle
  d'exécution sur `mfa_recovery_codes`).
- **Codes de secours** (`internal/web` : `auth_pages.go`, `security_pages.go` ;
  `internal/account/recovery.go`) : jeu de 10 codes montré une seule fois après
  l'activation du TOTP (`auth/recovery_codes`) ; formulaire « Utiliser un code de secours »
  à la connexion, arrivée sur la page du second facteur ; page **Mon compte › Second
  facteur** (`/account/security`) : codes restants (alerte à trois ou moins, invitation à
  générer pour un compte enrôlé avant la mise à jour), régénération après un code TOTP,
  reconfiguration de l'application par un code TOTP ou un code de secours
  (`account.ReconfigureTOTP` : secret, défis et codes retirés, sessions fermées, nouvel
  enrôlement à la connexion suivante) ; message sur la page de connexion. Codes supprimés
  aussi par la réinitialisation du TOTP (administrateur, procédure de secours). Audit :
  `account.recovery_codes_generated`, `auth.recovery_code_used`,
  `auth.recovery_code_failed`, `account.totp_reconfigured`. Réglage `mfa.recovery_codes`
  (5 à 50). Traductions FR et EN.
- **Recherche** (reliquats de T14 et T16) : filtre `team` (écran, API, export) ;
  équipe de chaque projet dans les résultats ; statut de triage de chaque constat d'une
  recherche par vulnérabilité (lien vers la fiche du constat) et filtre `triage`, refusé
  hors recherche par vulnérabilité (`error.search.triage_vulnerability_only`) ; recherche
  par composant sans les constats « non affecté » ni « faux positif » ; colonnes `team` et
  `triage_status` en fin d'export, `team`, `team_id` et `triage_status` en JSON ;
  `api/openapi.yaml` (paramètres `SearchTeam`, `SearchTriage`, schéma `TeamRef`) et code
  régénéré.
- **Purge des conteneurs archivés** (reliquat de T13) : étape de la rétention nocturne
  (`inventory.History.purgeContainers`), réglage `containers.purge_after` (180 jours,
  `0` : jamais, au moins `retention.days`), audit `project.purged`.
- Documentation : ADR 0048 à 0050, architecture (§ 8, § 10, § 13, § 23),
  `docs/utilisation.md` (section « Second facteur et codes de secours », filtres de la
  recherche, conteneurs), guides de démarrage FR et EN, `docs/operations.md`, modèle de
  menace, `config.example.yaml`, `CHANGELOG.md`.
- Tests : unitaires (mfax, requête de recherche, configuration) ; intégration PostgreSQL
  `TestRecoveryCodes` (critère « un utilisateur peut se connecter avec un code de secours,
  à usage unique », bout en bout : génération, connexion, refus du rejeu, reconfiguration,
  nouvel enrôlement, ancien jeu caduc, audit, aucun code dans les journaux),
  `TestReconfigureWithTOTPCode`, store de mfax sous PostgreSQL (`internal/account`),
  `TestSearchTeamFilter`, `TestSearchTriageStatus`, écran et API de la recherche
  (`TestSearchScreenAndAPI`), `TestRetentionPurgesLongArchivedContainers` ; nouvelles
  pages dans les balayages d'accessibilité (FR, EN, clair, sombre) et de titres ; routes
  ajoutées à la liste des routes globales du test d'isolement.

#### Décisions

- Format des codes (16 caractères de Crockford, 80 bits), empreinte SHA-256 liée au compte
  plutôt que bcrypt, 10 codes par défaut ([ADR 0048](../../docs/adr/0048-codes-de-secours.md)) **[à relire]**.
- Régénération soumise à un code TOTP, comme la création d'un jeton personnel ; codes
  montrés dans la réponse (`no-store`), jamais réaffichés (ADR 0048) **[à relire]**.
- **Reconfiguration de l'application par le titulaire**, au-delà de la fiche : sans elle,
  un code de secours ne sert qu'une connexion et la perte du téléphone exige encore un
  administrateur ; mot de passe et jetons gardés ; pas de page de confirmation (le code
  exigé en tient lieu) (ADR 0048) **[à relire]**.
- Comptes enrôlés avant la mise à jour : invités à générer leurs codes depuis la page du
  second facteur, sans bannière globale (ADR 0048) **[à relire]**.
- Recherche : statut de triage montré pour tous les constats d'une recherche par
  vulnérabilité, « non affecté » compris ; filtre `triage` refusé hors recherche par
  vulnérabilité ; recherche par composant sans les constats masqués
  ([ADR 0050](../../docs/adr/0050-equipe-et-triage-dans-la-recherche.md)) **[à relire]**.
- Purge : conteneurs archivés **pour absence** depuis 180 jours, jamais ceux archivés à la
  main ni ceux qui portent une décision de triage, dans la rétention nocturne, que
  `retention.enabled` soit vrai ou non, durée au moins égale à `retention.days`
  ([ADR 0049](../../docs/adr/0049-purge-des-conteneurs-archives.md)) **[à relire]**.

#### Écarts

- Reliquat de T17 (« tri des constats de T14 dans l'effet sur la sécurité ») : déjà fait
  par T14 (`finding/effect.go` écarte les statuts masqués) ; rien à reprendre.
- Reliquat de T12 (boutons « Confirmer la détection » / « Signaler une erreur » d'un
  composant trouvé par l'IA) : **non livré** ; c'est une fonction nouvelle (revue humaine
  des composants, distincte du triage des constats), exclue de T18 (« toute autre nouvelle
  fonction ») ; à reprendre dans un lot ultérieur s'il est voulu **[à relire]**.
- Les critères de T18 ne sont pas cochés ici, sauf « Un utilisateur peut se connecter avec
  un code de secours, à usage unique ».
- Parties suivantes, non traitées ici : revue de sécurité (qui relira ADR 0048 et la
  reconfiguration), audit RGAA (nouvelles pages : connexion par code de secours, codes de
  secours, second facteur ; filtres de la recherche), captures, mesures (dont la recherche
  avec les nouveaux filtres), évaluation de l'IA, essais Podman et Compose réels,
  `v0.2.0`.

#### ADR créés

- [0048 — Codes de secours du second facteur](../../docs/adr/0048-codes-de-secours.md).
- [0049 — Purge des conteneurs archivés depuis longtemps](../../docs/adr/0049-purge-des-conteneurs-archives.md).
- [0050 — Équipe et statut de triage dans la recherche](../../docs/adr/0050-equipe-et-triage-dans-la-recherche.md).

Aucune nouvelle fonction `crossorg`, aucune nouvelle dépendance tierce (open-go-base
monte de version).
