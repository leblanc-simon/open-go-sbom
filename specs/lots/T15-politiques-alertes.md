# T15 — Politiques, alertes et statuts de commit

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T14 | Terminé |

## Objectif

Exprimer des règles déclaratives, être prévenu quand elles sont violées sur les bons
canaux, et voir le verdict directement sur chaque commit dans la forge.

## Périmètre

**Inclus**

- `internal/policy` : règles en CEL sur le contexte (projet, étiquettes, composant, constat,
  statut de triage, agent) ; modèles fournis : KEV sur un projet de production, critique avec
  correctif disponible depuis plus de 30 jours, agent muet depuis 7 jours (le modèle
  « licence AGPL » est livré désactivé jusqu'à T20). Évaluation après chaque analyse et
  chaque jour. Violations datées ; drapeau « bloquante ».
- `internal/notify` : canaux par organisation (e-mail SMTP, webhook générique signé en HMAC
  avec horodatage, Matrix, Mattermost, Slack), secrets chiffrés par `internal/secret`,
  envoi par jobs avec réessais, résumé quotidien ou envoi immédiat selon la règle, bouton
  « envoyer un test », messages traduits dans la langue de l'organisation.
- Mailer `net/smtp` (TLS implicite ou STARTTLS), configuration et documentation.
- Messages produits dans la langue de l'organisation (définie en T03).
- Verdict d'un instantané : `GET /api/v1/agent/snapshots/{id}/verdict` (en attente, conforme,
  non conforme, résumé, lien).
- Agent dépôt : après l'envoi, attente bornée du verdict puis publication du statut de commit
  (GitHub et GitLab).
- Écrans : liste et édition des règles (validation et aperçu du nombre de violations
  actuelles avant enregistrement), violations, canaux.
- Audit : création, modification et suppression des règles et des canaux, envois de test.

**Exclu** : réinitialisation de mot de passe par e-mail (hors cahier des charges).

## Conception

- Une règle invalide ou trop coûteuse est refusée à l'enregistrement (CEL compilé, coût
  borné) ; aucune règle ne s'exécute sans limite de coût.
- Les notifications sont dédoublonnées : une violation déjà notifiée ne l'est pas de nouveau
  tant qu'elle n'a pas été résolue.
- Signature des webhooks : `HMAC-SHA256(secret, horodatage + "." + corps)`, horodatage dans un
  en-tête pour permettre au destinataire de refuser les rejeux.

## Livrables

Paquets, migrations, écrans, route d'API, évolution de l'agent dépôt, documentation des
canaux et du format de webhook.

## Critères d'acceptation

- [x] Chaque modèle de règle fournie déclenche sur un jeu construit à la main, et pas en
      dehors (`TestTemplateKEVProduction`, `TestTemplateCriticalFix`,
      `TestTemplateAgentSilent` ; de bout en bout : `TestKEVProductionOnHandBuiltSet`,
      `TestCriticalFixOnHandBuiltSet`, `TestAgentSilentOnHandBuiltSet`). Le modèle
      « licence AGPL » est livré indisponible jusqu'à T20 (décision de la fiche).
- [x] Un canal en panne reçoit ses messages après rétablissement (réessais), sans doublon
      (`TestChannelDownGetsMessagesWithoutDuplicate` : trois refus, puis un seul message
      accepté, même identifiant à chaque tentative, signature vérifiée).
- [x] Le statut de commit apparaît sur GitHub et GitLab avec le bon état, contre des forges
      simulées (`TestGitHubSetStatus`, `TestGitLabSetStatus`,
      `TestReportStatusPublishesPendingThenVerdict`) ; essai sur une vraie forge : action de
      l'utilisateur (voir Écarts).
- [x] Une règle CEL invalide est refusée avec un message traduit qui situe l'erreur
      (`TestInvalidRulesAreLocated` ; écran en français et en anglais : `TestPolicyScreens`).
- [x] Aucun secret de canal n'est lisible en base ni dans les journaux
      (`TestChannelSecretsAreSealed`, `TestChannelSecretsRotate`, `TestPolicyScreens` :
      base, audit, journaux, pages).

## Tests attendus

Tables de règles CEL ; destinataires simulés (`httptest`, serveur SMTP de test) ;
vérification de signature ; forges simulées ; isolement.

## Décisions

Prises le 1er novembre 2026 :

- Dépendance `github.com/google/cel-go` validée.

## Journal

Réalisé le 1er novembre 2026, branche `lot/T15-politiques-alertes`, en autonomie (lot 2
enchaîné sans attendre l'utilisateur, après la fusion de T16, T17, T14 et, pendant le lot,
T12) : les décisions marquées **[à relire]** n'ont pas été validées explicitement.

### Livré

- Migration **020** (`020_policies.sql`, numérotée 019 avant la fusion de T12) : tables
  d'organisation `policies`, `policy_channels`, `policy_violations` (une seule ouverte par
  couple règle × sujet, index uniques partiels), `policy_evaluations`,
  `notification_channels` (secret chiffré, réglages en `jsonb`), `notification_deliveries`
  (clé primaire canal × violation) ; RLS standard, clés composites ; colonne
  `findings.fixed_seen_at` (première vue d'un correctif), posée par l'analyse.
- `internal/policy` : compilateur CEL (contexte typé par `ext.NativeTypes`, deux sujets,
  erreurs situées `ExprError`, coût estimé et réel bornés, cache), modèles fournis,
  service (création, modification, suppression, aperçu, vérification), évaluation
  (`policy.evaluate_project`, `policy.evaluate_org`, `policy.evaluate_all` à 02:00 UTC ;
  points d'accroche `OnAnalyzed` pour `finding.Analyzer` et `OnTriageChange` pour
  `triage.Options.OnChange`), violations (liste paginée filtrée par équipe, résumé du
  tableau de bord), `notify.Loader`, verdict d'un instantané.
- `internal/notify` : canaux (e-mail, webhook générique, Matrix, Mattermost, Slack),
  secrets chiffrés par `internal/secret` (données associées : organisation et canal) et
  rechiffrés au démarrage, `Queue` dans la transaction qui ouvre les violations, job
  `notify.send` (lot de 100, violations résolues écartées, identifiant de message stable,
  30 tentatives), résumé quotidien (`notify.digest_all`, `notify.digest_org`, qui relance
  aussi les envois restés en attente), essai, messages dans la langue de l'organisation,
  signature `Sign`.
- `internal/delivery` (serveur, hors métier) : client HTTP gardé contre la SSRF (adresse
  vérifiée à la connexion, sans redirection ni mandataire, réponse bornée, erreurs sans
  URL) ; courriel par `net/smtp` (STARTTLS exigé ou TLS implicite, PLAIN, en-têtes protégés,
  quoted-printable).
- API : `GET /api/v1/agent/snapshots/{id}/verdict` (contrat, code généré, résumé traduit
  dans la langue de l'organisation, 140 caractères) ; `agentclient.Verdict`, `WaitVerdict`.
- Agent dépôt : `forge.Provider.SetStatus` (GitHub : jeton séparé `statuses: write` ;
  GitLab : `/statuses/:sha`), reçu d'envoi et `Server.Verdict`, `reportStatus` (en attente
  puis verdict, délai borné), configuration `status.*` désactivée par défaut.
- Écrans : `/o/{slug}/policies` (liste, modèles, nouvelle règle, édition avec aperçu,
  suppression confirmée), `/o/{slug}/violations` (ouvertes et résolues, filtre par règle,
  pagination), `/o/{slug}/channels` (liste, création, modification, essai, suppression
  confirmée), section « Alertes » du tableau de bord ; écran `policies.css` ; traductions
  FR et EN ; menu et plan du site.
- Droits : `policy.manage`, `channel.manage` (administrateurs d'organisation) ;
  `docs/security/permissions.md` régénéré.
- Configuration : fragments `notify` (`public_url`, `timeout`, `allow_private_networks`,
  `digest_hour`) et `smtp` ; `config.example.yaml`, `deploy/lotor-repo-agent/config.example.yaml`.
- Audit : `policy.created|updated|deleted`, `channel.created|updated|deleted|tested`.
- Docs : ADR 0045 à 0047 ; `docs/notifications.md` (canaux, format et vérification du
  webhook, statut de commit) ; `docs/operations.md` (« Politiques et notifications »,
  « Statut de commit », droits GitHub et GitLab, rotation des clés) ; `docs/utilisation.md`
  (« Politiques et alertes ») ; modèle de menace ; `architecture.md` (§ 3, 4, 5, 6, 8, 10,
  12, 15, 17, 19) ; `CHANGELOG.md`.

### Tests

- `internal/policy` (unitaires) : modèles compilés et indisponibilité du modèle AGPL ;
  **chaque modèle sur un jeu construit à la main, et pas en dehors** ; **table des règles
  invalides** (clé, ligne, colonne, nom) ; erreur d'évaluation, cache.
- `internal/policy` (intégration, vraie chaîne ingestion → analyse avec base factice) :
  modèles de bout en bout, dédoublonnage et réouverture, triage qui résout, correctif qui
  disparaît, agent muet, **canal en panne puis rétabli sans doublon**, résumé quotidien et
  envoi écarté, **verdict** (en attente, non conforme, conforme avec avertissement, commit au
  même inventaire, autre agent ou organisation : introuvable), cycle de vie et audit,
  **isolement** entre organisations et filtre d'équipe, secrets scellés et rotation,
  jobs, pages. Vérifié en retirant le dédoublonnage de `apply` : deux tests échouent.
- `internal/notify` : signature (vecteur recalculé), mise en forme de chaque nature,
  échappement Slack, messages traduits et bornés, identifiant stable, validation des
  canaux ; intégration : CRUD, isolement, canal inactif puis réactivé, échec puis succès
  avec le même identifiant, essai journalisé.
- `internal/delivery` : table des adresses refusées, garde par défaut, redirection non
  suivie, statut, serveur arrêté, URL absente des erreurs ; **serveur SMTP de test**
  (STARTTLS, TLS implicite, AUTH PLAIN, refus sans STARTTLS avant tout mot de passe,
  mauvais mot de passe, destinataire refusé, injection d'en-tête).
- `internal/forge` : statuts GitHub (permissions du jeton, jeton distinct du clonage,
  description bornée, refus d'un état ou d'un commit invalide) et GitLab (correspondance des
  états, lien non http retiré).
- `internal/repoagent` : en attente puis verdict pour chaque état, délai dépassé,
  désactivé, forge qui refuse ; `apiServer.Verdict` contre une API simulée.
- `internal/web` : `TestPolicyScreens` (canaux, secret jamais réaffiché, essai réussi et en
  échec, règle invalide en français et en anglais, aperçu, enregistrement, notification,
  verdict par l'API, lecteur en 403 sur règles et canaux, violations et Alertes, deux
  langues, accessibilité et CSP de chaque écran, isolement, suppressions, audit, secret
  absent des journaux) ; harnais d'isolement par route et `TestRoutePermissionsFollowMatrix`
  couvrent les nouvelles routes ; clés dynamiques.
- `internal/db` : harnais RLS étendu aux six tables ; `internal/config` : défauts et
  validation des fragments.
- Couverture : `policy` 81,5 %, `notify` 79,8 %.

### Décisions

Décision de la fiche appliquée : dépendance CEL validée. Décisions prises pendant le lot,
toutes **[à relire]** :

- **`cel.dev/cel-go` v0.32.0** : `github.com/google/cel-go` sous son nouveau chemin de
  module (le chemin GitHub s'arrête à v0.31.0) ; version la plus récente de plus de deux
  semaines ; `antlr4-go` en dépendance transitive ([ADR 0045](../../docs/adr/0045-politiques-cel-et-verdicts.md)).
- **Contexte typé, deux sujets** (constat, agent), `finding.actionable` = « à analyser »
  ou « affecté » ; coût borné à 50 000 ; 100 politiques par organisation (ADR 0045).
- **Correctif disponible depuis** = première vue du correctif par lotor (`fixed_seen_at`),
  constats existants datés de leur première détection (ADR 0045).
- **Violations** par couple (règle, sujet), résolues dès que la règle cesse d'être vraie ;
  désactiver ou changer une règle résout ses violations, la supprimer les supprime (ADR 0045).
- **Verdict** sur l'état courant de la référence, en attente tant que l'ensemble de
  l'instantané n'est pas analysé et évalué ; règles d'agent jamais bloquantes (ADR 0045).
- **Modèle AGPL** affiché mais indisponible jusqu'à T20 ; « production » = étiquette
  `env=production` (ADR 0045).
- **Objectifs de délai** du tableau de bord (renvoi d'ADR 0027) exprimés par des règles,
  section « Alertes » livrée ; pas de réglage ni de repères sur les barres (ADR 0045).
- **Droits** : règles et canaux aux administrateurs d'organisation, violations à tout
  membre selon ses équipes (ADR 0045, 0046).
- **Envois** : un par couple (canal, violation), regroupés par message, 30 tentatives puis
  relance quotidienne, violation résolue écartée, identifiant de message stable ; résumé à
  7 h UTC ([ADR 0046](../../docs/adr/0046-notifications.md)).
- **Webhook** : clé HMAC fournie par l'administrateur (16 caractères au moins), signature
  `sha256=` sur `horodatage.corps` (ADR 0046).
- **Garde SSRF** sans mandataire, `notify.allow_private_networks` pour un relais interne
  (ADR 0046).
- **Statut de commit** : attente synchrone (le commit suivant attend), « en attente »
  laissé à l'expiration, `canceled` sur GitLab pour une ingestion refusée, désactivé par
  défaut, jeton GitHub séparé ([ADR 0047](../../docs/adr/0047-statut-de-commit.md)).
- **Rotation des secrets des canaux** au démarrage, comme les secrets TOTP (non demandée
  par la fiche, nécessaire pour retirer une ancienne clé).

### Écarts

- **Vraies forges** : le statut de commit n'a été vérifié que contre des API GitHub et
  GitLab simulées ; l'essai sur une vraie GitHub App (permission *Commit statuses*) et un
  vrai projet GitLab (portée `api`, rôle Developer) reste une action de l'utilisateur
  (procédure de `docs/operations.md`, « Recette sur une vraie forge » et « Statut de
  commit »).
- **Vrais destinataires** : Matrix, Slack et Mattermost vérifiés par la forme des requêtes
  (tests unitaires) et un destinataire HTTP simulé ; pas d'envoi réel.
- **Objectifs de délai par sévérité** : pas de réglage dédié ni de repères sur les barres
  du délai de correction (voir Décisions).
- **Captures et audit RGAA manuel** des nouveaux écrans : non faits ici (aucun test
  temporaire de capture), contrôles automatiques passés (accessibilité, CSP, deux langues) ;
  à couvrir par l'audit du lot 2 (T18).
- **Mesure de l'aperçu** sur le jeu de référence : non faite (T18).

### ADR créés

- [0045 — Politiques en CEL, violations datées et verdict d'un instantané](../../docs/adr/0045-politiques-cel-et-verdicts.md).
- [0046 — Notifications : canaux, secrets, envois dédoublonnés et réessayés](../../docs/adr/0046-notifications.md).
- [0047 — Statut de commit publié par l'agent dépôt](../../docs/adr/0047-statut-de-commit.md).

Aucune nouvelle fonction `crossorg` (liste des organisations par
`lotor_list_organizations`, comme la réanalyse et le tableau de bord). Nouvelle dépendance
tierce : `cel.dev/cel-go` (validée), avec `github.com/antlr4-go/antlr/v4`.

### Pour la suite

- **T18** : audit RGAA des écrans des politiques, des violations et des canaux ; mesure de
  l'aperçu et de l'évaluation sur le jeu de référence ; recette d'un canal réel et du
  statut de commit sur une vraie forge.
- **T20** : rendre disponible le modèle « licence AGPL » en ajoutant les licences au
  contexte des règles de constat (`component.licenses`).
