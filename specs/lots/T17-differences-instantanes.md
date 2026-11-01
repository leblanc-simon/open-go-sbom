# T17 — Différences d'instantanés

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | Terminé |

## Objectif

Montrer ce qui a changé entre deux instantanés d'une référence, et garder un historique dont
la taille est maîtrisée.

## Périmètre

**Inclus**

- Calcul de la différence entre l'ensemble d'inventaire d'un instantané et celui du
  précédent : composants ajoutés, retirés, montés ou descendus de version (comparaison par
  `version`), stockée par couple d'ensembles (deux instantanés au même ensemble n'ont
  aucune différence à calculer).
- Différence entre deux instantanés quelconques, à la demande.
- Effet sur la sécurité : constats introduits et résolus par un instantané.
- Écrans : frise des instantanés d'une référence, comparaison de deux instantanés.
- Rétention configurable des anciens instantanés (nombre ou durée, avec conservation d'un
  instantané par mois au-delà) et nettoyage par job des ensembles d'inventaire et des blobs
  devenus orphelins.
- Routes d'API correspondantes.

**Exclu** : recherche à une date passée (T21), qui s'appuie sur cette rétention.

## Conception

- Deux composants de même `purl_base` et de versions différentes forment une montée ou une
  descente, pas un ajout plus un retrait.
- La rétention ne supprime jamais le dernier instantané d'une référence, ni un ensemble ou
  un blob encore référencé.

## Livrables

Migrations, calcul, écrans, job de rétention, documentation de la rétention.

## Critères d'acceptation

- [x] Les quatre catégories de changement sont correctes sur un jeu construit à la main
      (`TestClassifyFourKinds`, `TestDiffsOfConsecutiveSnapshots`).
- [x] Une montée de version qui corrige une CVE apparaît comme « constat résolu »
      (`TestUpgradeFixingCVEIsResolvedFinding`, écran et API dans
      `TestSnapshotComparisonScreensAndAPI`).
- [x] La rétention garde un instantané par mois au-delà de la fenêtre et supprime les
      ensembles et blobs orphelins, et eux seuls (`TestRetentionKeepsOnePerMonthAndOrphansOnly`,
      horloge simulée).

## Tests attendus

Tables de différences ; intégration de la rétention avec horloge simulée ; isolement.

## Décisions

Prises le 1er novembre 2026 :

- Rétention par défaut : tous les instantanés sont gardés 90 jours, puis un par mois, sans
  limite de durée ; le dernier instantané d'une référence n'est jamais supprimé.

## Journal

Réalisé le 1er novembre 2026, branche `lot/T17-differences-instantanes`, en autonomie
(lot 2 enchaîné sans attendre l'utilisateur), en parallèle de T12, T13 et T14 : les
décisions marquées **[à relire]** n'ont pas été validées explicitement.

### Livré

- Migration **017** (`017_snapshot_history.sql`) : tables d'organisation `set_diffs`,
  `set_diff_items` (différence par couple d'ensembles, cascade avec les ensembles) et
  `snapshot_retention` (horizon et bilan du dernier passage), sous la RLS standard et
  ajoutées au harnais SQL ; `findings.snapshot_id` et `finding_events.snapshot_id`
  facultatifs, `ON DELETE SET NULL (snapshot_id)` ; index des contrôles de clés
  étrangères et des recherches d'orphelins.
- `internal/inventory` : différences (`diff.go` : appariement par `purl_base` et version,
  `ComputeDiff`, `StoredDiff`), service `History` (`history.go` : job `inventory.diff`,
  `ComputeMissing`, `Diff` paginé et filtrable, `Choices`), rétention (`retention.go` :
  `RetentionPolicy`, jobs `retention.snapshots_all` et `retention.snapshots_org`,
  échéance quotidienne à 02:30 UTC, `Retain`, `ReadRetention`) ; la lecture d'un
  instantané donne son précédent et ses changements ; `Store` met `inventory.diff` en file
  et verrouille l'ensemble réutilisé (`FOR KEY SHARE`).
- `internal/ingest` : le SBOM réutilisé est verrouillé (`FOR KEY SHARE`) et restocké s'il
  vient d'être supprimé.
- `internal/finding` : `SnapshotEffect` / `Service.Effect` (constats introduits et
  résolus, analyse en attente).
- Configuration `retention.*` (`enabled`, `days`, `count`, `monthly`), validée, documentée
  dans `config.example.yaml`.
- `internal/web` : frise (changements depuis le précédent, lien de comparaison, rappel de
  la politique de rétention), formulaire « Comparer deux instantanés », écran
  `/o/{slug}/projects/{project}/compare` (décomptes, effet sur la sécurité, changements
  filtrés par nature et paginés, inversion), changements sur la fiche d'un instantané ;
  composant CSS `change.css` ; traductions FR et EN.
- `internal/api` : `GET /api/v1/orgs/{org}/projects/{project}/snapshots`
  (`listProjectSnapshots`) et `GET …/compare` (`compareSnapshots`), contrat dans
  `api/openapi.yaml`, code régénéré.
- Docs : ADR 0038 et 0039 ; `architecture.md` (§ 3, § 6, § 8) ; `docs/operations.md`
  (« Rétention des instantanés ») ; `docs/utilisation.md` (« Historique et comparaison
  des instantanés ») ; fiche T21 (horizon de la rétention) ; `CHANGELOG.md` ; `doc.go`
  d'`inventory` et de `finding`.

### Tests

- Unitaires : `TestClassifyFourKinds` (montée et descente que l'ordre des chaînes
  inverserait, ajout, retrait), `TestClassifySameBaseIsNotAddPlusRemove` (couples dans
  l'ordre, même version aux qualificatifs changés, versions incomparables),
  `TestClassifyIsOrderIndependent`, ordre et curseur ; configuration.
- Intégration `inventory` : `TestDiffsOfConsecutiveSnapshots` (job, frise avant et après
  calcul, comparaison enregistrée, à la demande, à rebours, même ensemble, filtre,
  pagination, erreurs, isolement entre organisations), `TestDiffJobHandler`,
  `TestRetentionKeepsOnePerMonthAndOrphansOnly` (dix instantanés sur six mois, horloge
  simulée : dernier de chaque mois, instantané en vigueur à la coupure, dernière analyse,
  courant ; ensembles partagés et SBOM encore référencés gardés ; réceptions ; constat
  sans instantané ; différences recalculées ; horizon ; second passage sans effet ;
  autre organisation intacte), `TestRetentionPolicyVariants` (nombre, sans mois,
  désactivée), `TestRetentionKeepsRecentlyReceivedAndLastSnapshot`,
  `TestOrphanDeletionSkipsSetLockedByIngestion`, `TestEnqueueRetentionCoversEveryOrganization`.
- Intégration `finding` : `TestUpgradeFixingCVEIsResolvedFinding` (montée qui corrige la
  CVE, vulnérabilité présente des deux côtés ni résolue ni introduite, chemin inverse,
  `not_matched` exclu, analyse en attente, isolement).
- Intégration `web` : `TestSnapshotComparisonScreensAndAPI` (frise, comparaison, premier
  instantané, inverse, deux langues, accessibilité et CSP, erreurs 400 et 404, membre
  d'une autre équipe en 404, API et ses erreurs RFC 9457) ; la nouvelle route entre
  d'elle-même dans `TestEveryOrgRouteAnswers404ToAnotherOrganization` et
  `TestRoutePermissionsFollowMatrix` ; harnais RLS étendu aux trois tables.
- Vérifiés en cassant le code (leçon de T16) : sans la règle du dernier de chaque mois,
  les deux tests de rétention échouent ; sans la règle « vulnérabilité présente des deux
  côtés », le test de l'effet échoue ; sans `SKIP LOCKED`, la suppression des orphelins
  attend l'ingestion (le test borne désormais l'attente pour échouer au lieu de bloquer).

### Décisions

Décision de la fiche appliquée telle quelle : tout garder 90 jours, puis un instantané
par mois, sans limite de durée ; jamais le dernier d'une référence. Décisions prises
pendant le lot, toutes **[à relire]** :

- **Différences enregistrées pour les seuls couples d'instantanés consécutifs**, par un
  job séparé mis en file par l'ingestion ; comparaison quelconque calculée à la demande,
  non enregistrée ([ADR 0038](../../docs/adr/0038-differences-d-instantanes.md)).
- **Appariement par `purl_base`** : versions triées par écosystème puis appariées dans
  l'ordre ; même version aux qualificatifs changés = retrait + ajout ; versions
  incomparables ordonnées par chaîne et marquées « approché » (ADR 0038).
- **Effet sur la sécurité calculé à la lecture**, par `purl_base` et vulnérabilité, sans
  les constats `not_matched`, borné à 200 de chaque côté, signalé incomplet si
  l'instantané courant n'est pas analysé (ADR 0038).
- **« Un par mois » = le dernier instantané du mois (UTC)**, et l'instantané en vigueur
  au début de la fenêtre est toujours gardé, même sans `monthly`
  ([ADR 0039](../../docs/adr/0039-retention-des-instantanes.md)).
- **Fenêtre sur la date de scan et la date de réception** : un instantané envoyé en
  retard reste au moins `days` jours ; l'instantané de la dernière analyse est gardé
  (ADR 0039).
- **Réglages** : `retention.enabled`, `days` (90, au moins 1), `count` (0, en plus de la
  fenêtre), `monthly` (vrai) ; « nombre ou durée » de la fiche réalisé par `count` en plus
  de `days` (ADR 0039).
- **Réceptions terminées hors fenêtre supprimées** (journal de réception ; sinon une
  réception en échec retiendrait son SBOM) ; **orphelins supprimés même rétention
  désactivée** ; **composants jamais purgés** (ADR 0039).
- **Constat sans instantané** : `findings.snapshot_id` et `finding_events.snapshot_id`
  passent à nul quand la rétention supprime l'instantané, plutôt que de garder tous les
  instantanés cités par un constat (ADR 0039).
- **Concurrence ingestion / rétention** : verrou `FOR KEY SHARE` de l'ensemble et du SBOM
  réutilisés, `FOR UPDATE SKIP LOCKED` et nouvelle vérification côté rétention ;
  sélection des instantanés sous le verrou de la référence (ADR 0039).
- **Horizon enregistré** (`snapshot_retention`) pour T21, qui ne recule jamais ; la
  rétention couvre aussi les organisations archivées (ADR 0039).
- **Écrans** : la frise reste la liste existante de l'onglet Instantanés, enrichie
  (décomptes et lien), plutôt qu'une frise graphique ; comparaison en écran propre ;
  premier instantané sans précédent : avertissement en 200 plutôt qu'une erreur ; API :
  404 `error.diff.no_previous`.

### Écarts

- Captures d'écran en thèmes clair et sombre non faites : l'écran de comparaison
  réutilise panneaux, tuiles, tableaux et contrôle segmenté existants ; seul le composant
  `change.css` est nouveau (repères colorés par les jetons de couleur des deux thèmes,
  nature toujours écrite). Accessibilité vérifiée par `webtest` en deux langues ; l'audit
  RGAA du lot 2 (T18) couvrira ces écrans.
- La fiche parle d'« ensembles et blobs orphelins » : les **réceptions** terminées hors
  fenêtre sont aussi supprimées, faute de quoi aucun SBOM d'une réception ancienne ne
  deviendrait orphelin (voir Décisions).
- Le tri des constats de T14 (faux positif, non affecté) n'est pas encore pris en compte
  par l'effet sur la sécurité : à reprendre une fois T14 fusionné (T18).

### ADR créés

- [0038 — Différences d'instantanés](../../docs/adr/0038-differences-d-instantanes.md).
- [0039 — Rétention des instantanés](../../docs/adr/0039-retention-des-instantanes.md).

### Fonctions `crossorg`

Aucune nouvelle : la rétention liste les organisations par `crossorg.ListOrganizations`,
puis travaille dans `InOrg`.
