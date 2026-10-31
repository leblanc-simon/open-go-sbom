# T02 — File de traitements PostgreSQL

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T01 | Terminé |

## Objectif

Une file de traitements durable, sans dépendance, sur laquelle reposent l'ingestion,
l'analyse, la réanalyse quotidienne, les statistiques et plus tard les notifications.

## Périmètre

**Inclus** : tables `jobs` et `schedules`, mise en file transactionnelle, workers, baux,
réessais, état `dead`, clés d'unicité avec relèvement de priorité, plafond par
organisation, planificateur, métriques, arrêt propre. Fonctions d'administration
(`ListDead`, `Retry`, `Discard`) sans écran.

**Exclu** : l'écran d'administration (T11), les handlers métier (lots suivants).

## Conception

- Sémantique **au moins une fois** : un job peut s'exécuter deux fois (bail expiré pendant
  qu'il finissait). Tout handler est donc idempotent ; c'est vérifié en revue et par test.
- `jobs.Enqueue(ctx, tx, jobs.Job{Kind, OrgID, Payload, Priority, UniqueKey, RunAt})`
  s'exécute **dans la transaction de l'appelant** : un job n'existe que si la donnée qui le
  motive a été validée.
- Prise : `SELECT … FOR UPDATE SKIP LOCKED` ordonné par priorité puis échéance, en excluant
  les organisations qui ont atteint leur plafond pour ce type ; bail `locked_until` posé
  dans la même transaction et renouvelé tant que le handler tourne.
- Échec : tentative incrémentée, prochaine exécution à `base × 2^n` plus gigue, plafonnée ;
  au-delà de `max_attempts`, statut `dead` et dernière erreur conservée.
- Unicité : index unique partiel sur `unique_key` des jobs en attente ; une seconde mise en
  file fait `ON CONFLICT … DO UPDATE` qui garde la plus haute priorité et l'échéance la plus
  proche. La charge utile ne doit donc rien contenir que le handler ne puisse relire en base
  (par exemple « la référence », pas « l'instantané »).
- `jobs.Runner` : registre `Register(kind, Handler)`, nombre de workers, plafonds par
  organisation et par type, `Stop(ctx)` qui cesse de prendre du travail, attend les jobs en
  cours puis libère leurs baux.
- Planificateur : une ligne par échéance dans `schedules` (nom, intervalle, prochaine
  exécution). Chaque instance tente régulièrement
  `UPDATE schedules SET next_run_at = now() + interval WHERE name = $1 AND next_run_at <= now()
  RETURNING …` ; seule celle qui obtient la ligne met le travail en file. Aucun verrou de
  session : robuste aux coupures et à pgbouncer.
- Nettoyage des jobs terminés au-delà d'une durée de rétention configurable.
- Métriques par type : en attente, en cours, échecs, morts, durée d'exécution.

## Livrables

Paquet `internal/jobs`, migrations, documentation d'usage dans `doc.go`, section
« Traitements » de `docs/operations.md`.

## Critères d'acceptation

- [x] Un job mis en file dans une transaction annulée n'est jamais exécuté.
- [x] Avec trois runners concurrents et sans panne, aucun job n'est exécuté deux fois et
      aucun n'est perdu.
- [x] Un worker tué en plein job : le job est repris après expiration du bail.
- [x] Le calendrier des réessais suit la formule documentée ; un job épuisé passe `dead`.
- [x] Une mise en file prioritaire sur une clé déjà en attente en basse priorité relève la
      priorité du job existant.
- [x] Une organisation au plafond n'empêche pas les jobs d'une autre de s'exécuter.
- [x] Deux planificateurs actifs : une seule mise en file par échéance.
- [x] `Stop` rend la main dans le délai imparti et ne laisse aucun bail actif.

## Tests attendus

Intégration PostgreSQL pour tous les critères ci-dessus, avec horloge injectable pour les
délais. Test de charge court (10 000 jobs, plusieurs workers, plusieurs organisations)
sans doublon ni perte.

## Décisions

- File maison, sans dépendance (ADR 5 de T00).

## Journal

Réalisé le 31 octobre 2026, branche `lot/T02-file-de-traitements`.

### Livré

- Migration `002_jobs.sql` : tables globales `jobs` (statuts `pending`, `running`,
  `done`, `dead` ; bail `locked_until` + `lease_token` ; contraintes de cohérence statut ↔
  bail ↔ fin) et `schedules` (période, décalage de grille, prochain point) ; index
  partiels de prise, de jobs en cours, d'unicité (`kind`, `unique_key`) des jobs en
  attente, de purge et de liste des morts.
- `internal/jobs` :
  - `Enqueue(ctx, db.Querier, Job)` dans la transaction de l'appelant ; organisation
    reprise d'une transaction `InOrg` (`ErrOrgMismatch` sinon) ; clé d'unicité qui relève
    priorité et échéance, sans jamais fusionner deux organisations
    (`ErrUniqueKeyConflict`) ; charge JSON bornée à 16 Kio ; priorités `PriorityLow`,
    `PriorityNormal`, `PriorityHigh` dans [−1000, 1000].
  - `Runner` : `Register(kind, Handler, WithOrgLimit(n), WithTimeout(d))`, `Start`,
    `Stop(ctx)`, `Run(ctx)` ; prise `FOR UPDATE SKIP LOCKED` (baux expirés d'abord,
    puis jobs en attente par l'index) ; plafond strict par (type, organisation) ; bail
    renouvelé au tiers de sa durée, perte de bail détectée (handler annulé, résultat
    ignoré) ; réessais `Backoff` (`min(base × 2^(n−1), max) × (1 + gigue × u)`) ;
    `Permanent(err)` ; panique récupérée ; maintenance (jobs épuisés au bail expiré →
    `dead`, purge des terminés au-delà de la rétention) ; arrêt qui libère les baux.
  - `Execution` (charge, organisation, tentative) et `Execution.Decode` (champ inconnu →
    erreur permanente).
  - `Scheduler` : `Register(Schedule{Name, Every, Offset, Job})`, `Run(ctx)` ; grille UTC
    fixe ; prise par `UPDATE … WHERE next_run_at <= maintenant` et mise en file dans la
    même transaction ; clé d'unicité par défaut `schedule:<nom>`.
  - Administration sans écran : `ListDead` (paginée), `Retry`, `Discard`, dans la
    transaction de l'appelant.
  - Métriques : `lotor_jobs{kind,status}` (lu en base à la collecte),
    `lotor_job_runs_total{kind,outcome}`, `lotor_job_duration_seconds{kind}`,
    `lotor_job_schedule_fires_total{schedule}`.
  - `Clock`, `ClockFunc`, `SystemClock()` : horloge injectable.
- Configuration : fragment `Workers` (`enabled`, `concurrency`, `poll_interval`, `lease`,
  `retry_base`, `retry_max`, `retention`, `schedule_interval`, `shutdown_timeout`),
  validé, documenté dans `config.example.yaml`.
- `cmd/lotor-server` : métriques de la file, runner et planificateur si
  `workers.enabled`, lancés avec le serveur web et arrêtés ensemble sur SIGTERM
  (`runAll`).
- Documentation : `doc.go` du paquet, section « Traitements » et « Arrêt » de
  `docs/operations.md`, ADR 0011, § 6 et § 16 de `architecture.md`.

### Décisions

- ADR 0011 **[à relire]**, en particulier :
  - horloge Go injectable pour toutes les dates de la file (pas de `now()` SQL), d'où
    l'exigence d'instances synchronisées par NTP ; `Enqueue` et `Retry` prennent
    l'horloge du système ;
  - transitions d'état du runner en `synchronous_commit = off` (prise, bail, fin) : une
    panne de PostgreSQL juste après ne fait que rejouer un job (2,0 ms contre 3,4 ms par
    prise et fin en local) ;
  - prise en deux requêtes (baux expirés d'abord) pour parcourir l'index des jobs en
    attente : une requête unique avec `OR` triait tous les jobs à chaque prise ;
  - plafond strict par verrou consultatif **de transaction** (pas de session) ;
  - `Stop` : au quart du délai restant (au plus 2 s) avant l'échéance, annulation des
    handlers et remise en attente **sans compter la tentative** ;
  - un job remis en attente qui heurte un jumeau de même clé en attente s'efface devant
    lui ; une mise en file pendant l'exécution d'un job de même clé crée un nouveau job ;
  - la tentative est comptée à la prise (un job qui tue son worker finit `dead`) ;
  - grille d'échéances fixe en UTC, une échéance nouvelle est due tout de suite, points
    manqués rattrapés une seule fois ;
  - jobs `dead` conservés sans limite (relance ou suppression par l'administrateur).
- Valeurs par défaut **[à relire]** : 4 workers, scrutation 1 s, bail 30 s, réessais 10 s
  → 30 min avec 20 % de gigue, 10 tentatives, rétention 7 jours, planificateur toutes les
  10 s, arrêt 30 s, maintenance chaque minute.
- Clé d'unicité sur (`kind`, `unique_key`) et non sur `unique_key` seule : deux types ne
  partagent jamais un job par erreur de nommage de clé.
- `workers.enabled` sans `env-default` : le défaut est posé par `config.Defaults`, sinon
  `enabled: false` dans le fichier serait écrasé par le défaut (voir `lecons.md`).
- Le plafond par organisation n'a pas de réglage de configuration : aucun type ne
  l'emploie encore (règle « aucune variable sans effet »). T05 et T06 le fixeront.
- Aucune nouvelle dépendance ; `prometheus/client_golang/prometheus/testutil` (même
  module) sert aux tests.

### Écarts

- `internal/db/pool.go` (T01) : `PoolConfig.MaxIdleConns` nul appelait
  `SetMaxIdleConns(0)`, qui ne garde **aucune** connexion inactive ; tous les pools de
  `dbtest` rouvraient une connexion (et une authentification SCRAM) par transaction,
  soit environ 12 ms par transaction en test. Corrigé : nul garde le défaut de
  `database/sql`, et `dbtest` garde ses connexions. La configuration du serveur
  (`max_idle_conns: 10`) n'était pas touchée.
- `internal/db/db_integration_test.go` (T01) : les migrations de test étaient nommées
  `002_*.sql` en dur, ce qui cassait dès la première vraie migration 002. Elles
  s'écrivent désormais `+N_sujet.sql` (N-ième numéro libre). Le cas « table globale à
  `org_id` facultatif » créait une table `jobs`, renommée `global_probe`.
- La fiche parle d'un index unique sur `unique_key` : il porte sur (`kind`,
  `unique_key`) (voir Décisions).

### ADR créés

0011.

### Mesures

- Prise et fin d'un job : 2,0 ms (une connexion, sans `-race`, PostgreSQL 16 local).
- Test de charge : 10 000 jobs, 3 runners × 8 workers, 10 organisations, moitié d'un type
  plafonné à 3 par organisation : 23,6 s soit 424 jobs/s sans `-race` (4 cœurs, la base
  sur la même machine) ; environ 36 s avec `-race` pendant les autres tests. Aucun
  doublon, aucune perte, plafond jamais dépassé.
- Couverture (unitaires et intégration) : `jobs` 90 %, `config` 96 %, `db` 85 %.

### Pour les lots suivants

- Un handler est idempotent, relit en base ce que la charge référence, travaille dans
  `pool.InOrg(ctx, e.OrgID, …)` et respecte l'annulation de `ctx`. Son test l'exécute
  deux fois.
- Enregistrer les types dans `cmd/lotor-server/main.go` avant `runner.Run` (bloc
  `if cfg.Workers.Enabled`), avec `jobs.WithOrgLimit` pour `ingest.decode` et
  `analysis.ref` (T05, T06 : ajouter le réglage `workers.org_limit` à ce moment-là).
- Échéances (`vulndb.check` en T06, statistiques quotidiennes en T10) : `scheduler.Register`
  au même endroit. Le job d'une échéance a par défaut la clé `schedule:<nom>`.
- `jobs.org_id` n'a pas de clé étrangère (la table `organizations` arrive en T03) ; une
  migration ultérieure peut ajouter `REFERENCES organizations (id) ON DELETE CASCADE`.
- Tests : horloge `fakeClock` (dans les tests d'intégration du paquet) qui part une heure
  après l'heure réelle, car `Enqueue` date les jobs avec l'horloge du système.
- Écran d'administration (T11) : `jobs.ListDead`, `Retry`, `Discard` dans une
  transaction `InTx` qui écrit aussi l'entrée d'audit.
