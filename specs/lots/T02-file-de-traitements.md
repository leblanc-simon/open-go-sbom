# T02 — File de traitements PostgreSQL

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T01 | À faire |

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

- [ ] Un job mis en file dans une transaction annulée n'est jamais exécuté.
- [ ] Avec trois runners concurrents et sans panne, aucun job n'est exécuté deux fois et
      aucun n'est perdu.
- [ ] Un worker tué en plein job : le job est repris après expiration du bail.
- [ ] Le calendrier des réessais suit la formule documentée ; un job épuisé passe `dead`.
- [ ] Une mise en file prioritaire sur une clé déjà en attente en basse priorité relève la
      priorité du job existant.
- [ ] Une organisation au plafond n'empêche pas les jobs d'une autre de s'exécuter.
- [ ] Deux planificateurs actifs : une seule mise en file par échéance.
- [ ] `Stop` rend la main dans le délai imparti et ne laisse aucun bail actif.

## Tests attendus

Intégration PostgreSQL pour tous les critères ci-dessus, avec horloge injectable pour les
délais. Test de charge court (10 000 jobs, plusieurs workers, plusieurs organisations)
sans doublon ni perte.

## Points à trancher

Aucun s'il est confirmé en T00 (ADR 5) que la file reste maison.

## Journal

_À remplir pendant la réalisation._
