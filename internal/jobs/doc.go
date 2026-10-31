// Package jobs implémente la file de traitements sur PostgreSQL (tables globales jobs et
// schedules) et le planificateur d'échéances, sans dépendance (ADR 0005 et 0011).
//
// # Mise en file
//
// Un job se met en file dans la transaction qui produit la donnée qui le motive : il
// n'existe que si elle est validée.
//
//	err := pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
//		// … enregistre l'ingestion …
//		_, err := jobs.Enqueue(ctx, tx, jobs.Job{
//			Kind:      "ingest.decode",
//			Payload:   decodePayload{IngestionID: id}, // une référence, jamais le document
//			Priority:  jobs.PriorityHigh,
//			UniqueKey: "ingestion:" + id.String(),
//		})
//		return err
//	})
//
// Dans une transaction InOrg, Job.OrgID vaut par défaut l'organisation de la transaction
// (ErrOrgMismatch si une autre est donnée). La clé d'unicité dédoublonne les jobs en
// attente du même type : une seconde mise en file garde la plus haute priorité et
// l'échéance la plus proche, ainsi que la charge du job existant. La charge (16 Kio au
// plus) ne contient donc que des références que le handler relit en base.
//
// # Exécution
//
// La sémantique est « au moins une fois » : un job peut s'exécuter deux fois (bail expiré
// pendant qu'il finissait, arrêt). Tout handler est idempotent, ce qui se vérifie en revue
// et par un test qui l'exécute deux fois. Un handler qui touche des données
// d'organisation travaille dans InOrg(e.OrgID) ; la table jobs, globale, n'a pas de RLS.
//
//	runner := jobs.NewRunner(pool, jobs.RunnerOptions{Concurrency: 4, Logger: logger, Metrics: m})
//	err := runner.Register("ingest.decode", jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
//		var p decodePayload
//		if err := e.Decode(&p); err != nil {
//			return err // erreur permanente : le job passe dead
//		}
//		return pool.InOrg(ctx, e.OrgID, func(tx *db.OrgTx) error { … })
//	}), jobs.WithOrgLimit(2), jobs.WithTimeout(10*time.Minute))
//	err = runner.Run(ctx) // jusqu'à l'annulation de ctx, puis Stop
//
// Un worker prend le job le plus prioritaire, puis le plus ancien (FOR UPDATE SKIP
// LOCKED), pose un bail renouvelé au tiers de sa durée, et appelle le handler. WithOrgLimit
// plafonne les jobs simultanés d'un type pour une même organisation, toutes instances
// confondues. Une erreur programme un nouvel essai à
// min(base × 2^(n−1), max) × (1 + gigue × u) (Backoff) ; après MaxAttempts tentatives, ou
// sur une erreur marquée Permanent, le job passe dead avec sa dernière erreur. Une
// panique est un échec ordinaire.
//
// Stop cesse de prendre du travail, attend les jobs en cours et, à l'approche de son
// délai, annule leurs handlers et remet leurs jobs en attente sans compter la tentative :
// il rend la main dans le délai et ne laisse aucun bail actif.
//
// # Échéances
//
//	s := jobs.NewScheduler(pool, jobs.SchedulerOptions{Logger: logger, Metrics: m})
//	err := s.Register(jobs.Schedule{Name: "vulndb.check", Every: time.Hour, Job: jobs.Job{Kind: "vulndb.check"}})
//	err = s.Run(ctx)
//
// Les points d'une échéance forment une grille fixe en UTC (Offset + k × Every). Chaque
// instance tente UPDATE schedules … WHERE next_run_at <= maintenant ; une seule obtient la
// ligne et met le job en file dans la même transaction. Sans verrou de session, donc
// robuste aux coupures et à pgbouncer.
//
// # Administration
//
// ListDead, Retry et Discard servent l'écran d'administration (T11), dans la transaction
// de l'appelant. Les jobs terminés sont purgés au-delà de RunnerOptions.Retention ; les
// jobs morts restent jusqu'à leur relance ou leur suppression.
//
// # Horloge
//
// Toutes les dates sont calculées en Go avec RunnerOptions.Clock et
// SchedulerOptions.Clock, que les tests remplacent pour avancer le temps ; Enqueue et
// Retry prennent l'horloge du système. Les instances ont des horloges synchronisées.
package jobs
