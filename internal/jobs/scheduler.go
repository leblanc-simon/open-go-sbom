package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"leblanc.io/lotor/internal/db"
)

// DefaultSchedulerInterval espace les tentatives de prise des échéances.
const DefaultSchedulerInterval = 10 * time.Second

// Schedule est une échéance récurrente : à chaque point de sa grille, une seule instance
// met Job en file.
type Schedule struct {
	// Name identifie l'échéance (« vulndb.check »), clé de la table schedules.
	Name string
	// Every est la période et Offset le décalage de la grille, en UTC : les points sont
	// Offset + k × Every depuis l'époque Unix. Every 24 h et Offset 3 h : chaque jour à
	// 03:00 UTC. Une échéance nouvelle est due tout de suite (dernier point passé).
	Every  time.Duration
	Offset time.Duration
	// Job est mis en file à chaque point, pour maintenant (RunAt est ignoré). Sans clé
	// d'unicité, il reçoit « schedule:<Name> » : des points manqués pendant une panne ne
	// s'empilent pas en jobs identiques.
	Job Job
}

func (s Schedule) validate() error {
	if err := validKind(s.Name); err != nil {
		return fmt.Errorf("jobs: nom d'échéance %q invalide", s.Name)
	}
	if s.Every < time.Second || s.Offset < 0 || s.Offset >= s.Every {
		return fmt.Errorf("jobs: échéance %s : période d'au moins 1 s et décalage dans [0, période) requis", s.Name)
	}
	_, err := s.Job.validate()
	return err
}

// lastPoint renvoie le dernier point de la grille inférieur ou égal à now.
func (s Schedule) lastPoint(now time.Time) time.Time {
	every, off := int64(s.Every), int64(s.Offset)
	n := now.UnixNano() - off
	k := n / every
	if n%every < 0 {
		k--
	}
	return time.Unix(0, k*every+off).UTC()
}

// nextPoint renvoie le premier point de la grille strictement postérieur à now.
func (s Schedule) nextPoint(now time.Time) time.Time { return s.lastPoint(now).Add(s.Every) }

// SchedulerOptions paramètre NewScheduler ; une valeur zéro prend son défaut.
type SchedulerOptions struct {
	// Interval espace les tentatives de prise : une échéance part au plus Interval après
	// son point.
	Interval time.Duration
	Clock    Clock
	Logger   *slog.Logger
	Metrics  *Metrics
}

// Scheduler met en file les jobs des échéances enregistrées. Plusieurs instances
// peuvent tourner ensemble : chaque point n'est pris que par une seule, par
// UPDATE schedules … WHERE next_run_at <= maintenant, sans verrou de session.
type Scheduler struct {
	pool *db.Pool
	o    SchedulerOptions

	mu        sync.Mutex
	schedules []Schedule
	started   bool
}

// NewScheduler prépare un planificateur ; les échéances s'enregistrent avant Run.
func NewScheduler(pool *db.Pool, o SchedulerOptions) *Scheduler {
	o.Interval = cmp(o.Interval, DefaultSchedulerInterval)
	if o.Clock == nil {
		o.Clock = SystemClock()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Scheduler{pool: pool, o: o}
}

// Register ajoute une échéance.
func (s *Scheduler) Register(sc Schedule) error {
	if err := sc.validate(); err != nil {
		return err
	}
	if sc.Job.UniqueKey == "" {
		sc.Job.UniqueKey = "schedule:" + sc.Name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("jobs: échéance %s enregistrée après Run", sc.Name)
	}
	for _, other := range s.schedules {
		if other.Name == sc.Name {
			return fmt.Errorf("jobs: échéance %s enregistrée deux fois", sc.Name)
		}
	}
	s.schedules = append(s.schedules, sc)
	return nil
}

// Run inscrit les échéances en base puis tente de les prendre toutes les Interval,
// jusqu'à l'annulation de ctx. Une erreur de prise est journalisée et retentée au tour
// suivant.
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("jobs: planificateur déjà démarré")
	}
	s.started = true
	s.mu.Unlock()
	if err := s.sync(ctx); err != nil {
		return err
	}
	t := time.NewTicker(s.o.Interval)
	defer t.Stop()
	for {
		if _, err := s.tick(ctx); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("planificateur", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// sync inscrit chaque échéance. Une échéance existante garde son prochain point, sauf si
// sa grille a changé : elle part alors au premier point de la nouvelle grille.
func (s *Scheduler) sync(ctx context.Context) error {
	now := s.o.Clock.Now()
	for _, sc := range s.schedules {
		err := s.pool.InTx(ctx, func(tx *db.Tx) error {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO schedules (name, period, phase, next_run_at, updated_at)
				VALUES ($1, make_interval(secs => $2), make_interval(secs => $3), $4, $6)
				ON CONFLICT (name) DO UPDATE SET
					period = EXCLUDED.period,
					phase = EXCLUDED.phase,
					next_run_at = CASE
						WHEN schedules.period <> EXCLUDED.period OR schedules.phase <> EXCLUDED.phase THEN $5
						ELSE schedules.next_run_at END,
					updated_at = EXCLUDED.updated_at`,
				sc.Name, sc.Every.Seconds(), sc.Offset.Seconds(), sc.lastPoint(now), sc.nextPoint(now), now)
			return err
		})
		if err != nil {
			return fmt.Errorf("jobs: inscription de l'échéance %s : %w", sc.Name, err)
		}
	}
	return nil
}

// tick tente de prendre chaque échéance due et renvoie le nombre d'échéances prises.
// La prise et la mise en file partagent une transaction : une instance qui tombe entre
// les deux ne perd pas le point.
func (s *Scheduler) tick(ctx context.Context) (int, error) {
	fired := 0
	var errs []error
	for _, sc := range s.schedules {
		var took bool
		err := s.pool.InTx(ctx, func(tx *db.Tx) error {
			now := s.o.Clock.Now()
			res, err := tx.ExecContext(ctx, `
				UPDATE schedules SET next_run_at = $2, last_run_at = $3, updated_at = $3
				WHERE name = $1 AND next_run_at <= $3`, sc.Name, sc.nextPoint(now), now)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil || n == 0 {
				return err
			}
			job := sc.Job
			job.RunAt = now
			if _, err := Enqueue(ctx, tx, job); err != nil {
				return err
			}
			took = true
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("jobs: échéance %s : %w", sc.Name, err))
			continue
		}
		if took {
			fired++
			s.o.Metrics.observeFire(sc.Name)
			s.o.Logger.Info("échéance prise", "schedule", sc.Name, "kind", sc.Job.Kind)
		}
	}
	return fired, errors.Join(errs...)
}
