package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"leblanc.io/open-go-sbom/internal/db"
)

// Issues d'une exécution, étiquette outcome de ogsbom_job_runs_total.
const (
	outcomeDone     = "done"     // terminé
	outcomeRetry    = "retry"    // échec, nouvel essai programmé
	outcomeDead     = "dead"     // échec définitif
	outcomeLost     = "lost"     // bail perdu, résultat ignoré
	outcomeReleased = "released" // interrompu par l'arrêt, remis en attente
)

// collectTimeout borne la lecture de l'état de la file à chaque collecte.
const collectTimeout = 2 * time.Second

// Metrics expose les métriques de la file. Une valeur nil est admise et n'enregistre
// rien.
type Metrics struct {
	runs     *prometheus.CounterVec
	duration *prometheus.HistogramVec
	fires    *prometheus.CounterVec
}

// NewMetrics enregistre les métriques de la file dans reg :
//
//   - ogsbom_jobs{kind, status} : jobs en attente (pending), en cours (running) et morts
//     (dead), lus en base à chaque collecte, donc identiques sur toutes les instances ;
//   - ogsbom_job_runs_total{kind, outcome} : exécutions de l'instance par issue (done,
//     retry et dead pour les échecs, lost, released) ;
//   - ogsbom_job_duration_seconds{kind} : durée des exécutions de l'instance ;
//   - ogsbom_job_schedule_fires_total{schedule} : échéances prises par l'instance.
func NewMetrics(reg prometheus.Registerer, pool *db.Pool, logger *slog.Logger) (*Metrics, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	m := &Metrics{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ogsbom_job_runs_total",
			Help: "Job executions on this instance by kind and outcome (done, retry, dead, lost, released).",
		}, []string{"kind", "outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ogsbom_job_duration_seconds",
			Help:    "Duration of job executions on this instance.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 900},
		}, []string{"kind"}),
		fires: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ogsbom_job_schedule_fires_total",
			Help: "Schedule occurrences taken by this instance.",
		}, []string{"schedule"}),
	}
	for _, c := range []prometheus.Collector{m.runs, m.duration, m.fires, newQueueCollector(pool, logger)} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Metrics) observeRun(kind, outcome string) {
	if m != nil {
		m.runs.WithLabelValues(kind, outcome).Inc()
	}
}

func (m *Metrics) observeDuration(kind string, d time.Duration) {
	if m != nil {
		m.duration.WithLabelValues(kind).Observe(d.Seconds())
	}
}

func (m *Metrics) observeFire(schedule string) {
	if m != nil {
		m.fires.WithLabelValues(schedule).Inc()
	}
}

// queueCollector lit l'état de la file à chaque collecte. En cas d'erreur, la série est
// absente de la collecte et l'erreur est journalisée : /metrics reste disponible.
type queueCollector struct {
	pool *db.Pool
	log  *slog.Logger
	desc *prometheus.Desc
}

func newQueueCollector(pool *db.Pool, logger *slog.Logger) *queueCollector {
	return &queueCollector{pool: pool, log: logger, desc: prometheus.NewDesc("ogsbom_jobs",
		"Jobs in the queue by kind and status (pending, running, dead), shared by all instances.",
		[]string{"kind", "status"}, nil)}
}

func (q *queueCollector) Describe(ch chan<- *prometheus.Desc) { ch <- q.desc }

func (q *queueCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	type row struct {
		kind, status string
		n            float64
	}
	var rows []row
	err := q.pool.InTx(ctx, func(tx *db.Tx) error {
		rs, err := tx.QueryContext(ctx, `
			SELECT kind, status, count(*) FROM jobs
			WHERE status IN ('pending', 'running', 'dead')
			GROUP BY kind, status`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.kind, &r.status, &r.n); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	}, db.ReadOnly())
	if err != nil {
		q.log.Warn("métriques de la file", "err", err)
		return
	}
	for _, r := range rows {
		ch <- prometheus.MustNewConstMetric(q.desc, prometheus.GaugeValue, r.n, r.kind, r.status)
	}
}
