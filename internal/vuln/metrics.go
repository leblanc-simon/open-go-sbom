package vuln

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"leblanc.io/lotor/internal/db"
)

const collectTimeout = 2 * time.Second

// RegisterMetrics enregistre dans reg les métriques de la base de vulnérabilités, lues à
// chaque collecte :
//
//   - lotor_vulndb_target_age_seconds : âge (date de construction) de la base cible,
//     absente sans base ;
//   - lotor_vulndb_stale : 1 si la cible manque ou dépasse maxAge (l'alerte), 0 sinon ;
//   - lotor_vulndb_loaded : 1 si l'instance a une base chargée (manager non nil), 0 sinon.
func RegisterMetrics(reg prometheus.Registerer, pool *db.Pool, manager *Manager, maxAge time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return reg.Register(&collector{pool: pool, manager: manager, maxAge: maxAge, logger: logger, now: time.Now})
}

var (
	ageDesc    = prometheus.NewDesc("lotor_vulndb_target_age_seconds", "Age of the shared target vulnerability database.", nil, nil)
	staleDesc  = prometheus.NewDesc("lotor_vulndb_stale", "1 when the target vulnerability database is missing or older than vulndb.max_age.", nil, nil)
	loadedDesc = prometheus.NewDesc("lotor_vulndb_loaded", "1 when this worker instance has a vulnerability database loaded.", nil, nil)
)

type collector struct {
	pool    *db.Pool
	manager *Manager
	maxAge  time.Duration
	logger  *slog.Logger
	now     func() time.Time
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ageDesc
	ch <- staleDesc
	if c.manager != nil {
		ch <- loadedDesc
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	v, err := TargetVersion(ctx, c.pool.DB())
	if err != nil {
		c.logger.Warn("métriques de la base de vulnérabilités", "err", err)
	} else {
		stale := 1.0
		if !v.IsZero() {
			age := c.now().Sub(v.Built)
			ch <- prometheus.MustNewConstMetric(ageDesc, prometheus.GaugeValue, age.Seconds())
			if age <= c.maxAge {
				stale = 0
			}
		}
		ch <- prometheus.MustNewConstMetric(staleDesc, prometheus.GaugeValue, stale)
	}
	if c.manager != nil {
		loaded := 0.0
		if _, ok := c.manager.Loaded(); ok {
			loaded = 1
		}
		ch <- prometheus.MustNewConstMetric(loadedDesc, prometheus.GaugeValue, loaded)
	}
}
