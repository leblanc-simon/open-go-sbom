package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"leblanc.io/open-go-sbom/internal/web/middleware"
)

// checkTimeout borne chaque vérification de /readyz.
const checkTimeout = 2 * time.Second

// Check est une vérification de disponibilité de /readyz.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

// Readiness tient les vérifications de /readyz et l'état d'arrêt.
type Readiness struct {
	checks   []Check
	draining atomic.Bool
}

// NewReadiness crée l'état de disponibilité.
func NewReadiness(checks ...Check) *Readiness { return &Readiness{checks: checks} }

// Drain marque l'instance comme en cours d'arrêt : /readyz répond 503 pour que le
// répartiteur cesse d'y envoyer du trafic.
func (r *Readiness) Drain() { r.draining.Store(true) }

type readyReport struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

func (r *Readiness) report(ctx context.Context) (int, readyReport) {
	if r.draining.Load() {
		return http.StatusServiceUnavailable, readyReport{Status: "draining"}
	}
	rep := readyReport{Status: "ok", Checks: map[string]string{}}
	status := http.StatusOK
	for _, c := range r.checks {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		err := c.Run(cctx)
		cancel()
		if err != nil {
			rep.Checks[c.Name] = err.Error()
			rep.Status = "unavailable"
			status = http.StatusServiceUnavailable
			continue
		}
		rep.Checks[c.Name] = "ok"
	}
	return status, rep
}

// NewManagementHandler sert /healthz, /readyz et /metrics.
func NewManagementHandler(reg *prometheus.Registry, ready *Readiness) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPAPI, NoStore: true}))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, readyReport{Status: "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		status, rep := ready.report(req.Context())
		writeJSON(w, status, rep)
	})
	r.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
