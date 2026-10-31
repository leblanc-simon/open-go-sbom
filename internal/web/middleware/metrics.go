package middleware

import (
	"net/http"
	"strconv"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

// HTTPMetrics compte les requêtes et mesure leur durée, par groupe de routes, méthode,
// motif de route et statut.
type HTTPMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewHTTPMetrics enregistre les métriques HTTP dans reg.
func NewHTTPMetrics(reg prometheus.Registerer) *HTTPMetrics {
	m := &HTTPMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lotor", Subsystem: "http", Name: "requests_total",
			Help: "HTTP requests served, by route group, method, route pattern and status code.",
		}, []string{"group", "method", "route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "lotor", Subsystem: "http", Name: "request_duration_seconds",
			Help:    "HTTP request duration, by route group, method and route pattern.",
			Buckets: prometheus.DefBuckets,
		}, []string{"group", "method", "route"}),
	}
	reg.MustRegister(m.requests, m.duration)
	return m
}

// Middleware mesure les requêtes d'un groupe de routes.
func (m *HTTPMetrics) Middleware(group string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			method := methodLabel(r.Method)
			route := routePattern(r)
			m.requests.WithLabelValues(group, method, route, strconv.Itoa(status)).Inc()
			m.duration.WithLabelValues(group, method, route).Observe(time.Since(start).Seconds())
		})
	}
}

// methodLabel borne la cardinalité : une méthode inventée par un client compte pour
// « other ».
func methodLabel(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return m
	default:
		return "other"
	}
}
