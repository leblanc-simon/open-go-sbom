package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"leblanc.io/open-go-sbom/internal/db"
)

func mgmt(t *testing.T, checks ...Check) (http.Handler, *Readiness) {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	ready := NewReadiness(checks...)
	return NewManagementHandler(reg, ready), ready
}

func call(h http.Handler, path string) (*httptest.ResponseRecorder, readyReport) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var rep readyReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	return rec, rep
}

func TestHealthzAndMetrics(t *testing.T) {
	h, _ := mgmt(t, Check{"database", func(context.Context) error { return errors.New("down") }})
	if rec, rep := call(h, "/healthz"); rec.Code != 200 || rep.Status != "ok" {
		t.Fatalf("/healthz : %d %+v (la vivacité ne dépend pas de la base)", rec.Code, rep)
	}
	rec, _ := call(h, "/metrics")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Fatalf("/metrics : %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("en-têtes de sécurité absents de la gestion")
	}
}

func TestReadyz(t *testing.T) {
	ok := Check{"database", func(context.Context) error { return nil }}
	h, ready := mgmt(t, ok, Check{"schema", func(context.Context) error { return nil }})
	if rec, rep := call(h, "/readyz"); rec.Code != 200 || rep.Status != "ok" || rep.Checks["schema"] != "ok" {
		t.Fatalf("/readyz : %d %+v", rec.Code, rep)
	}
	ready.Drain()
	if rec, rep := call(h, "/readyz"); rec.Code != 503 || rep.Status != "draining" {
		t.Fatalf("/readyz pendant l'arrêt : %d %+v", rec.Code, rep)
	}

	h, _ = mgmt(t, ok, Check{"schema", func(context.Context) error { return errors.New("migrations en attente") }})
	if rec, rep := call(h, "/readyz"); rec.Code != 503 || rep.Checks["schema"] != "migrations en attente" || rep.Checks["database"] != "ok" {
		t.Fatalf("/readyz en échec : %d %+v", rec.Code, rep)
	}
}

// TestReadyzWhileDatabaseUnreachable : la vérification réelle de la base, sur une base
// injoignable, rend /readyz indisponible.
func TestReadyzWhileDatabaseUnreachable(t *testing.T) {
	pool, err := db.Open("postgres://u:p@127.0.0.1:1/db?connect_timeout=1", db.PoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	h, _ := mgmt(t, Check{"database", db.NewPool(pool).Ping})
	if rec, rep := call(h, "/readyz"); rec.Code != 503 || rep.Checks["database"] == "ok" {
		t.Fatalf("/readyz sans base : %d %+v", rec.Code, rep)
	}
}
