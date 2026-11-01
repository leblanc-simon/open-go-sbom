package repoagent

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"leblanc.io/lotor/internal/forge"
)

func statusAgent(t *testing.T, srv *fakeServer, f *fakeForge, cfg StatusConfig) (*Agent, tracked) {
	t.Helper()
	a := newTestAgent(t, srv, f, io.Discard, func(o *Options) { o.Status = cfg })
	return a, tracked{project: Project{ID: "p1", Slug: "app"}, ref: TrackedRef{Ref: mainRef}, forge: f, repo: "acme/app"}
}

func TestReportStatusPublishesPendingThenVerdict(t *testing.T) {
	for _, c := range []struct {
		verdict Verdict
		want    forge.StatusState
	}{
		{Verdict{State: VerdictFail, Summary: "Non conforme", URL: "https://sbom.example.org/x"}, forge.StatusFailure},
		{Verdict{State: VerdictPass, Summary: "Conforme"}, forge.StatusSuccess},
		{Verdict{State: VerdictError, Summary: "SBOM refusé"}, forge.StatusError},
	} {
		srv := &fakeServer{verdicts: []Verdict{{State: VerdictPending}, {State: VerdictPending, Summary: "En cours"},
			{State: VerdictPending, Summary: "En cours"}, c.verdict}}
		f := &fakeForge{name: "fake"}
		a, tr := statusAgent(t, srv, f, StatusConfig{Enabled: true, Context: "lotor", Timeout: 10 * time.Second, Poll: time.Millisecond})
		a.reportStatus(context.Background(), tr, commitN(7), Receipt{IngestionID: "i"})
		got := f.published()
		if len(got) != 2 {
			t.Fatalf("%s : statuts %+v", c.want, got)
		}
		if got[0].Status.State != forge.StatusPending || got[0].Status.Description != "En cours" || got[0].Commit != commitN(7) {
			t.Errorf("premier statut %+v", got[0])
		}
		last := got[1].Status
		if last.State != c.want || last.Description != c.verdict.Summary || last.TargetURL != c.verdict.URL || last.Context != "lotor" {
			t.Errorf("verdict publié %+v", last)
		}
	}
}

func TestReportStatusTimeoutLeavesPending(t *testing.T) {
	srv := &fakeServer{verdicts: []Verdict{{State: VerdictPending, Summary: "En cours"}}}
	f := &fakeForge{name: "fake"}
	a, tr := statusAgent(t, srv, f, StatusConfig{Enabled: true, Context: "lotor", Timeout: 500 * time.Millisecond, Poll: time.Millisecond})
	a.reportStatus(context.Background(), tr, commitN(8), Receipt{IngestionID: "i"})
	got := f.published()
	if len(got) != 1 || got[0].Status.State != forge.StatusPending {
		t.Fatalf("statuts %+v", got)
	}
	if srv.verdictCalls < 2 {
		t.Fatalf("verdict interrogé %d fois", srv.verdictCalls)
	}
}

func TestReportStatusDisabledOrFailing(t *testing.T) {
	srv := &fakeServer{}
	f := &fakeForge{name: "fake"}
	a, tr := statusAgent(t, srv, f, StatusConfig{})
	a.reportStatus(context.Background(), tr, commitN(9), Receipt{})
	if len(f.published()) != 0 || srv.verdictCalls != 0 {
		t.Fatal("statut publié alors que désactivé")
	}
	// Une forge qui refuse ne fait pas échouer l'agent.
	f.statusErr = forge.ErrDenied
	a, tr = statusAgent(t, srv, f, StatusConfig{Enabled: true, Context: "lotor", Timeout: time.Second, Poll: time.Millisecond})
	a.reportStatus(context.Background(), tr, commitN(9), Receipt{})
	if !errors.Is(f.statusErr, forge.ErrDenied) || srv.verdictCalls != 1 {
		t.Fatalf("appels %d", srv.verdictCalls)
	}
}
