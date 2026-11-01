//go:build integration

package agent_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
)

// hostAgent inscrit un agent serveur et renvoie son principal et son inscription.
func (f fixture) hostAgent(t *testing.T, org tenant.OrgID, host string, labels map[string]string) (agent.Principal, agent.Enrollment) {
	t.Helper()
	ctx := context.Background()
	tok := f.enrollment(t, org, agent.EnrollmentInput{Labels: project.Labels{"env": "prod"}})
	p, err := f.agents.Authenticate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.agents.Enroll(ctx, p, agent.EnrollRequest{Hostname: host, Version: "1.0.0", Labels: labels}, "192.0.2.1", "r")
	if err != nil {
		t.Fatal(err)
	}
	if p, err = f.agents.Authenticate(ctx, e.Token.Plaintext); err != nil {
		t.Fatal(err)
	}
	return p, e
}

// TestEnrollmentMergesAgentLabels : les étiquettes de l'agent complètent celles du jeton,
// qui l'emportent ; des étiquettes invalides refusent l'inscription.
func TestEnrollmentMergesAgentLabels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	_, e := f.hostAgent(t, o, "srv-labels", map[string]string{"Role": "db", "env": "test"})
	p, err := f.projects.Get(ctx, o, tenant.AllTeams(), e.Project.Slug)
	if err != nil {
		t.Fatal(err)
	}
	if p.Labels["role"] != "db" || p.Labels["env"] != "prod" || len(p.Labels) != 2 {
		t.Errorf("étiquettes %v : role=db de l'agent, env=prod du jeton attendus", p.Labels)
	}
	tok := f.enrollment(t, o, agent.EnrollmentInput{})
	pr, _ := f.agents.Authenticate(ctx, tok)
	if _, err := f.agents.Enroll(ctx, pr, agent.EnrollRequest{Hostname: "srv-bad", Version: "1", Labels: map[string]string{"a=b": "x"}}, "", ""); !isKey(err, project.KeyLabelInvalid) {
		t.Errorf("étiquette invalide : %v", err)
	}
}

// TestScanRequestDeliveredOnce : « Scanner maintenant » est remis au prochain signal de
// vie, une seule fois, et journalisé ; seul un projet de serveur actif peut être scanné.
func TestScanRequestDeliveredOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-scan", nil)
	hb := agent.HeartbeatRequest{Version: "1.0.1"}
	if res, err := f.agents.Heartbeat(ctx, p, hb); err != nil || res.ScanRequested {
		t.Fatalf("sans demande : %+v %v", res, err)
	}
	if _, err := f.agents.RequestScan(ctx, f.actor, o, e.Project.Slug); err != nil {
		t.Fatal(err)
	}
	first := f.clock.Now()
	f.clock.advance(time.Minute)
	if _, err := f.agents.RequestScan(ctx, f.actor, o, e.Project.Slug); err != nil {
		t.Fatal(err)
	}
	a, _ := f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if a.ScanRequestedAt == nil || !a.ScanRequestedAt.Equal(first) {
		t.Errorf("une demande en attente garde sa date : %v, %v attendu", a.ScanRequestedAt, first)
	}
	if res, err := f.agents.Heartbeat(ctx, p, hb); err != nil || !res.ScanRequested {
		t.Fatalf("demande remise : %+v %v", res, err)
	}
	if res, err := f.agents.Heartbeat(ctx, p, hb); err != nil || res.ScanRequested {
		t.Errorf("demande remise deux fois : %+v %v", res, err)
	}
	n := 0
	for _, en := range f.actions(t, o) {
		if en.Action == audit.AgentScanRequested {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d demandes journalisées, 2 attendues", n)
	}

	repo, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, project.Input{Kind: project.KindRepo, Name: "app", Branches: []string{"main"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.RequestScan(ctx, f.actor, o, repo.Slug); !isKey(err, agent.KeyScanNotHost) {
		t.Errorf("dépôt : %v", err)
	}
	if _, err := f.agents.RequestScan(ctx, f.actor, o, "absent"); err != agent.ErrNotFound {
		t.Errorf("projet absent : %v", err)
	}
	other := f.org(t, "b")
	if _, err := f.agents.RequestScan(ctx, f.actor, other, e.Project.Slug); err != agent.ErrNotFound {
		t.Errorf("projet d'une autre organisation : %v", err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, e.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.RequestScan(ctx, f.actor, o, e.Project.Slug); !isKey(err, agent.KeyScanNotHost) {
		t.Errorf("agent désactivé (projet retiré) : %v", err)
	}
}

// TestHostContextIsStored : le contexte joint à un signal de vie est conservé ; un
// contexte invalide ou envoyé par un agent dépôt est refusé.
func TestHostContextIsStored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-ctx", nil)
	h := agent.HostContext{Hostname: "srv-ctx", OSID: "debian", OSVersion: "12", OSName: "Debian GNU/Linux 12 (bookworm)",
		Kernel: "6.1.0-26-amd64", Arch: "x86_64", ScanDuration: 42_000}
	if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1", Host: &h}); err != nil {
		t.Fatal(err)
	}
	a, _ := f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if a.Host == nil || *a.Host != h || a.HostAt == nil || a.Host.ScanDurationValue() != 42*time.Second {
		t.Errorf("contexte relu %+v (%v)", a.Host, a.HostAt)
	}
	h2 := h
	h2.Kernel = "6.1.0-27-amd64"
	if err := f.agents.RecordHost(ctx, p, h2); err != nil {
		t.Fatal(err)
	}
	if a, _ = f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID); a.Host.Kernel != h2.Kernel {
		t.Errorf("contexte d'un envoi non enregistré : %+v", a.Host)
	}
	for name, bad := range map[string]agent.HostContext{
		"retour à la ligne": {Kernel: "6.1\nX"},
		"trop long":         {Arch: string(bytes.Repeat([]byte("a"), 33))},
		"durée négative":    {ScanDuration: -1},
		"durée démesurée":   {ScanDuration: (25 * time.Hour).Milliseconds()},
	} {
		if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1", Host: &bad}); !isKey(err, agent.KeyHostContextInvalid) {
			t.Errorf("%s : %v", name, err)
		}
	}
	_, repoTok, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci", "initial", 30)
	if err != nil {
		t.Fatal(err)
	}
	rp, _ := f.agents.Authenticate(ctx, repoTok.Plaintext)
	if _, err := f.agents.Heartbeat(ctx, rp, agent.HeartbeatRequest{Version: "1", Host: &h}); !isKey(err, agent.KeyInventoryInvalid) {
		t.Errorf("contexte d'hôte d'un agent dépôt : %v", err)
	}
	if err := f.agents.RecordHost(ctx, rp, h); !isKey(err, agent.KeyHostContextInvalid) {
		t.Errorf("contexte d'un envoi d'agent dépôt : %v", err)
	}
}

// TestInventoryReportAdvancesLastScan : l'empreinte que l'agent calcule (même fonction que
// le serveur, sur le même SBOM) confirme l'inventaire courant sans renvoyer le SBOM ; une
// autre empreinte, une référence inconnue ou l'absence d'instantané demandent l'envoi.
// L'agent serveur est muet quand il n'inventorie plus, même s'il répond encore.
func TestInventoryReportAdvancesLastScan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-inv", nil)
	data, err := os.ReadFile("../../testdata/sbom/alpine-3.20.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := syft.Decode(sbom.FormatSyft, data)
	if err != nil {
		t.Fatal(err)
	}
	fp := sbom.Fingerprint(doc.Components)
	report := func(fp [32]byte, ref string, at time.Time) agent.InventoryState {
		t.Helper()
		res, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1",
			Inventory: &agent.InventoryReport{ProjectID: e.Project.ID, RefName: ref, Fingerprint: fp, ScannedAt: at}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Inventory
	}
	if st := report(fp, "srv-inv", f.clock.Now()); st != agent.InventoryOutdated {
		t.Errorf("sans instantané : %s", st)
	}

	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ing, err := ingest.NewService(ingest.Options{Pool: f.tdb.App, Validator: v, Logger: slog.New(slog.DiscardHandler),
		Limits: ingest.Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}})
	if err != nil {
		t.Fatal(err)
	}
	scanned := f.clock.Now().Add(-time.Hour)
	in, err := ing.Receive(ctx, o, e.Agent.ID, ingest.Context{ProjectID: e.Project.ID, RefKind: project.RefHost,
		RefName: "srv-inv", AgentVersion: "1", ScannedAt: scanned}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := ing.Decode(ctx, o, in.ID); err != nil {
		t.Fatal(err)
	}
	a, _ := f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if a.LastInventoryAt == nil || !a.LastInventoryAt.Equal(scanned) {
		t.Fatalf("dernier inventaire %v, %v attendu", a.LastInventoryAt, scanned)
	}

	later := f.clock.Now()
	if st := report(fp, "srv-inv", later); st != agent.InventoryCurrent {
		t.Fatalf("même empreinte : %s", st)
	}
	if a, _ = f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID); !a.LastInventoryAt.Equal(later) {
		t.Errorf("date de dernière analyse %v, %v attendu", a.LastInventoryAt, later)
	}
	if st := report([32]byte{1}, "srv-inv", later); st != agent.InventoryOutdated {
		t.Errorf("autre empreinte : %s", st)
	}
	if st := report(fp, "autre-hote", later); st != agent.InventoryOutdated {
		t.Errorf("référence inconnue : %s", st)
	}
	for name, r := range map[string]agent.InventoryReport{
		"date future": {ProjectID: e.Project.ID, RefName: "srv-inv", Fingerprint: fp, ScannedAt: later.Add(2 * time.Hour)},
		"sans date":   {ProjectID: e.Project.ID, RefName: "srv-inv", Fingerprint: fp},
		"sans projet": {RefName: "srv-inv", Fingerprint: fp, ScannedAt: later},
	} {
		if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1", Inventory: &r}); !isKey(err, agent.KeyInventoryInvalid) {
			t.Errorf("%s : %v", name, err)
		}
	}

	// Muet : l'agent répond encore, mais n'a plus inventorié depuis plus de trois jours.
	f.clock.advance(agent.SilentAfter + time.Hour)
	if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatal(err)
	}
	a, _ = f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if st := a.StateAt(f.clock.Now()); st != agent.StateSilent {
		t.Errorf("agent serveur sans inventaire récent : %s", st)
	}
	if report(fp, "srv-inv", f.clock.Now()) != agent.InventoryCurrent {
		t.Fatal("confirmation")
	}
	a, _ = f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if st := a.StateAt(f.clock.Now()); st != agent.StateActive {
		t.Errorf("après un inventaire confirmé : %s", st)
	}
}
