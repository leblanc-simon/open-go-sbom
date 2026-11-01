//go:build integration

package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient"
	apiv1 "leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/hostagent"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// tlsAPI sert le routeur de l'application en HTTPS (comme le TLS natif du serveur) ;
// clientCAs, si non nil, vérifie un certificat client présenté (VerifyClientCertIfGiven,
// comme TLSConfig).
func (a *app) tlsAPI(clientCAs *x509.CertPool) (*httptest.Server, string) {
	a.t.Helper()
	srv := httptest.NewUnstartedServer(a.handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCAs != nil {
		srv.TLS.ClientCAs, srv.TLS.ClientAuth = clientCAs, tls.VerifyClientCertIfGiven
	}
	srv.StartTLS()
	a.t.Cleanup(srv.Close)
	caFile := filepath.Join(a.t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		a.t.Fatal(err)
	}
	return srv, caFile
}

// decoder fait tourner les jobs de décodage des SBOM, comme les workers du serveur.
func (a *app) decoder() {
	a.t.Helper()
	runner := jobs.NewRunner(a.tdb.App, jobs.RunnerOptions{Concurrency: 2, PollInterval: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := runner.Register(ingest.DecodeKind, a.ingest.DecodeHandler(), jobs.WithTimeout(time.Minute)); err != nil {
		a.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	a.t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			a.t.Error(err)
		}
	})
}

// hostAgent construit un lotor-host-agent réel (Syft sur testdata/rootfs) vers srv ;
// mutate complète ses options (inventaire des conteneurs).
func (a *app) hostAgent(srv *httptest.Server, caFile, enrollment string, tlsOpts agentclient.TLSOptions,
	mutate ...func(*hostagent.Options)) *hostagent.Agent {
	a.t.Helper()
	dir := a.t.TempDir()
	tokFile := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokFile, []byte(enrollment), 0o600); err != nil {
		a.t.Fatal(err)
	}
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		a.t.Fatal(err)
	}
	cfg := hostagent.Defaults()
	cfg.Mode, cfg.Hostname, cfg.StateDir, cfg.EnrollmentTokenFile = hostagent.ModeOneshot, "srv-agent-01", filepath.Join(dir, "etat"), tokFile
	cfg.Labels = map[string]string{"role": "db"}
	cfg.Server.URL = srv.URL
	cfg.Scan = hostagent.Scan{Root: root, Interval: 24 * time.Hour, PollInterval: 5 * time.Minute, MaxDuration: 5 * time.Minute}
	tlsOpts.CAFile = caFile
	client, err := agentclient.New(agentclient.Options{ServerURL: srv.URL, TLS: tlsOpts, Retry: agentclient.Retry{Attempts: 2, Base: 10 * time.Millisecond}})
	if err != nil {
		a.t.Fatal(err)
	}
	store, err := hostagent.OpenStore(cfg.StateDir)
	if err != nil {
		a.t.Fatal(err)
	}
	o := hostagent.Options{Config: cfg, Version: "1.0.0-test", Client: client, Store: store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), IngestionPoll: 20 * time.Millisecond,
		Scanner: hostagent.SyftScanner{Root: root, Hostname: cfg.Hostname, Parallelism: 2, Version: "1.0.0-test"}}
	for _, m := range mutate {
		m(&o)
	}
	ag, err := hostagent.New(o)
	if err != nil {
		a.t.Fatal(err)
	}
	return ag
}

// TestHostAgentEndToEnd : un administrateur crée un jeton d'inscription (assistant
// d'installation), un vrai lotor-host-agent s'inscrit en HTTPS, inventorie
// testdata/rootfs et envoie son SBOM, rangé par le décodage ; un second scan sans
// changement n'envoie rien (signal de vie qui confirme l'inventaire) ; « Scanner
// maintenant » est remis au prochain signal de vie.
func TestHostAgentEndToEnd(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	a.decoder()
	admin, analyst, viewer := a.user("admin@example.org", false), a.user("analyste@example.org", false), a.user("lecteur@example.org", false)
	o := a.org("org-a", admin)
	a.addTeamMember(o, analyst, tenant.TeamAnalyst)
	a.addTeamMember(o, viewer, tenant.TeamReader)
	b := a.signIn(admin)
	srv, caFile := a.tlsAPI(nil)

	created := b.post("/o/org-a/enrollment-tokens", url.Values{"name": {"parc"}, "expires_in": {"24"}, "max_uses": {"1"},
		"labels": {"env=prod"}, "project": {""}, "team": {a.defaultTeam(o.ID).String()}})
	enr := shownToken(t, created)
	body := unescape(created.body)
	for _, want := range []string{"Installer l'agent serveur", "systemctl enable --now lotor-host-agent.service",
		"/etc/lotor-host-agent/enrollment-token", "printf '%s' '" + enr + "'"} {
		if !strings.Contains(body, want) {
			t.Errorf("assistant d'installation : %q absent", want)
		}
	}
	webtest.AssertAccessible(t, []byte(created.body))
	webtest.AssertNoInlineCode(t, []byte(created.body))

	ag := a.hostAgent(srv, caFile, enr, agentclient.TLSOptions{})
	ctx := context.Background()
	res, err := ag.Cycle(ctx)
	if err != nil || res.Outcome != hostagent.OutcomeSent || res.Components < 7 {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	p, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), "srv-agent-01")
	if err != nil || p.Labels["env"] != "prod" || p.Labels["role"] != "db" {
		t.Fatalf("projet de l'hôte : %+v %v", p, err)
	}
	if res, err = ag.Cycle(ctx); err != nil || res.Outcome != hostagent.OutcomeConfirmed {
		t.Fatalf("second cycle : %+v %v", res, err)
	}
	snaps := b.get("/o/org-a/projects/srv-agent-01/snapshots")
	if strings.Count(snaps.body, `/projects/srv-agent-01/snapshots/`) < 1 {
		t.Fatalf("instantanés : %d", snaps.status)
	}
	var ingestions, snapshots int
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ingestions`).Scan(&ingestions); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM snapshots`).Scan(&snapshots)
	}); err != nil {
		t.Fatal(err)
	}
	if ingestions != 1 || snapshots != 1 {
		t.Errorf("%d ingestions et %d instantanés après deux scans identiques (1 et 1 attendus)", ingestions, snapshots)
	}

	// Fiche de l'hôte : contexte reçu, dernier inventaire, bouton « Scanner maintenant ».
	page := b.get("/o/org-a/projects/srv-agent-01")
	body = unescape(page.body)
	for _, want := range []string{"Debian GNU/Linux 12 (bookworm)", "Scanner maintenant", "Dernier inventaire", "Actif"} {
		if !strings.Contains(body, want) {
			t.Errorf("fiche de l'hôte : %q absent", want)
		}
	}
	webtest.AssertAccessible(t, []byte(page.body))
	webtest.AssertNoInlineCode(t, []byte(page.body))
	if denied := a.signIn(viewer).post("/o/org-a/projects/srv-agent-01/scan", url.Values{}); denied.status != http.StatusForbidden {
		t.Errorf("lecteur : %d", denied.status)
	}
	if requested, err := ag.Heartbeat(ctx); err != nil || requested {
		t.Fatalf("sans demande : %v %v", requested, err)
	}
	asAnalyst := a.signIn(analyst)
	done := asAnalyst.post("/o/org-a/projects/srv-agent-01/scan", url.Values{})
	if done.status != http.StatusSeeOther {
		t.Fatalf("demande de scan : %d", done.status)
	}
	pending := asAnalyst.get(done.location)
	if body := unescape(pending.body); !strings.Contains(body, "Scan demandé") || strings.Contains(body, "Scanner maintenant") {
		t.Error("demande en attente non affichée")
	}
	if requested, err := ag.Heartbeat(ctx); err != nil || !requested {
		t.Fatalf("demande remise au signal de vie : %v %v", requested, err)
	}
	if requested, _ := ag.Heartbeat(ctx); requested {
		t.Error("demande remise deux fois")
	}
	agentPage := b.get("/o/org-a/agents/" + p.Agent.ID.String())
	if body := unescape(agentPage.body); !strings.Contains(body, "Noyau") || !strings.Contains(body, "Debian GNU/Linux 12") {
		t.Error("contexte de l'hôte absent de la fiche de l'agent")
	}
	webtest.AssertAccessible(t, []byte(agentPage.body))

	if logs := a.logs.String(); strings.Contains(logs, enr[len(enr)-52:]) {
		t.Error("jeton d'inscription dans les journaux")
	}
}

// testPKI est une autorité qui signe des certificats clients.
type testPKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agents"}, IsCA: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := &testPKI{cert: cert, key: key, pool: x509.NewCertPool()}
	p.pool.AddCert(cert)
	return p
}

// client signe un certificat client et écrit le certificat et sa clé (0600).
func (p *testPKI) client(t *testing.T) agentclient.TLSOptions {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "srv-agent-01"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	o := agentclient.TLSOptions{ClientCertFile: filepath.Join(dir, "agent.pem"), ClientKeyFile: filepath.Join(dir, "agent.key")}
	_ = os.WriteFile(o.ClientCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(o.ClientKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return o
}

// TestHostAgentMutualTLS : avec tls.client_ca_file, l'API des agents refuse une connexion
// sans certificat client valide (ni jeton lu, ni inscription), et l'agent muni d'un
// certificat de l'autorité fait son cycle ; l'interface reste accessible sans certificat.
func TestHostAgentMutualTLS(t *testing.T) {
	t.Parallel()
	a := newApp(t, func(o *RouterOptions) { o.AgentAPI.RequireClientCert = true })
	a.decoder()
	admin := a.user("admin@example.org", false)
	oa := a.org("org-a", admin)
	b := a.signIn(admin)
	agents := newTestPKI(t)
	srv, caFile := a.tlsAPI(agents.pool)
	created := b.post("/o/org-a/enrollment-tokens", url.Values{"name": {"parc"}, "expires_in": {"24"}, "max_uses": {"2"}, "project": {""},
		"team": {a.defaultTeam(oa.ID).String()}})
	enr := shownToken(t, created)

	// Sans certificat : refus explicite, le jeton n'est pas consommé.
	if _, err := a.hostAgent(srv, caFile, enr, agentclient.TLSOptions{}).Cycle(context.Background()); !agentclient.IsKey(err, apiv1.KeyClientCertRequired) {
		t.Fatalf("sans certificat client : %v", err)
	}
	// Certificat d'une autre autorité : la poignée de main échoue.
	if _, err := a.hostAgent(srv, caFile, enr, newTestPKI(t).client(t)).Cycle(context.Background()); err == nil {
		t.Fatal("certificat d'une autre autorité accepté")
	}
	res, err := a.hostAgent(srv, caFile, enr, agents.client(t)).Cycle(context.Background())
	if err != nil || res.Outcome != hostagent.OutcomeSent {
		t.Fatalf("avec certificat : %+v %v", res, err)
	}
	// L'interface, servie par la même écoute, ne demande pas de certificat.
	ui, err := srv.Client().Get(srv.URL + "/login")
	if err != nil || ui.StatusCode != http.StatusOK {
		t.Fatalf("interface sans certificat : %v %v", ui, err)
	}
	_ = ui.Body.Close()
}
