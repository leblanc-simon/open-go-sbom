package repoagent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/forge"
)

const projectUUID = "0192f3a0-0000-7000-8000-000000000001"

func newAPITestServer(t *testing.T, uploadStatus int) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var uploads []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agent/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lotor_agt_x" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"projects":[
			  {"id":"`+projectUUID+`","slug":"app","name":"App","kind":"repo","labels":{},"forge_url":"https://github.com/acme/app",
			   "refs":[{"id":"0192f3a0-0000-7000-8000-000000000002","kind":"branch","name":"main",
			     "last_snapshot":{"id":"0192f3a0-0000-7000-8000-000000000003","commit":"`+strings.Repeat("A", 40)+`","scanned_at":"2026-10-31T00:00:00Z"}}]},
			  {"id":"0192f3a0-0000-7000-8000-000000000004","slug":"srv","name":"srv","kind":"host","labels":{},"refs":[]}
			],"page":{"next_cursor":"next"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"projects":[{"id":"0192f3a0-0000-7000-8000-000000000005","slug":"lib","name":"Lib","kind":"repo",
		  "labels":{},"forge_url":"https://github.com/acme/lib","refs":[{"id":"0192f3a0-0000-7000-8000-000000000006","kind":"tag","name":"v1"}]}],
		  "page":{"next_cursor":null}}`)
	})
	mux.HandleFunc("POST /api/v1/agent/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"scan_requested":false,"server_time":"2026-10-31T00:00:00Z"}`)
	})
	mux.HandleFunc("POST /api/v1/agent/ingestions", func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		got := map[string]any{}
		for i := 0; ; i++ {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			got["part"+string(rune('0'+i))] = p.FormName()
			switch p.FormName() {
			case "context":
				var c map[string]any
				_ = json.NewDecoder(p).Decode(&c)
				got["context"] = c
			case "sbom":
				got["sbomType"] = p.Header.Get("Content-Type")
				zr, err := gzip.NewReader(p)
				if err != nil {
					t.Error(err)
					return
				}
				raw, _ := io.ReadAll(zr)
				got["sbom"] = string(raw)
			}
		}
		uploads = append(uploads, got)
		if uploadStatus == http.StatusAccepted {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(uploadStatus)
			_, _ = io.WriteString(w, `{"id":"0192f3a0-0000-7000-8000-000000000009","status":"queued","project_id":"`+projectUUID+
				`","ref_id":"0192f3a0-0000-7000-8000-000000000002","received_at":"2026-10-31T00:00:00Z"}`)
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(uploadStatus)
		_, _ = io.WriteString(w, `{"type":"error.ingest.ref_unknown","title":"x","status":404}`)
	})
	ingestion := func(id, status, extra string) string {
		return `{"id":"` + id + `","status":"` + status + `","project_id":"` + projectUUID +
			`","ref_id":"0192f3a0-0000-7000-8000-000000000002","received_at":"2026-10-31T00:00:00Z"` + extra + `}`
	}
	mux.HandleFunc("GET /api/v1/agent/ingestions/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch id := r.PathValue("id"); id {
		case "0192f3a0-0000-7000-8000-000000000009":
			_, _ = io.WriteString(w, ingestion(id, "done", `,"snapshot_id":"0192f3a0-0000-7000-8000-000000000010"`))
		case "0192f3a0-0000-7000-8000-000000000011":
			_, _ = io.WriteString(w, ingestion(id, "failed", `,"error":{"key":"error.sbom.schema_invalid","title":"SBOM refusé","detail":"x"}`))
		default:
			_, _ = io.WriteString(w, ingestion(id, "processing", ""))
		}
	})
	mux.HandleFunc("GET /api/v1/agent/snapshots/0192f3a0-0000-7000-8000-000000000010/verdict", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"state":"fail","summary":"Non conforme","blocking":1,"warnings":0,"policies":["KEV"],"url":"https://sbom.example.org/o/acme"}`)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &uploads
}

func TestServerVerdict(t *testing.T) {
	srv, _ := newAPITestServer(t, http.StatusAccepted)
	s, err := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "lotor_agt_x", ServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for id, want := range map[string]PolicyVerdict{
		"0192f3a0-0000-7000-8000-000000000009": {State: VerdictFail, Summary: "Non conforme", URL: "https://sbom.example.org/o/acme"},
		"0192f3a0-0000-7000-8000-000000000011": {State: VerdictError, Summary: "SBOM refusé"},
		"0192f3a0-0000-7000-8000-000000000012": {State: VerdictPending},
	} {
		got, err := s.Verdict(ctx, Receipt{IngestionID: id})
		if err != nil || got != want {
			t.Errorf("%s : %+v, %v", id, got, err)
		}
	}
	if _, err := s.Verdict(ctx, Receipt{IngestionID: "x"}); err == nil {
		t.Error("reçu invalide accepté")
	}
}

func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServerProjectsAndHeartbeat(t *testing.T) {
	srv, _ := newAPITestServer(t, http.StatusAccepted)
	s, err := NewServer(ServerConfig{Retries: 1, URL: srv.URL + "/", CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "lotor_agt_x", ServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ps, err := s.Projects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Slug != "app" || ps[1].Slug != "lib" {
		t.Fatalf("projets %+v : dépôts des deux pages attendus, sans l'hôte", ps)
	}
	if r := ps[0].Refs[0]; r.Ref != mainRef || r.LastCommit != strings.Repeat("a", 40) {
		t.Fatalf("référence %+v", r)
	}
	if r := ps[1].Refs[0]; r.Ref != (forge.Ref{Kind: forge.RefTag, Name: "v1"}) || r.LastCommit != "" {
		t.Fatalf("étiquette %+v", r)
	}
	if err := s.Heartbeat(ctx, "1.0.0"); err != nil {
		t.Fatal(err)
	}

	bad, _ := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "wrong", ServerOptions{})
	if _, err := bad.Projects(ctx); err == nil {
		t.Fatal("jeton refusé non signalé")
	}
	// Sans l'autorité du serveur, le certificat est refusé.
	untrusted, _ := NewServer(ServerConfig{Retries: 1, URL: srv.URL, Timeout: 10 * time.Second}, "lotor_agt_x", ServerOptions{})
	if _, err := untrusted.Projects(ctx); err == nil {
		t.Fatal("certificat inconnu accepté")
	}
	if err := untrusted.Heartbeat(ctx, "1"); err == nil {
		t.Fatal("certificat inconnu accepté")
	}
	if _, err := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: "/nonexistent"}, "x", ServerOptions{}); err == nil {
		t.Fatal("autorité absente acceptée")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("x"), 0o600)
	if _, err := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: empty}, "x", ServerOptions{}); err == nil {
		t.Fatal("autorité vide acceptée")
	}
}

func TestServerUpload(t *testing.T) {
	ctx := context.Background()
	u := Upload{ProjectID: projectUUID, Ref: mainRef, Commit: strings.Repeat("b", 40), AgentVersion: "1.0.0",
		ScannedAt: time.Date(2026, 10, 31, 1, 2, 3, 0, time.UTC), SBOM: []byte(`{"bomFormat":"CycloneDX"}`)}

	srv, uploads := newAPITestServer(t, http.StatusAccepted)
	s, err := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "lotor_agt_x", ServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := s.Upload(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if rc.IngestionID == "" {
		t.Fatal("reçu sans ingestion")
	}
	got := (*uploads)[0]
	if got["part0"] != "context" || got["part1"] != "sbom" || got["sbomType"] != "application/gzip" || got["sbom"] != string(u.SBOM) {
		t.Fatalf("envoi %v", got)
	}
	c := got["context"].(map[string]any)
	if c["project_id"] != projectUUID || c["commit"] != u.Commit || c["agent_version"] != "1.0.0" ||
		c["scanned_at"] != "2026-10-31T01:02:03Z" || c["ref"].(map[string]any)["kind"] != "branch" {
		t.Fatalf("contexte %v", c)
	}

	for status, rejected := range map[int]bool{http.StatusNotFound: true, http.StatusRequestEntityTooLarge: true, http.StatusTooManyRequests: false, http.StatusBadGateway: false} {
		srv, _ := newAPITestServer(t, status)
		s, _ := NewServer(ServerConfig{Retries: 1, URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "lotor_agt_x", ServerOptions{})
		_, err := s.Upload(ctx, u)
		if err == nil || errors.Is(err, ErrRejected) != rejected {
			t.Errorf("%d : %v", status, err)
		}
		if rejected && !strings.Contains(err.Error(), "error.ingest.ref_unknown") {
			t.Errorf("%d : clé absente de %v", status, err)
		}
	}
	bad := u
	bad.ProjectID = "pas-un-uuid"
	if _, err := s.Upload(ctx, bad); err == nil {
		t.Fatal("projet invalide accepté")
	}
}

func TestServerChecksClientKey(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.key")
	_ = os.WriteFile(cert, []byte("x"), 0o644)
	_ = os.WriteFile(key, []byte("x"), 0o644)
	cfg := ServerConfig{URL: "https://sbom.example.org", ClientCertFile: cert, ClientKeyFile: key, Retries: 1, Timeout: time.Second}
	if _, err := NewServer(cfg, "t", ServerOptions{}); err == nil || !strings.Contains(err.Error(), "droits") {
		t.Errorf("clé lisible par tous : %v", err)
	}
	_ = os.Chmod(key, 0o600)
	if _, err := NewServer(cfg, "t", ServerOptions{}); err == nil {
		t.Error("paire invalide acceptée")
	}
	cfg.URL = "http://sbom.example.org"
	cfg.ClientCertFile, cfg.ClientKeyFile = "", ""
	if _, err := NewServer(cfg, "t", ServerOptions{}); err == nil {
		t.Error("adresse http acceptée")
	}
}
