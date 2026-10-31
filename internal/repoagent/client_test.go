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

	"leblanc.io/open-go-sbom/internal/forge"
)

const projectUUID = "0192f3a0-0000-7000-8000-000000000001"

func newAPITestServer(t *testing.T, uploadStatus int) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var uploads []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agent/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ogsbom_agt_x" {
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
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(uploadStatus)
		_, _ = io.WriteString(w, `{"type":"error.ingest.ref_unknown","title":"x","status":404}`)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &uploads
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

func TestAPIServerProjectsAndHeartbeat(t *testing.T) {
	srv, _ := newAPITestServer(t, http.StatusAccepted)
	s, err := NewAPIServer(ServerConfig{URL: srv.URL + "/", CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "ogsbom_agt_x")
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

	bad, _ := NewAPIServer(ServerConfig{URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "wrong")
	if _, err := bad.Projects(ctx); err == nil {
		t.Fatal("jeton refusé non signalé")
	}
	// Sans l'autorité du serveur, le certificat est refusé.
	untrusted, _ := NewAPIServer(ServerConfig{URL: srv.URL, Timeout: 10 * time.Second}, "ogsbom_agt_x")
	if _, err := untrusted.Projects(ctx); err == nil {
		t.Fatal("certificat inconnu accepté")
	}
	if err := untrusted.Heartbeat(ctx, "1"); err == nil {
		t.Fatal("certificat inconnu accepté")
	}
	if _, err := NewAPIServer(ServerConfig{URL: srv.URL, CAFile: "/nonexistent"}, "x"); err == nil {
		t.Fatal("autorité absente acceptée")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("x"), 0o600)
	if _, err := NewAPIServer(ServerConfig{URL: srv.URL, CAFile: empty}, "x"); err == nil {
		t.Fatal("autorité vide acceptée")
	}
}

func TestAPIServerUpload(t *testing.T) {
	ctx := context.Background()
	u := Upload{ProjectID: projectUUID, Ref: mainRef, Commit: strings.Repeat("b", 40), AgentVersion: "1.0.0",
		ScannedAt: time.Date(2026, 10, 31, 1, 2, 3, 0, time.UTC), SBOM: []byte(`{"bomFormat":"CycloneDX"}`)}

	srv, uploads := newAPITestServer(t, http.StatusAccepted)
	s, err := NewAPIServer(ServerConfig{URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "ogsbom_agt_x")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upload(ctx, u); err != nil {
		t.Fatal(err)
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
		s, _ := NewAPIServer(ServerConfig{URL: srv.URL, CAFile: caFile(t, srv), Timeout: 10 * time.Second}, "ogsbom_agt_x")
		err := s.Upload(ctx, u)
		if err == nil || errors.Is(err, ErrRejected) != rejected {
			t.Errorf("%d : %v", status, err)
		}
		if rejected && !strings.Contains(err.Error(), "error.ingest.ref_unknown") {
			t.Errorf("%d : clé absente de %v", status, err)
		}
	}
	bad := u
	bad.ProjectID = "pas-un-uuid"
	if err := s.Upload(ctx, bad); err == nil {
		t.Fatal("projet invalide accepté")
	}
}
