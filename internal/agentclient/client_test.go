package agentclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient/gen"
)

// fastRetry garde les tests rapides tout en exerçant les réessais.
var fastRetry = Retry{Attempts: 4, Base: time.Millisecond, Max: 20 * time.Millisecond}

func newTestClient(t *testing.T, h http.Handler, opts ...func(*Options)) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	o := Options{ServerURL: srv.URL, Token: "lotor_agt_x_y", UserAgent: "lotor-test/1.0", Language: "en",
		Retry: fastRetry, Transport: srv.Client().Transport}
	for _, f := range opts {
		f(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, key string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	detail, rid := "detail of "+key, "req-1"
	_ = json.NewEncoder(w).Encode(gen.Problem{Type: key, Title: "title", Status: status, Detail: &detail, RequestId: &rid})
}

func TestNewRejectsInvalidServerURL(t *testing.T) {
	for _, u := range []string{"", "sbom.example.org", "http://sbom.example.org", "https://", "https://h/?q=1", "https://u:p@h", "ftp://h"} {
		if _, err := New(Options{ServerURL: u}); err == nil {
			t.Errorf("%q accepté", u)
		}
	}
	if _, err := New(Options{ServerURL: "https://sbom.example.org/"}); err != nil {
		t.Errorf("https refusé : %v", err)
	}
}

func TestEnrollSendsHeadersAndEnrollmentToken(t *testing.T) {
	agentID := uuid.New()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/enroll" || r.Method != http.MethodPost {
			t.Errorf("requête %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer lotor_enr_a_b" {
			t.Errorf("Authorization = %q", got)
		}
		if r.Header.Get("User-Agent") != "lotor-test/1.0" || r.Header.Get("Accept-Language") != "en" {
			t.Errorf("en-têtes %v", r.Header)
		}
		var req gen.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hostname != "srv-1" {
			t.Errorf("corps %+v, %v", req, err)
		}
		writeJSON(w, http.StatusCreated, gen.EnrollmentResult{AgentId: agentID, Token: "lotor_agt_new_secret"})
	}))
	res, err := c.Enroll(context.Background(), "lotor_enr_a_b", gen.EnrollRequest{Hostname: "srv-1", Version: "1.0"})
	if err != nil || res.AgentId != agentID || res.Token != "lotor_agt_new_secret" {
		t.Fatalf("Enroll = %+v, %v", res, err)
	}
	if _, err := c.Enroll(context.Background(), "", gen.EnrollRequest{}); !errors.Is(err, ErrNoToken) {
		t.Errorf("sans jeton : %v", err)
	}
}

func TestNoTokenIsRefusedWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }),
		func(o *Options) { o.Token = "" })
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); !errors.Is(err, ErrNoToken) {
		t.Errorf("Heartbeat sans jeton : %v", err)
	}
	if calls.Load() != 0 {
		t.Errorf("%d requêtes envoyées sans jeton", calls.Load())
	}
	if _, err := c.WithToken("lotor_agt_t_s").Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err == nil {
		t.Error("réponse vide acceptée")
	}
}

func TestRetriesTransientStatusAndReplaysBody(t *testing.T) {
	var calls atomic.Int32
	var logs bytes.Buffer
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gen.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Version != "2.0" {
			t.Errorf("corps rejoué : %+v, %v", req, err)
		}
		if calls.Add(1) < 3 {
			writeProblem(w, http.StatusServiceUnavailable, "error.unavailable")
			return
		}
		writeJSON(w, http.StatusOK, gen.HeartbeatStatus{ScanRequested: true, ServerTime: time.Now()})
	}), func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&logs, nil)) })
	st, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "2.0"})
	if err != nil || !st.ScanRequested {
		t.Fatalf("Heartbeat = %+v, %v", st, err)
	}
	if calls.Load() != 3 {
		t.Errorf("%d tentatives, 3 attendues", calls.Load())
	}
	if out := logs.String(); strings.Count(out, "op=heartbeat") != 2 || !strings.Contains(out, "status=503") || strings.Contains(out, "lotor_agt") {
		t.Errorf("journal des réessais : %s", out)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeProblem(w, http.StatusBadGateway, "error.bad_gateway")
	}))
	_, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"})
	if !HasStatus(err, http.StatusBadGateway) || !IsKey(err, "error.bad_gateway") {
		t.Fatalf("erreur = %v", err)
	}
	if calls.Load() != int32(fastRetry.Attempts) {
		t.Errorf("%d tentatives, %d attendues", calls.Load(), fastRetry.Attempts)
	}
	var e *Error
	if !errors.As(err, &e) || e.RequestID != "req-1" || e.Detail == "" || e.Op != "heartbeat" {
		t.Errorf("erreur détaillée %+v", e)
	}
	if !strings.Contains(err.Error(), "502") || strings.Contains(err.Error(), "lotor_agt") {
		t.Errorf("message %q", err.Error())
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeProblem(w, http.StatusUnauthorized, KeyTokenRevoked)
	}))
	_, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"})
	if !IsKey(err, KeyTokenRevoked) || calls.Load() != 1 {
		t.Fatalf("erreur = %v après %d tentatives", err, calls.Load())
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			writeProblem(w, http.StatusTooManyRequests, "error.too_many_requests")
			return
		}
		writeJSON(w, http.StatusOK, gen.HeartbeatStatus{ServerTime: time.Now()})
	}))
	var waits []time.Duration
	c.doer.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 1 || waits[0] != 0 {
		t.Errorf("attentes %v, [0] attendu (Retry-After)", waits)
	}
}

func TestRetryAfterBeyondPolicyGivesUp(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		writeProblem(w, http.StatusServiceUnavailable, "error.unavailable")
	}))
	_, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"})
	if !HasStatus(err, http.StatusServiceUnavailable) || calls.Load() != 1 {
		t.Fatalf("erreur %v après %d tentatives", err, calls.Load())
	}
}

// flakyTransport échoue sur ses premiers appels comme un réseau coupé.
type flakyTransport struct {
	fails atomic.Int32
	next  http.RoundTripper
}

func (f *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.fails.Add(-1) >= 0 {
		return nil, errors.New("connexion réinitialisée")
	}
	return f.next.RoundTrip(r)
}

func TestNetworkErrorsAreRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, gen.HeartbeatStatus{ServerTime: time.Now()})
	}))
	defer srv.Close()
	ft := &flakyTransport{next: srv.Client().Transport}
	ft.fails.Store(2)
	c, err := New(Options{ServerURL: srv.URL, Token: "t", Retry: fastRetry, Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatalf("après deux coupures : %v", err)
	}
	ft.fails.Store(10)
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err == nil || HasStatus(err, 0) {
		t.Errorf("réseau toujours coupé : %v", err)
	}
}

func TestCancelledContextStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		cancel()
		writeProblem(w, http.StatusServiceUnavailable, "error.unavailable")
	}), func(o *Options) { o.Retry = Retry{Attempts: 5, Base: time.Hour, Max: time.Hour} })
	if _, err := c.Heartbeat(ctx, gen.HeartbeatRequest{Version: "1"}); !errors.Is(err, context.Canceled) {
		t.Errorf("erreur = %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("%d tentatives après annulation", calls.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer other.Close()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); !HasStatus(err, http.StatusTemporaryRedirect) {
		t.Errorf("erreur = %v", err)
	}
	if leaked.Load() {
		t.Error("redirection suivie : jeton envoyé ailleurs")
	}
}

func TestUploadSendsContextThenGzippedSBOM(t *testing.T) {
	sbom := []byte(`{"artifacts":[],"schema":{"version":"16.1.0"}}`)
	projectID, ingestionID := uuid.New(), uuid.New()
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/ingestions" {
			t.Errorf("chemin %s", r.URL.Path)
		}
		mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "multipart/form-data" {
			t.Fatalf("Content-Type %q", r.Header.Get("Content-Type"))
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		p, err := mr.NextPart()
		if err != nil || p.FormName() != "context" || p.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("première partie %v, %v", p, err)
		}
		var ic gen.IngestionContext
		if err := json.NewDecoder(p).Decode(&ic); err != nil || ic.ProjectId != projectID || ic.Ref.Name != "srv-1" {
			t.Errorf("contexte %+v, %v", ic, err)
		}
		if p, err = mr.NextPart(); err != nil || p.FormName() != "sbom" || p.Header.Get("Content-Type") != "application/gzip" {
			t.Fatalf("seconde partie %v, %v", p, err)
		}
		zr, err := gzip.NewReader(p)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(zr)
		if !bytes.Equal(got, sbom) {
			t.Errorf("SBOM reçu %q", got)
		}
		if calls.Add(1) == 1 {
			writeProblem(w, http.StatusServiceUnavailable, "error.unavailable")
			return
		}
		writeJSON(w, http.StatusAccepted, gen.Ingestion{Id: ingestionID, Status: gen.Queued})
	}))
	ic := gen.IngestionContext{ProjectId: projectID, AgentVersion: "1.0", ScannedAt: time.Now()}
	ic.Ref.Kind, ic.Ref.Name = gen.IngestionContextRefKindHost, "srv-1"
	in, err := c.Upload(context.Background(), ic, sbom)
	if err != nil || in.Id != ingestionID || calls.Load() != 2 {
		t.Fatalf("Upload = %+v, %v (%d tentatives)", in, err, calls.Load())
	}
	if _, err := c.Upload(context.Background(), ic, nil); err == nil {
		t.Error("SBOM vide accepté")
	}
}

func TestUploadDuplicateAndTooLarge(t *testing.T) {
	id := uuid.New()
	status := http.StatusOK
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status == http.StatusOK {
			writeJSON(w, status, gen.Ingestion{Id: id, Status: gen.Done})
			return
		}
		writeProblem(w, status, KeyTooLarge)
	}))
	ic := gen.IngestionContext{ProjectId: uuid.New(), ScannedAt: time.Now()}
	if in, err := c.Upload(context.Background(), ic, []byte("{}")); err != nil || in.Id != id {
		t.Fatalf("doublon : %+v, %v", in, err)
	}
	status = http.StatusRequestEntityTooLarge
	if _, err := c.Upload(context.Background(), ic, []byte("{}")); !IsKey(err, KeyTooLarge) || !HasStatus(err, 413) {
		t.Errorf("trop gros : %v", err)
	}
}

func TestProjectsWalksAllPages(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "200" {
			t.Errorf("limit %q", r.URL.Query().Get("limit"))
		}
		var page gen.AgentProjectList
		switch r.URL.Query().Get("cursor") {
		case "":
			next := "p2"
			page = gen.AgentProjectList{Projects: []gen.AgentProject{{Name: "a"}}, Page: gen.PageInfo{NextCursor: &next}}
		case "p2":
			page = gen.AgentProjectList{Projects: []gen.AgentProject{{Name: "b"}, {Name: "c"}}}
		default:
			t.Errorf("curseur %q", r.URL.Query().Get("cursor"))
		}
		writeJSON(w, http.StatusOK, page)
	}))
	ps, err := c.Projects(context.Background())
	if err != nil || len(ps) != 3 || ps[2].Name != "c" {
		t.Fatalf("Projects = %+v, %v", ps, err)
	}
}

func TestWaitPollsUntilFinal(t *testing.T) {
	id := uuid.New()
	var calls atomic.Int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/ingestions/"+id.String() {
			t.Errorf("chemin %s", r.URL.Path)
		}
		st := gen.Processing
		if calls.Add(1) >= 2 {
			st = gen.Done
		}
		writeJSON(w, http.StatusOK, gen.Ingestion{Id: id, Status: st})
	}))
	in, err := c.Wait(context.Background(), gen.Ingestion{Id: id, Status: gen.Queued}, time.Millisecond)
	if err != nil || in.Status != gen.Done || calls.Load() != 2 {
		t.Fatalf("Wait = %+v, %v (%d appels)", in, err, calls.Load())
	}
	done := gen.Ingestion{Id: id, Status: gen.Failed}
	if in, err := c.Wait(context.Background(), done, time.Millisecond); err != nil || in != done || calls.Load() != 2 {
		t.Errorf("ingestion déjà finale : %+v, %v", in, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	calls.Store(-1000)
	if _, err := c.Wait(ctx, gen.Ingestion{Id: id, Status: gen.Queued}, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("attente bornée : %v", err)
	}
}

func TestResponseIsBounded(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"projects":[`))
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxResponse))
		_, _ = w.Write([]byte(`],"page":{"next_cursor":null}}`))
	}))
	if _, err := c.Projects(context.Background()); !errors.Is(err, errResponseTooLarge) {
		t.Errorf("réponse démesurée : %v", err)
	}
}

func TestResponseErrorWithoutProblem(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>proxy</html>"))
	}))
	_, err := c.Ingestion(context.Background(), uuid.New())
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Key != "" {
		t.Errorf("erreur = %#v", err)
	}
}

func TestBackoffAndRetryAfter(t *testing.T) {
	r := Retry{Attempts: 3, Base: time.Second, Max: 10 * time.Second}
	for n, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 5: 10 * time.Second, 80: 10 * time.Second} {
		for range 20 {
			if d := r.backoff(n); d < want/2 || d > want {
				t.Errorf("backoff(%d) = %v, hors de [%v, %v]", n, d, want/2, want)
			}
		}
	}
	if d := (Retry{}).withDefaults(); d != DefaultRetry {
		t.Errorf("défauts %+v", d)
	}
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	h := http.Header{}
	if _, ok := retryAfter(h, now); ok {
		t.Error("Retry-After absent lu")
	}
	h.Set("Retry-After", "7")
	if d, ok := retryAfter(h, now); !ok || d != 7*time.Second {
		t.Errorf("secondes : %v %v", d, ok)
	}
	h.Set("Retry-After", now.Add(90*time.Second).Format(http.TimeFormat))
	if d, ok := retryAfter(h, now); !ok || d != 90*time.Second {
		t.Errorf("date : %v %v", d, ok)
	}
	h.Set("Retry-After", "bientôt")
	if _, ok := retryAfter(h, now); ok {
		t.Error("valeur illisible acceptée")
	}
}
