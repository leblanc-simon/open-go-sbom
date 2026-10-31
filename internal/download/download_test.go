package download

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/vuln"
)

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("User-Agent") != "ogsbom-server test" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("contenu"))
		case "/stream":
			// Sans Content-Length : la borne s'applique à la lecture.
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		case "/slow":
			time.Sleep(200 * time.Millisecond)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New("ogsbom-server test", 0)
	ctx := context.Background()
	var buf bytes.Buffer
	if err := c.Fetch(ctx, srv.URL+"/ok", &buf, 100); err != nil || buf.String() != "contenu" {
		t.Fatalf("%q, %v", buf.String(), err)
	}
	if err := c.Fetch(ctx, srv.URL+"/ok", &bytes.Buffer{}, 3); !errors.Is(err, vuln.ErrTooLarge) {
		t.Fatalf("taille annoncée : %v", err)
	}
	if err := c.Fetch(ctx, srv.URL+"/stream", &bytes.Buffer{}, 10); !errors.Is(err, vuln.ErrTooLarge) {
		t.Fatalf("taille lue : %v", err)
	}
	if err := c.Fetch(ctx, srv.URL+"/absent", &bytes.Buffer{}, 10); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 : %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := c.Fetch(short, srv.URL+"/slow", &bytes.Buffer{}, 10); err == nil {
		t.Fatal("contexte ignoré")
	}
	if err := c.Fetch(ctx, "://", &bytes.Buffer{}, 10); err == nil {
		t.Fatal("adresse invalide acceptée")
	}
}
