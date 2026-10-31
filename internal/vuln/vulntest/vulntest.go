// Package vulntest fournit aux tests une fausse base de vulnérabilités : un vuln.Engine,
// une vuln.Source et des archives, sans Grype ni réseau.
//
// Une archive est un document JSON {"built", "schema", "rules"} ; une règle associe un
// purl canonique à une vulnérabilité, et la fausse base produit une correspondance pour
// chaque règle dont le purl figure dans le SBOM (recherche textuelle de "purl":"…").
package vulntest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/vuln"
)

// Rule est une vulnérabilité de la fausse base, attachée à un purl canonique.
type Rule struct {
	PURL  string             `json:"purl"`
	Match vuln.Match         `json:"match"`
	Vuln  vuln.Vulnerability `json:"vuln"`
}

// Content est le contenu d'une fausse archive.
type Content struct {
	Built  time.Time `json:"built"`
	Schema string    `json:"schema"`
	Rules  []Rule    `json:"rules"`
}

// Archive sérialise c.
func Archive(t testing.TB, c Content) []byte {
	t.Helper()
	if c.Schema == "" {
		c.Schema = "v6.1.10"
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SHA256 renvoie la somme hexadécimale de b.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Engine est un faux vuln.Engine. Hook, s'il est posé, est appelé au début de chaque
// correspondance (pour simuler un événement concurrent).
type Engine struct {
	Hook  func(ctx context.Context)
	Delay time.Duration

	opened atomic.Int64
	closed atomic.Int64
}

var _ vuln.Engine = (*Engine)(nil)

// Install refuse ce qui n'est pas une fausse archive valide.
func (e *Engine) Install(_ context.Context, archivePath, dir string) (vuln.Description, error) {
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		return vuln.Description{}, fmt.Errorf("vulntest: %s existe déjà", dir)
	}
	b, err := os.ReadFile(archivePath)
	if err != nil {
		return vuln.Description{}, err
	}
	var c Content
	if err := json.Unmarshal(b, &c); err != nil || c.Built.IsZero() {
		return vuln.Description{}, fmt.Errorf("vulntest: archive illisible : %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return vuln.Description{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "db.json"), b, 0o600); err != nil {
		return vuln.Description{}, err
	}
	return vuln.Description{Built: c.Built.UTC(), Schema: c.Schema}, nil
}

// Open ouvre une base installée.
func (e *Engine) Open(_ context.Context, dir string) (vuln.Database, error) {
	b, err := os.ReadFile(filepath.Join(dir, "db.json"))
	if err != nil {
		return nil, err
	}
	var c Content
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	e.opened.Add(1)
	return &database{e: e, c: c}, nil
}

// Opened compte les bases ouvertes.
func (e *Engine) Opened() int64 { return e.opened.Load() }

// Closed compte les bases fermées.
func (e *Engine) Closed() int64 { return e.closed.Load() }

type database struct {
	e      *Engine
	c      Content
	mu     sync.Mutex
	closed bool
}

func (d *database) Description() vuln.Description {
	return vuln.Description{Built: d.c.Built.UTC(), Schema: d.c.Schema}
}

func (d *database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.e.closed.Add(1)
	}
	return nil
}

// ErrClosed : correspondance demandée à une base fermée (bascule mal synchronisée).
var ErrClosed = errors.New("vulntest: base fermée")

func (d *database) Match(ctx context.Context, blob []byte) ([]vuln.Match, map[string]vuln.Vulnerability, error) {
	if d.e.Hook != nil {
		d.e.Hook(ctx)
	}
	if d.e.Delay > 0 {
		time.Sleep(d.e.Delay)
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, nil, ErrClosed
	}
	var ms []vuln.Match
	vs := map[string]vuln.Vulnerability{}
	for _, r := range d.c.Rules {
		if !bytes.Contains(blob, []byte(`"purl": "`+r.PURL+`"`)) && !bytes.Contains(blob, []byte(`"purl":"`+r.PURL+`"`)) {
			continue
		}
		m := r.Match
		m.PURL = r.PURL
		if m.VulnerabilityID == "" {
			m.VulnerabilityID = r.Vuln.ID
		}
		if m.Type == "" {
			m.Type = vuln.MatchExactDirect
		}
		if m.FixState == "" {
			m.FixState = vuln.FixUnknown
		}
		if m.Severity == "" {
			m.Severity = r.Vuln.Severity
		}
		ms = append(ms, m)
		v := r.Vuln
		if v.Severity == "" {
			v.Severity = vuln.SeverityUnknown
		}
		vs[v.ID] = v
	}
	// Une base close pendant la correspondance aurait servi des résultats incohérents.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil, ErrClosed
	}
	return ms, vs, nil
}

// Source est une fausse liste de distribution : la dernière archive publiée.
type Source struct {
	mu      sync.Mutex
	listing vuln.Listing
	body    []byte
	err     error
}

var _ vuln.Source = (*Source)(nil)

// Publish annonce body comme dernière archive ; sum vide : la somme de body.
func (s *Source) Publish(body []byte, built time.Time, sum string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sum == "" {
		sum = SHA256(body)
	}
	s.listing = vuln.Listing{URL: "https://db.example/" + sum + ".tar.zst", Built: built.UTC(), Schema: "v6.1.10", SHA256: sum}
	s.body, s.err = body, nil
}

// Fail fait échouer les appels suivants.
func (s *Source) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Latest renvoie la dernière archive publiée.
func (s *Source) Latest(context.Context) (vuln.Listing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return vuln.Listing{}, s.err
	}
	if s.body == nil {
		return vuln.Listing{}, errors.New("vulntest: rien de publié")
	}
	return s.listing, nil
}

// Download écrit l'archive publiée.
func (s *Source) Download(_ context.Context, _ vuln.Listing, w io.Writer, maxBytes int64) error {
	s.mu.Lock()
	body := s.body
	s.mu.Unlock()
	if int64(len(body)) > maxBytes {
		return vuln.ErrTooLarge
	}
	_, err := w.Write(body)
	return err
}
