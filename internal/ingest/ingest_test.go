package ingest

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
)

func unitService() *Service {
	return &Service{limits: Limits{MaxUpload: 1 << 10, SBOM: sbom.Limits{MaxBytes: 4 << 10, MaxDepth: 8, MaxComponents: 10}},
		now: func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }}
}

func gzipped(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadUpload(t *testing.T) {
	s := unitService()
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	raw, err := s.read(bytes.NewReader(doc))
	if err != nil || raw.reject != nil || raw.size != int64(len(doc)) {
		t.Fatalf("envoi brut : %+v, %v", raw, err)
	}
	gz, err := s.read(bytes.NewReader(gzipped(t, doc)))
	if err != nil || gz.reject != nil || gz.size != int64(len(doc)) {
		t.Fatalf("envoi gzip : %+v, %v", gz, err)
	}
	if raw.sum != gz.sum {
		t.Error("l'empreinte doit porter sur le JSON, compressé ou non")
	}
	// Le blob d'un envoi brut est compressé ; celui d'un envoi gzip est gardé tel quel.
	if !bytes.HasPrefix(raw.gz, gzipMagic) {
		t.Error("blob brut non compressé")
	}

	if _, err := s.read(bytes.NewReader(make([]byte, s.limits.MaxUpload+1))); !errors.Is(err, ErrUploadTooLarge) {
		t.Errorf("envoi trop gros : %v", err)
	}
	bomb, err := s.read(bytes.NewReader(gzipped(t, bytes.Repeat([]byte(" "), int(s.limits.SBOM.MaxBytes)+1))))
	if err != nil || bomb.reject == nil || bomb.reject.Key != sbom.KeyTooLarge {
		t.Errorf("bombe gzip : %+v, %v", bomb.reject, err)
	}
	for name, data := range map[string][]byte{
		"vide":         {},
		"gzip tronqué": gzipped(t, doc)[:12],
		"gzip vide":    gzipped(t, nil),
		"en-tête seul": {0x1f, 0x8b, 0x08},
	} {
		up, err := s.read(bytes.NewReader(data))
		if err != nil || up.reject == nil || up.reject.Key != sbom.KeyMalformed {
			t.Errorf("%s : %+v, %v", name, up.reject, err)
		}
	}
}

func TestValidateContext(t *testing.T) {
	s := unitService()
	base := Context{ProjectID: uuid.New(), RefKind: project.RefBranch, RefName: "main",
		Commit: strings.Repeat("A", 40), AgentVersion: "1.0.0", ScannedAt: s.now().Add(-time.Minute)}
	ok := base
	if err := s.validate(&ok); err != nil || ok.Commit != strings.Repeat("a", 40) {
		t.Fatalf("contexte valide : %v (%q)", err, ok.Commit)
	}
	sha256Commit := base
	sha256Commit.Commit = strings.Repeat("b", 64)
	if err := s.validate(&sha256Commit); err != nil {
		t.Errorf("commit SHA-256 : %v", err)
	}
	host := base
	host.RefKind, host.Commit = project.RefHost, ""
	if err := s.validate(&host); err != nil {
		t.Errorf("hôte : %v", err)
	}
	cases := map[string]struct {
		change func(*Context)
		key    string
	}{
		"projet absent":     {func(c *Context) { c.ProjectID = uuid.Nil }, KeyRefInvalid},
		"nature inconnue":   {func(c *Context) { c.RefKind = "pr" }, KeyRefInvalid},
		"nom vide":          {func(c *Context) { c.RefName = "" }, KeyRefInvalid},
		"commit manquant":   {func(c *Context) { c.Commit = "" }, KeyCommitRequired},
		"commit court":      {func(c *Context) { c.Commit = "abc123" }, KeyCommitInvalid},
		"commit d'hôte":     {func(c *Context) { c.RefKind = project.RefHost }, KeyCommitForbid},
		"version illisible": {func(c *Context) { c.AgentVersion = "1.0 bêta" }, KeyVersionInvalid},
		"date absente":      {func(c *Context) { c.ScannedAt = time.Time{} }, KeyScannedAt},
		"date future":       {func(c *Context) { c.ScannedAt = s.now().Add(2 * time.Hour) }, KeyScannedAt},
		"date ancienne":     {func(c *Context) { c.ScannedAt = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }, KeyScannedAt},
	}
	for name, tc := range cases {
		c := base
		tc.change(&c)
		v, ok := account.IsValidation(s.validate(&c))
		if !ok || v.Key != tc.key {
			t.Errorf("%s : %v, attendu %s", name, v, tc.key)
		}
	}
	if len(ErrorKeys()) == 0 || len(ValidationKeys()) != 6 || len(Statuses()) != 4 {
		t.Error("listes de clés")
	}
}

func TestNewServiceChecksOptions(t *testing.T) {
	if _, err := NewService(Options{}); err == nil {
		t.Error("dépendances manquantes acceptées")
	}
	if wrap("x", nil) != nil {
		t.Error("wrap(nil)")
	}
	if !errors.Is(wrap("x", ErrRefUnknown), ErrRefUnknown) || truncate("abcdef", 3) != "abc" {
		t.Error("wrap ou truncate")
	}
}
