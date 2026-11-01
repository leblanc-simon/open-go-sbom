package repoagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/llm"
)

func call(t *testing.T, h llm.Handler, input any) (llm.Result, error) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return h(context.Background(), data)
}

func TestExclusions(t *testing.T) {
	e, err := newExclusions(append(DefaultExclude, "secret/*.json", "*.local"))
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]bool{
		".env": true, "app/.env.production": true, "deploy/id_rsa": true, "deploy/id_ed25519.pub": true,
		".ssh/config": true, "a/.aws/credentials": true, "certs/server.KEY": true, "secret/x.json": true, "x.local": true,
		".git/config": true, "terraform.tfstate": true, ".npmrc": true,
		"src/app.js": false, ".github/workflows/ci.yml": false, "envoy.yaml": false, "docs/keys.md": false, ".": false,
	} {
		if got := e.match(rel); got != want {
			t.Errorf("%s : %v", rel, got)
		}
	}
	if _, err := newExclusions([]string{"["}); err == nil {
		t.Error("motif invalide accepté")
	}
}

func TestWorkspacePaths(t *testing.T) {
	ws := verifyFixture(t)
	for p, ok := range map[string]bool{"": true, ".": true, "./src": true, "src/../src/app.js": true, "src\\app.js": true,
		"/etc": false, "../x": false, "src/../../x": false, "a\x00b": false} {
		_, err := ws.clean(p)
		if (err == nil) != ok {
			t.Errorf("clean(%q) : %v", p, err)
		}
	}
}

func TestToolsListReadSearch(t *testing.T) {
	ws := verifyFixture(t)
	tb := &toolbox{ws: ws}
	h := tb.handlers()

	res, err := call(t, h[toolListDir], map[string]string{"path": "."})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Contains(res.Content, ".env") || !strings.Contains(res.Content, `"Dockerfile"`) {
		t.Fatalf("liste : %s", res.Content)
	}
	// « / » désigne la racine du dépôt, jamais celle du système.
	if res, _ := call(t, h[toolListDir], map[string]string{"path": "/"}); strings.Contains(res.Content, `"etc"`) || !strings.Contains(res.Content, "Dockerfile") {
		t.Fatalf("list_dir / : %s", res.Content)
	}
	for _, p := range []string{"..", "../..", ".env", ".git", "/etc"} {
		res, _ := call(t, h[toolListDir], map[string]string{"path": p})
		if !res.IsError {
			t.Errorf("list_dir %q accepté : %s", p, res.Content)
		}
	}

	res, _ = call(t, h[toolRead], map[string]any{"path": "Dockerfile", "start_line": 2, "end_line": 2})
	var ex excerpt
	if err := json.Unmarshal([]byte(res.Content), &ex); err != nil || ex.Content != "2\tFROM node:20.11.1-alpine3.19 AS build\n" || ex.Total != 7 {
		t.Fatalf("read : %s", res.Content)
	}
	for _, p := range []string{".env", "config/key.yaml", "../../etc/passwd", "/etc/passwd", "bin/blob", "missing"} {
		res, err := call(t, h[toolRead], map[string]any{"path": p})
		if err != nil || !res.IsError || strings.Contains(res.Content, "4.17.21") {
			t.Errorf("read %q : %v %+v", p, err, res)
		}
	}
	// Un fichier exclu répond comme un fichier absent.
	excluded, _ := call(t, h[toolRead], map[string]any{"path": ".env"})
	missing, _ := call(t, h[toolRead], map[string]any{"path": "missing"})
	if excluded.Content != missing.Content {
		t.Fatalf("fichier exclu reconnaissable : %s / %s", excluded.Content, missing.Content)
	}
	if res, _ := call(t, h[toolRead], map[string]any{"path": "x", "extra": 1}); !res.IsError {
		t.Fatal("argument inconnu accepté")
	}

	res, _ = call(t, h[toolSearch], map[string]any{"pattern": `4\.17\.21`})
	if strings.Contains(res.Content, ".env") || strings.Contains(res.Content, "key.yaml") || !strings.Contains(res.Content, "src/app.js") {
		t.Fatalf("search : %s", res.Content)
	}
	res, _ = call(t, h[toolSearch], map[string]any{"pattern": "FROM", "glob": "Dockerfile", "max_results": 1})
	if !strings.Contains(res.Content, `"truncated":true`) || strings.Count(res.Content, `"path"`) != 1 {
		t.Fatalf("search bornée : %s", res.Content)
	}
	if res, _ := call(t, h[toolSearch], map[string]any{"pattern": "("}); !res.IsError {
		t.Fatal("expression invalide acceptée")
	}
}

func TestReadBudgetStopsAnalysis(t *testing.T) {
	ws := verifyFixture(t)
	ws.maxRead = 100
	tb := &toolbox{ws: ws}
	var err error
	for range 10 {
		if _, err = call(t, tb.handlers()[toolRead], map[string]any{"path": "Dockerfile"}); err != nil {
			break
		}
	}
	if !errors.Is(err, llm.ErrBudget) {
		t.Fatalf("budget de lecture non tenu : %v (%d octets)", err, ws.read)
	}
}

func TestLongLinesAreBounded(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("x", 5000) + "MARK" + strings.Repeat("y", 5000)
	if err := os.WriteFile(filepath.Join(dir, "min.js"), []byte(long+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excl, _ := newExclusions(nil)
	ws, _ := openWorkspace(dir, excl, 0)
	defer ws.Close()
	ex, err := ws.readLines("min.js", 1, 1)
	if err != nil || !ex.Truncated || len(ex.Content) > maxLineChars*4+32 {
		t.Fatalf("%v %d", err, len(ex.Content))
	}
	hits, _, err := ws.search(regexp.MustCompile("MARK"), "", 5)
	if err != nil || len(hits) != 1 || !strings.Contains(hits[0].Text, "MARK") || len([]rune(hits[0].Text)) > maxHitChars+2 {
		t.Fatalf("%v %+v", err, hits)
	}
}

func TestSubmitSchema(t *testing.T) {
	ok := map[string]any{"candidates": []map[string]any{{"name": "jquery", "version": "3.4.1", "purl": "pkg:npm/jquery@3.4.1",
		"file": "a.js", "line": 1, "excerpt": "jQuery v3.4.1", "confidence": 0.9}}}
	tooMany := make([]map[string]any, maxCandidates+1)
	for i := range tooMany {
		tooMany[i] = ok["candidates"].([]map[string]any)[0]
	}
	cases := map[string]any{
		"champ inconnu":         map[string]any{"candidates": []any{}, "note": "x"},
		"candidat incomplet":    map[string]any{"candidates": []map[string]any{{"name": "x"}}},
		"confiance hors bornes": map[string]any{"candidates": []map[string]any{{"name": "jquery", "version": "1", "purl": "p", "file": "f", "line": 1, "excerpt": "e", "confidence": 2}}},
		"ligne négative":        map[string]any{"candidates": []map[string]any{{"name": "jquery", "version": "1", "purl": "p", "file": "f", "line": -1, "excerpt": "e", "confidence": 0.5}}},
		"trop de candidats":     map[string]any{"candidates": tooMany},
		"pas un objet":          []int{1},
	}
	for name, in := range cases {
		tb := &toolbox{}
		res, err := call(t, tb.submit, in)
		if err != nil || !res.IsError || res.Done || tb.done || tb.schemaErrors != 1 {
			t.Errorf("%s : %v %+v", name, err, res)
		}
	}
	tb := &toolbox{}
	res, err := call(t, tb.submit, ok)
	if err != nil || !res.Done || len(tb.submitted) != 1 || tb.submitted[0].Confidence != 0.9 {
		t.Fatalf("%v %+v", err, res)
	}
	if res, _ := call(t, tb.submit, ok); !res.IsError {
		t.Fatal("seconde soumission acceptée")
	}
	if _, err := parseSubmission(json.RawMessage(`{"candidates":[]`)); err == nil {
		t.Fatal("JSON tronqué accepté")
	}
}
