package repoagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/llm/llmtest"
)

// TestIncrementalPromptOmitsExcludedFiles : SEC2-07. En analyse incrémentale, les fichiers
// modifiés viennent de la forge sans filtre : un fichier exclu, par son nom (secrets,
// clés) ou par son contenu (clé privée détectée), n'est jamais nommé au fournisseur, ni
// dans le prompt ni dans une liste de répertoire.
func TestIncrementalPromptOmitsExcludedFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"deploy/prod/.env.production": "STRIPE_KEY=sk_live_x\n",
		"secrets/stripe-live.yaml":    "key: sk_live_x\n",
		"keys/id_ed25519":             "not really a key\n",
		"src/app.js":                  "console.log('app')\n",
		"src/notes.txt":               "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := &llmtest.Script{IsExternal: true, Steps: []llmtest.Step{
		llmtest.Tools(llmtest.Call{Name: toolListDir, Input: map[string]any{"path": "src"}}),
		submitOf(),
	}}
	rec := llmtest.Record(script)
	scope := []string{"deploy/prod/.env.production", "secrets/stripe-live.yaml", "keys/id_ed25519", "src/app.js", "src/notes.txt", "src/removed.js"}
	res := newTestEnricher(t, rec).enrich(context.Background(), enrichInput{Dir: dir, Project: "app", Commit: commitN(2),
		Mode: AIExternal, Scope: scope})
	if res.Status != EnrichmentComplete {
		t.Fatalf("%+v", res)
	}
	sent := rec.Sent()
	for _, leak := range []string{".env.production", "stripe-live", "id_ed25519", "notes.txt"} {
		if strings.Contains(sent, leak) {
			t.Errorf("fichier exclu nommé au fournisseur : %q", leak)
		}
	}
	for _, want := range []string{"- src/app.js", "- src/removed.js", `"name":"app.js"`} {
		if !strings.Contains(sent, want) {
			t.Errorf("%q absent des échanges", want)
		}
	}
}
