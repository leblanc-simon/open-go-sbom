package repoagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"

	"leblanc.io/lotor/internal/llm"
	"leblanc.io/lotor/internal/llm/llmtest"
	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

func corpusCaseNamed(t *testing.T, name string) corpusCase {
	t.Helper()
	for _, c := range loadCorpus(t) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cas %s absent", name)
	return corpusCase{}
}

// syftBOM est un SBOM Syft minimal : express trouvé dans package.json.
func syftBOM() *cyclonedx.BOM {
	comps := []cyclonedx.Component{{BOMRef: "pkg:npm/express@4.18.2", Type: cyclonedx.ComponentTypeLibrary, Name: "express",
		Version: "4.18.2", PackageURL: "pkg:npm/express@4.18.2",
		Properties: &[]cyclonedx.Property{{Name: sbomsyft.PropOrigin, Value: originSyft}}}}
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "app"}}
	bom.Components = &comps
	return bom
}

func metaProp(bom *cyclonedx.BOM, name string) string {
	if bom.Metadata == nil || bom.Metadata.Properties == nil {
		return ""
	}
	for _, p := range *bom.Metadata.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

type aiHarness struct {
	agent  *Agent
	srv    *fakeServer
	forge  *fakeForge
	key    refKey
	track  tracked
	src    string
	script *llmtest.Script
}

func newAIHarness(t *testing.T, mode AIMode, steps ...llmtest.Step) *aiHarness {
	t.Helper()
	c := corpusCaseNamed(t, "vendored-js")
	h := &aiHarness{srv: &fakeServer{ai: map[string][]PreviousComponent{}}, forge: &fakeForge{name: "fake"},
		src: stage(t, c), script: &llmtest.Script{ModelName: "claude-test", IsExternal: true, Steps: steps}}
	h.agent = newTestAgent(t, h.srv, h.forge, io.Discard, func(o *Options) {
		o.AI = testAIConfig()
		o.ExternalModel = h.script
	})
	p := Project{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", AIMode: mode,
		Refs: []TrackedRef{{ID: "r1", Ref: mainRef}}}
	h.key = refKey{project: "p1", ref: mainRef}
	h.track = tracked{project: p, ref: p.Refs[0], forge: h.forge, repo: "acme/app"}
	return h
}

func (h *aiHarness) run(commit string, head bool) *cyclonedx.BOM {
	bom := syftBOM()
	h.agent.enrich(context.Background(), h.key, h.track, h.src, commit, head, bom)
	return bom
}

var jqueryCandidate = Candidate{Name: "jquery", Version: "3.4.1", PURL: "pkg:npm/jquery@3.4.1", File: "public/js/vendor/jquery.min.js",
	Line: 1, Excerpt: "jQuery v3.4.1", Confidence: 0.97}

// TestDisabledProjectNeverCallsModel : un projet réglé « IA désactivée » (ou non réglé)
// n'appelle jamais de modèle, et son SBOM reste celui de Syft (critère d'acceptation).
func TestDisabledProjectNeverCallsModel(t *testing.T) {
	for _, mode := range []AIMode{AIDisabled, "", "inconnu"} {
		h := newAIHarness(t, mode, submitOf(jqueryCandidate))
		bom := h.run(commitN(1), true)
		if h.script.Calls() != 0 || h.srv.aiCalls != 0 {
			t.Fatalf("%q : modèle appelé %d fois", mode, h.script.Calls())
		}
		if len(*bom.Components) != 1 || bom.Metadata.Properties != nil {
			t.Fatalf("%q : SBOM modifié", mode)
		}
	}
	// « Modèle local uniquement » sans modèle local : rien n'est envoyé au fournisseur
	// externe.
	h := newAIHarness(t, AILocal, submitOf(jqueryCandidate))
	h.run(commitN(1), true)
	if h.script.Calls() != 0 {
		t.Fatal("fournisseur externe appelé pour un projet « local uniquement »")
	}
}

func TestEnrichAddsProvenComponents(t *testing.T) {
	h := newAIHarness(t, AIExternal, submitOf(jqueryCandidate, Candidate{Name: "express", Version: "4.18.2",
		PURL: "pkg:npm/express@4.18.2", File: "package.json", Line: 5, Excerpt: `"express": "4.18.2"`, Confidence: 0.9}))
	bom := h.run(commitN(1), true)
	if metaProp(bom, PropEnrichment) != EnrichmentComplete || metaProp(bom, PropEnrichmentModel) != "claude-test" ||
		metaProp(bom, PropEnrichmentPrompt) != PromptVersion {
		t.Fatalf("métadonnées : %+v", *bom.Metadata.Properties)
	}
	data, err := encodeBOM(bom)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbomsyft.Decode(sbom.FormatCycloneDX, data)
	if err != nil {
		t.Fatalf("%v : %v\n%s", err, errors.Unwrap(err), data)
	}
	if doc.Enrichment != sbom.EnrichmentComplete || doc.EnrichmentModel != "claude-test" {
		t.Fatalf("statut relu : %q %q", doc.Enrichment, doc.EnrichmentModel)
	}
	var ia, syftN int
	for _, c := range doc.Components {
		switch c.Origin {
		case sbom.OriginIA:
			ia++
			if c.PURL != "pkg:npm/jquery@3.4.1" || c.Confidence == nil || *c.Confidence != 0.97 || c.Model != "claude-test" {
				t.Fatalf("composant IA : %+v", c)
			}
			occ, ok := sbom.FirstOccurrence(c.Evidence)
			if !ok || occ.Location != "public/js/vendor/jquery.min.js" || occ.Line != 1 || occ.Excerpt != "jQuery v3.4.1" {
				t.Fatalf("preuve : %s", c.Evidence)
			}
			if len(c.Hashes) != 1 || !strings.HasPrefix(c.Hashes[0], "sha256:") {
				t.Fatalf("empreinte du fichier : %v", c.Hashes)
			}
		default:
			syftN++
		}
	}
	// express est dans un manifeste (rejeté) et déjà trouvé par Syft : il reste d'origine
	// Syft, une seule fois.
	if ia != 1 || syftN != 1 {
		t.Fatalf("ia=%d syft=%d : %+v", ia, syftN, doc.Components)
	}
}

func TestMergeSyftWins(t *testing.T) {
	bom := syftBOM()
	p, _ := sbom.CanonicalPURL("pkg:npm/express@4.18.2")
	res := enrichResult{Status: EnrichmentComplete, Model: "m", Accepted: []AcceptedComponent{{Accepted: Accepted{
		Candidate: Candidate{Name: "express", Version: "4.18.2", File: "vendor/express.js", Excerpt: "express 4.18.2", Confidence: 0.5},
		PURL:      p, Line: 1}, Model: "m"}}}
	if n := mergeAI(bom, res, nil); n != 0 || len(*bom.Components) != 1 {
		t.Fatalf("doublon ajouté : %d", n)
	}
	if mergeAI(syftBOM(), enrichResult{}, nil) != 0 {
		t.Fatal("sans enrichissement")
	}
	inc := syftBOM()
	mergeAI(inc, enrichResult{Status: EnrichmentIncomplete, Model: "m", Accepted: res.Accepted}, nil)
	if len(*inc.Components) != 1 || metaProp(inc, PropEnrichment) != EnrichmentIncomplete {
		t.Fatal("enrichissement incomplet : SBOM Syft seul attendu")
	}
}

// TestIncompleteEnrichmentSendsSyftOnly : une erreur du fournisseur donne le SBOM Syft
// seul, marqué « enrichissement incomplet », sans faire échouer l'analyse.
func TestIncompleteEnrichmentSendsSyftOnly(t *testing.T) {
	h := newAIHarness(t, AIExternal, llmtest.Fail(errors.New("overloaded")))
	bom := h.run(commitN(1), true)
	if metaProp(bom, PropEnrichment) != EnrichmentIncomplete || len(*bom.Components) != 1 {
		t.Fatalf("%+v", bom.Metadata.Properties)
	}
	if _, ok := h.agent.aiState[h.key]; ok {
		t.Fatal("état avancé malgré l'échec")
	}
}

// TestIncrementalAnalysis : après un redémarrage, les composants IA de l'instantané
// courant sont lus au serveur et l'analyse est complète ; ensuite, le modèle reçoit les
// fichiers modifiés (comparaison de la forge) et les composants précédents, revérifiés.
// Un commit intermédiaire d'un rattrapage ne fait que reporter ce qui reste prouvé.
func TestIncrementalAnalysis(t *testing.T) {
	prev := PreviousComponent{PURL: "pkg:npm/jquery@3.4.1", Name: "jquery", Version: "3.4.1", File: "public/js/vendor/jquery.min.js",
		Line: 1, Excerpt: "jQuery v3.4.1", Confidence: 0.9, Model: "older-model"}
	empty := submitOf()
	h := newAIHarness(t, AIExternal, empty, empty)
	rec := llmtest.Record(h.script)
	h.agent.ai.external = rec
	h.srv.ai["r1"] = []PreviousComponent{prev}
	h.forge.files = []string{"public/js/app.js"}

	bom := h.run(commitN(1), true)
	if h.srv.aiCalls != 1 || h.forge.compares != 0 {
		t.Fatalf("premier passage : %d lectures, %d comparaisons", h.srv.aiCalls, h.forge.compares)
	}
	first := rec.Exchanges()[0].Request.Messages[0].Blocks[0].Text
	if !strings.Contains(first, "Full analysis") || !strings.Contains(first, prev.PURL) {
		t.Fatalf("prompt : %s", first)
	}
	// Le composant précédent est revérifié et reporté avec son modèle d'origine.
	comps := *bom.Components
	if len(comps) != 2 || (*comps[1].Properties)[2].Value != "older-model" {
		t.Fatalf("report : %+v", comps)
	}

	h.run(commitN(2), true)
	if h.srv.aiCalls != 1 || h.forge.compares != 1 {
		t.Fatalf("second passage : %d lectures, %d comparaisons", h.srv.aiCalls, h.forge.compares)
	}
	second := rec.Exchanges()[1].Request.Messages[0].Blocks[0].Text
	if !strings.Contains(second, "Incremental analysis") || !strings.Contains(second, "- public/js/app.js") {
		t.Fatalf("prompt incrémental : %s", second)
	}

	calls := h.script.Calls()
	bom = h.run(commitN(3), false)
	if h.script.Calls() != calls || metaProp(bom, PropEnrichment) != EnrichmentCarried || len(*bom.Components) != 2 {
		t.Fatalf("commit intermédiaire : %d appels, %+v", h.script.Calls()-calls, bom.Metadata.Properties)
	}

	// full_interval écoulé : analyse complète, sans comparaison.
	h.agent.now = func() time.Time { return time.Now().Add(200 * time.Hour) }
	h.script.Steps = append(h.script.Steps, empty)
	h.run(commitN(4), true)
	if h.forge.compares != 1 || !strings.Contains(rec.Exchanges()[2].Request.Messages[0].Blocks[0].Text, "Full analysis") {
		t.Fatal("analyse complète attendue à full_interval")
	}
}

func TestIncrementalFallsBackToFull(t *testing.T) {
	empty := submitOf()
	h := newAIHarness(t, AIExternal, empty, empty)
	h.srv.aiErr = errors.New("indisponible")
	h.run(commitN(1), true)
	h.forge.failCmp = true
	rec := llmtest.Record(h.script)
	h.agent.ai.external = rec
	h.run(commitN(2), true)
	if !strings.Contains(rec.Exchanges()[0].Request.Messages[0].Blocks[0].Text, "Full analysis") {
		t.Fatal("comparaison impossible : analyse complète attendue")
	}
}

func TestAIConfigValidateAndModels(t *testing.T) {
	ok := testAIConfig()
	if errs := ok.validate(); len(errs) != 0 {
		t.Fatal(errs)
	}
	bad := []func(*AIConfig){
		func(a *AIConfig) { a.MaxTurns = 0 },
		func(a *AIConfig) { a.ResponseTokens = 100_000 },
		func(a *AIConfig) { a.MaxReadKiB = 1 },
		func(a *AIConfig) { a.FullInterval = time.Minute },
		func(a *AIConfig) { a.Exclude = []string{"["} },
		func(a *AIConfig) { a.Local.URL = "ftp://x" },
		func(a *AIConfig) { a.Local.URL = "http://127.0.0.1:11434" },
		func(a *AIConfig) { a.External.Provider = "openai" },
		func(a *AIConfig) {
			a.External = ExternalAIConfig{Provider: "anthropic", Model: "m", APIKeyFile: "/k", BaseURL: "http://api", Timeout: time.Second}
		},
	}
	for i, mutate := range bad {
		c := testAIConfig()
		mutate(&c)
		if len(c.validate()) == 0 {
			t.Errorf("cas %d accepté", i)
		}
	}
	local, ext, err := ok.Models()
	if err != nil || local != nil || ext != nil {
		t.Fatalf("sans modèle : %v %v %v", local, ext, err)
	}
	c := testAIConfig()
	c.Local = LocalAIConfig{URL: "http://127.0.0.1:11434", Model: "qwen3", Timeout: time.Minute}
	c.External = ExternalAIConfig{Provider: "anthropic", Model: llm.DefaultAnthropicModel, APIKeyFile: writeSecret(t, t.TempDir(), "key", "sk-test\n", 0o600),
		BaseURL: llm.DefaultAnthropicURL, Timeout: time.Minute, Retries: 2}
	local, ext, err = c.Models()
	if err != nil || local == nil || ext == nil || local.External() || !ext.External() || ext.Model() != "claude-sonnet-5-5" {
		t.Fatalf("%v %v %v", local, ext, err)
	}
	c.External.APIKeyFile = "/nonexistent"
	if _, _, err := c.Models(); err == nil {
		t.Fatal("clé absente acceptée")
	}
}

func TestUserPrompt(t *testing.T) {
	p := userPrompt(enrichInput{Project: "app", Commit: "abc", Scope: []string{}})
	if !strings.Contains(p, "Incremental") || !strings.Contains(p, "(none)") {
		t.Fatal(p)
	}
	many := make([]string, maxScopeFiles+1)
	if p := userPrompt(enrichInput{Scope: many}); !strings.Contains(p, "Full analysis") {
		t.Fatal("trop de fichiers : analyse complète attendue")
	}
}

// TestSystemPromptEmbedded : le prompt système versionné est embarqué et rappelle que le
// contenu du dépôt est une donnée.
func TestSystemPromptEmbedded(t *testing.T) {
	if !strings.Contains(systemPrompt, "untrusted data") || !strings.Contains(systemPrompt, toolSubmit) {
		t.Fatal("prompt système incomplet")
	}
	for _, tool := range aiTools {
		if _, err := json.Marshal(tool.Schema); err != nil {
			t.Fatal(err)
		}
	}
}
