package repoagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"leblanc.io/lotor/internal/llm"
)

// Noms des outils proposés au modèle.
const (
	toolListDir = "list_dir"
	toolRead    = "read_file"
	toolSearch  = "search"
	toolSubmit  = "submit_candidates"
)

// maxCandidates borne une soumission.
const maxCandidates = 100

// Candidate est un composant proposé par le modèle, avec sa preuve.
type Candidate struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	PURL       string  `json:"purl"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Excerpt    string  `json:"excerpt"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason,omitempty"`
}

func str(desc string, maxLen int) map[string]any {
	return map[string]any{"type": "string", "description": desc, "minLength": 1, "maxLength": maxLen}
}

// candidateSchema est le schéma imposé à submit_candidates : il est envoyé au modèle et
// vérifié à la réception, avant toute autre lecture de la soumission.
var candidateSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"candidates"},
	"properties": map[string]any{
		"candidates": map[string]any{
			"type":     "array",
			"maxItems": maxCandidates,
			"items": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"name", "version", "purl", "file", "line", "excerpt", "confidence"},
				"properties": map[string]any{
					"name":       str("Component name as written in the evidence", 214),
					"version":    str("Exact version as written in the evidence", 128),
					"purl":       str("Package URL with the same name and version", 1024),
					"file":       str("File path relative to the repository root", 1024),
					"line":       map[string]any{"type": "integer", "minimum": 1, "description": "1-based line number of the evidence"},
					"excerpt":    str("Text copied verbatim from that line, containing the name and the version", 500),
					"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
					"reason":     map[string]any{"type": "string", "maxLength": 500, "description": "Why this is a shipped third-party component"},
				},
			},
		},
	},
}

var aiTools = []llm.Tool{
	{Name: toolListDir, Description: "List the entries of a directory of the repository (\".\" for the root). Files excluded from the analysis (secrets, keys, version-control data) are not listed.",
		Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path"},
			"properties": map[string]any{"path": str("Directory path relative to the repository root", 1024)}}},
	{Name: toolRead, Description: fmt.Sprintf("Read a range of lines of a text file of the repository (at most %d lines per call). Lines are numbered.", maxReadLines),
		Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path"},
			"properties": map[string]any{
				"path":       str("File path relative to the repository root", 1024),
				"start_line": map[string]any{"type": "integer", "minimum": 1},
				"end_line":   map[string]any{"type": "integer", "minimum": 1},
			}}},
	{Name: toolSearch, Description: fmt.Sprintf("Search text files of the repository for a regular expression (RE2 syntax), optionally restricted to a file glob; at most %d matching lines.", maxSearchHits),
		Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"pattern"},
			"properties": map[string]any{
				"pattern":     str("Regular expression (RE2)", 500),
				"glob":        map[string]any{"type": "string", "maxLength": 200, "description": "File glob, e.g. *.js or web/*.html"},
				"max_results": map[string]any{"type": "integer", "minimum": 1, "maximum": maxSearchHits},
			}}},
	{Name: toolSubmit, Description: "Submit all candidate components with their evidence. Call it exactly once, at the end.", Schema: candidateSchema},
}

// submitValidator vérifie une soumission contre candidateSchema.
var submitValidator = mustCompileSchema(candidateSchema)

func mustCompileSchema(schema map[string]any) *jsonschema.Schema {
	c := jsonschema.NewCompiler()
	// Le schéma Go n'a que des types JSON simples : un aller-retour le rend lisible par
	// le compilateur (tranches typées comprises).
	data, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	if err := c.AddResource("mem://submit.json", doc); err != nil {
		panic(err)
	}
	return c.MustCompile("mem://submit.json")
}

// parseSubmission valide une soumission par le schéma, puis la décode.
func parseSubmission(input json.RawMessage) ([]Candidate, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := submitValidator.Validate(inst); err != nil {
		return nil, errors.New("submission does not match the schema")
	}
	var s struct {
		Candidates []Candidate `json:"candidates"`
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("invalid submission: %w", err)
	}
	return s.Candidates, nil
}

// toolbox exécute les outils du modèle sur un répertoire d'analyse.
type toolbox struct {
	ws *workspace
	// submitted reçoit la soumission validée ; schemaErrors compte les refus du schéma.
	submitted    []Candidate
	done         bool
	schemaErrors int
}

func (t *toolbox) handlers() map[string]llm.Handler {
	return map[string]llm.Handler{
		toolListDir: t.listDir,
		toolRead:    t.readFile,
		toolSearch:  t.search,
		toolSubmit:  t.submit,
	}
}

// data présente un résultat d'outil comme une donnée JSON.
func data(v any) (llm.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return llm.Result{}, err
	}
	return llm.Result{Content: string(b)}, nil
}

// toolError renvoie au modèle une erreur d'usage ; le budget épuisé arrête l'analyse.
func toolError(err error) (llm.Result, error) {
	switch {
	case errors.Is(err, errReadBudget):
		return llm.Result{}, fmt.Errorf("%w : octets lus", llm.ErrBudget)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errExcluded):
		// Un fichier exclu répond comme un fichier absent : rien n'en est révélé.
		return llm.Result{Content: `{"error":"not found"}`, IsError: true}, nil
	case errors.Is(err, errNotText):
		return llm.Result{Content: `{"error":"not a text file or too large"}`, IsError: true}, nil
	case errors.Is(err, errBadPath):
		return llm.Result{Content: `{"error":"invalid path"}`, IsError: true}, nil
	default:
		return llm.Result{Content: `{"error":"unreadable"}`, IsError: true}, nil
	}
}

func decodeInput(input json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func badInput() (llm.Result, error) {
	return llm.Result{Content: `{"error":"invalid arguments"}`, IsError: true}, nil
}

func (t *toolbox) listDir(_ context.Context, input json.RawMessage) (llm.Result, error) {
	var in struct {
		Path string `json:"path"`
	}
	if decodeInput(input, &in) != nil {
		return badInput()
	}
	entries, truncated, err := t.ws.listDir(in.Path)
	if err != nil {
		return toolError(err)
	}
	type item struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size int64  `json:"size,omitempty"`
	}
	out := struct {
		Path      string `json:"path"`
		Entries   []item `json:"entries"`
		Truncated bool   `json:"truncated,omitempty"`
	}{Path: in.Path, Entries: []item{}, Truncated: truncated}
	size := 0
	for _, e := range entries {
		it := item{Name: e.Name, Type: "file", Size: e.Size}
		if e.Dir {
			it.Type = "dir"
		}
		out.Entries = append(out.Entries, it)
		size += len(e.Name) + 24
	}
	if err := t.ws.charge(size); err != nil {
		return toolError(err)
	}
	return data(out)
}

func (t *toolbox) readFile(_ context.Context, input json.RawMessage) (llm.Result, error) {
	var in struct {
		Path  string `json:"path"`
		Start int    `json:"start_line"`
		End   int    `json:"end_line"`
	}
	if decodeInput(input, &in) != nil || in.Path == "" {
		return badInput()
	}
	ex, err := t.ws.readLines(in.Path, in.Start, in.End)
	if err != nil {
		return toolError(err)
	}
	return data(ex)
}

func (t *toolbox) search(ctx context.Context, input json.RawMessage) (llm.Result, error) {
	var in struct {
		Pattern string `json:"pattern"`
		Glob    string `json:"glob"`
		Max     int    `json:"max_results"`
	}
	if decodeInput(input, &in) != nil || in.Pattern == "" || len(in.Pattern) > 500 || len(in.Glob) > 200 {
		return badInput()
	}
	re, err := regexp.Compile(in.Pattern)
	if err != nil {
		return llm.Result{Content: `{"error":"invalid regular expression"}`, IsError: true}, nil
	}
	glob := strings.TrimPrefix(strings.TrimSpace(in.Glob), "./")
	hits, truncated, err := t.ws.search(ctx, re, glob, in.Max)
	if ctx.Err() != nil {
		// Délai de l'analyse dépassé pendant la recherche : la boucle s'arrête.
		return llm.Result{}, ctx.Err()
	}
	if err != nil {
		return toolError(err)
	}
	if hits == nil {
		hits = []searchHit{}
	}
	return data(struct {
		Hits      []searchHit `json:"hits"`
		Truncated bool        `json:"truncated,omitempty"`
	}{hits, truncated})
}

func (t *toolbox) submit(_ context.Context, input json.RawMessage) (llm.Result, error) {
	if t.done {
		return llm.Result{Content: `{"error":"already submitted"}`, IsError: true}, nil
	}
	cands, err := parseSubmission(input)
	if err != nil {
		t.schemaErrors++
		return llm.Result{Content: fmt.Sprintf(`{"error":%q}`, err.Error()), IsError: true}, nil
	}
	t.submitted, t.done = cands, true
	return llm.Result{Content: fmt.Sprintf(`{"received":%d}`, len(cands)), Done: true}, nil
}
