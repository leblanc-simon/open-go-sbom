package repoagent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"leblanc.io/lotor/internal/llm"
)

// AIMode est le réglage d'enrichissement IA d'un projet, tel que le serveur le transmet
// (réglage du projet borné par la politique de l'instance).
type AIMode string

// Réglages d'enrichissement.
const (
	// AIDisabled : aucun modèle n'est appelé (défaut d'un projet non réglé).
	AIDisabled AIMode = "disabled"
	// AILocal : seul un modèle local (Ollama) peut recevoir le code.
	AILocal AIMode = "local"
	// AIExternal : un fournisseur externe peut recevoir le code ; à défaut, le modèle local.
	AIExternal AIMode = "external"
)

// Statuts d'enrichissement, écrits dans la propriété lotor:enrichment des métadonnées du
// SBOM.
const (
	// EnrichmentComplete : le modèle a analysé le commit et soumis ses candidats dans le
	// budget ; les composants IA sont ceux que le vérificateur a acceptés.
	EnrichmentComplete = "complete"
	// EnrichmentIncomplete : erreur du fournisseur, budget dépassé ou absence de
	// soumission ; le SBOM ne contient que les composants de Syft.
	EnrichmentIncomplete = "incomplete"
	// EnrichmentCarried : commit intermédiaire d'un rattrapage, sans appel au modèle ; les
	// composants IA précédents dont la preuve se vérifie encore sont reportés.
	EnrichmentCarried = "carried"
)

// PromptVersion est la version du prompt système embarqué (propriété
// lotor:enrichment-prompt). Toute modification du prompt crée un nouveau fichier et une
// nouvelle version.
const PromptVersion = "1"

//go:embed prompts/system-v1.md
var systemPrompt string

// PreviousComponent est un composant IA de l'instantané précédent d'une référence : sa
// preuve est revérifiée au nouveau commit, et son fichier fait partie de l'analyse
// incrémentale.
type PreviousComponent struct {
	PURL       string
	Name       string
	Version    string
	File       string
	Line       int
	Excerpt    string
	Confidence float64
	Model      string
}

// AcceptedComponent est un composant IA accepté, prêt à entrer dans le SBOM.
type AcceptedComponent struct {
	Accepted
	Model string
}

// enrichInput décrit une analyse IA.
type enrichInput struct {
	Dir     string
	Project string
	Commit  string
	Mode    AIMode
	// Scope liste les fichiers modifiés à examiner en priorité ; nil : analyse complète.
	Scope    []string
	Previous []PreviousComponent
}

// enrichResult est le résultat d'une analyse IA.
type enrichResult struct {
	// Status : vide si aucun modèle n'a été appelé, sinon complete ou incomplete.
	Status   string
	Model    string
	External bool
	Accepted []AcceptedComponent
	Verdict  Verdict
	Usage    llm.Usage
	Turns    int
	// Err est la cause d'un enrichissement incomplet.
	Err error
}

// enricher mène l'enrichissement IA d'une arborescence extraite.
type enricher struct {
	local, external llm.Provider
	cfg             AIConfig
	excl            exclusions
	log             *slog.Logger
}

func newEnricher(cfg AIConfig, local, external llm.Provider, log *slog.Logger) (*enricher, error) {
	excl, err := newExclusions(append(slices.Clone(DefaultExclude), cfg.Exclude...))
	if err != nil {
		return nil, err
	}
	if external != nil && !external.External() {
		return nil, errors.New("repoagent: le fournisseur externe se déclare local")
	}
	if local != nil && local.External() {
		// Un modèle « local » qui enverrait le code au-dehors contredirait le réglage
		// « modèle local uniquement » choisi pour un projet.
		return nil, errors.New("repoagent: le modèle local se déclare externe")
	}
	return &enricher{local: local, external: external, cfg: cfg, excl: excl, log: log}, nil
}

// provider choisit le modèle permis par le réglage du projet : rien pour un projet sans
// IA ; le fournisseur externe s'il est permis et configuré, sinon le modèle local.
func (e *enricher) provider(mode AIMode) llm.Provider {
	switch mode {
	case AIExternal:
		if e.external != nil {
			return e.external
		}
		if e.local != nil {
			return e.local
		}
	case AILocal:
		if e.local != nil {
			return e.local
		}
	}
	return nil
}

// carry revérifie les composants IA précédents sur l'arborescence, sans appeler de modèle
// (commits intermédiaires d'un rattrapage). Rien si le projet n'a pas d'IA permise.
func (e *enricher) carry(in enrichInput) enrichResult {
	if e.provider(in.Mode) == nil {
		return enrichResult{}
	}
	res := enrichResult{Status: EnrichmentCarried}
	ws, err := openWorkspace(in.Dir, e.excl, 0)
	if err != nil {
		return enrichResult{Status: EnrichmentIncomplete, Err: err}
	}
	defer ws.Close()
	cands := make([]Candidate, len(in.Previous))
	for i, pc := range in.Previous {
		cands[i] = Candidate{Name: pc.Name, Version: pc.Version, PURL: pc.PURL, File: pc.File, Line: pc.Line,
			Excerpt: pc.Excerpt, Confidence: pc.Confidence}
	}
	res.Verdict = verify(ws, cands)
	for _, a := range res.Verdict.Accepted {
		res.Accepted = append(res.Accepted, AcceptedComponent{Accepted: a, Model: in.Previous[a.index].Model})
	}
	sort.Slice(res.Accepted, func(i, j int) bool { return res.Accepted[i].PURL.String < res.Accepted[j].PURL.String })
	return res
}

// previousOf convertit des composants acceptés en composants précédents (analyse suivante).
func previousOf(acc []AcceptedComponent) []PreviousComponent {
	out := make([]PreviousComponent, len(acc))
	for i, a := range acc {
		out[i] = PreviousComponent{PURL: a.PURL.String, Name: a.Name, Version: a.Version, File: a.File, Line: a.Line,
			Excerpt: a.Excerpt, Confidence: a.Confidence, Model: a.Model}
	}
	return out
}

// maxScopeFiles borne la liste des fichiers d'une analyse incrémentale ; au-delà, l'analyse
// devient complète.
const maxScopeFiles = 200

// enrich mène l'analyse IA. Le résultat n'a des composants que si le modèle a soumis ses
// candidats dans le budget ; toute erreur du fournisseur, tout dépassement du budget ou
// une absence de soumission donnent un enrichissement incomplet, sans composant IA.
func (e *enricher) enrich(ctx context.Context, in enrichInput) enrichResult {
	p := e.provider(in.Mode)
	if p == nil {
		return enrichResult{}
	}
	res := enrichResult{Status: EnrichmentIncomplete, Model: p.Model(), External: p.External()}
	ws, err := openWorkspace(in.Dir, e.excl, int64(e.cfg.MaxReadKiB)<<10)
	if err != nil {
		res.Err = err
		return res
	}
	defer ws.Close()
	// Les fichiers modifiés viennent de la forge, sans filtre : un fichier exclu (secret,
	// clé) n'est jamais nommé dans le prompt (SEC2-07).
	if in.Scope != nil {
		in.Scope = slices.DeleteFunc(slices.Clone(in.Scope), func(f string) bool { return !ws.visible(f) })
	}
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	tb := &toolbox{ws: ws}
	out, err := llm.Run(ctx, llm.Session{
		Provider: p, System: systemPrompt, Prompt: userPrompt(in), Tools: aiTools, Handlers: tb.handlers(),
		MaxTokens: e.cfg.ResponseTokens,
		Budget: llm.Budget{MaxTurns: e.cfg.MaxTurns, MaxInputTokens: e.cfg.MaxInputTokens, MaxOutputTokens: e.cfg.MaxOutputTokens,
			MaxCallsPerTurn: maxToolCallsPerTurn},
		Reminder: "Call submit_candidates now with the candidates found so far (an empty list is valid).",
	})
	res.Usage, res.Turns = out.Usage, out.Turns
	if err == nil && !tb.done {
		err = llm.ErrNoResult
	}
	if err != nil {
		res.Err = err
		return res
	}
	// Les candidats du modèle passent d'abord : en double, c'est sa preuve qui reste.
	cands := slices.Clone(tb.submitted)
	models := make([]string, len(cands), len(cands)+len(in.Previous))
	for i := range models {
		models[i] = p.Model()
	}
	for _, pc := range in.Previous {
		cands = append(cands, Candidate{Name: pc.Name, Version: pc.Version, PURL: pc.PURL, File: pc.File, Line: pc.Line,
			Excerpt: pc.Excerpt, Confidence: pc.Confidence})
		models = append(models, cmpOr(pc.Model, p.Model()))
	}
	res.Verdict = verify(ws, cands)
	if tb.schemaErrors > 0 {
		if res.Verdict.Rejected == nil {
			res.Verdict.Rejected = map[string]int{}
		}
		res.Verdict.Rejected[RejectSchema] += tb.schemaErrors
	}
	for _, a := range res.Verdict.Accepted {
		res.Accepted = append(res.Accepted, AcceptedComponent{Accepted: a, Model: models[a.index]})
	}
	sort.Slice(res.Accepted, func(i, j int) bool { return res.Accepted[i].PURL.String < res.Accepted[j].PURL.String })
	res.Status = EnrichmentComplete
	return res
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// userPrompt décrit la tâche : analyse complète, ou incrémentale avec les fichiers
// modifiés et les composants IA précédents. Il ne contient que des données de l'analyse
// en cours (slug du projet, commit, chemins du dépôt).
func userPrompt(in enrichInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Repository: %s\nCommit: %s\n\n", in.Project, in.Commit)
	scope := in.Scope
	if scope != nil && len(scope) <= maxScopeFiles {
		b.WriteString("Incremental analysis. Files changed since the previous analysis (examine them first; ")
		b.WriteString("other files may be read when needed):\n")
		for _, f := range scope {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		if len(scope) == 0 {
			b.WriteString("- (none)\n")
		}
	} else {
		b.WriteString("Full analysis of the repository.\n")
	}
	if len(in.Previous) > 0 {
		b.WriteString("\nComponents found by the previous analysis (re-checked automatically; report them again only if their evidence moved):\n")
		for _, pc := range in.Previous {
			fmt.Fprintf(&b, "- %s (%s line %d)\n", pc.PURL, pc.File, pc.Line)
		}
	}
	b.WriteString("\nFind the undeclared third-party components and call submit_candidates once.")
	return b.String()
}

// logResult journalise un enrichissement : comptes, consommation et cause, jamais de
// contenu de fichier ni de candidat.
func (e *enricher) logResult(log *slog.Logger, res enrichResult, d time.Duration) {
	if res.Status == "" {
		return
	}
	attrs := []any{"status", res.Status, "model", res.Model, "external", res.External, "turns", res.Turns,
		"input_tokens", res.Usage.Input(), "output_tokens", res.Usage.OutputTokens, "accepted", len(res.Accepted),
		"rejected", res.Verdict.RejectedCount(), "duration", d.Round(time.Millisecond)}
	for _, k := range slices.Sorted(maps.Keys(res.Verdict.Rejected)) {
		attrs = append(attrs, "rejected_"+k, res.Verdict.Rejected[k])
	}
	if res.Err != nil {
		log.Warn("enrichissement IA incomplet : SBOM Syft seul", append(attrs, "err", res.Err)...)
		return
	}
	log.Info("enrichissement IA", attrs...)
}
