//go:build evalai

package repoagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/llm"
	"leblanc.io/lotor/internal/llm/llmtest"
)

// Évaluation de l'enrichissement IA avec un vrai modèle sur le corpus annoté (make
// eval-ai), hors CI : elle coûte des appels au fournisseur. Configuration par variables
// d'environnement :
//
//	LOTOR_EVAL_AI_PROVIDER      anthropic, ollama, ou credulous (modèle fictif, sans clé :
//	                            contrôle des preuves et des annotations, pas une mesure)
//	LOTOR_EVAL_AI_PILOT_DIR     clones de l'échantillon pilote (scripts/ai-pilot-fetch.sh),
//	                            évalué à part du corpus (facultatif)
//	LOTOR_EVAL_AI_MODEL         modèle (défaut : claude-sonnet-5-5 ; obligatoire pour ollama)
//	LOTOR_EVAL_AI_API_KEY_FILE  clé d'API Anthropic (fichier 0600)
//	LOTOR_EVAL_AI_BASE_URL      API Anthropic (défaut https://api.anthropic.com)
//	LOTOR_EVAL_AI_OLLAMA_URL    serveur Ollama (défaut http://127.0.0.1:11434)
//	LOTOR_EVAL_AI_RUNS          passages du corpus (défaut 3), pour la variance
//	LOTOR_EVAL_AI_REPORT        fichier où écrire le rapport JSON (facultatif)
//	LOTOR_EVAL_AI_PRICE_*       prix en dollars par million de jetons : INPUT, OUTPUT,
//	                            CACHE_READ, CACHE_WRITE (défaut : tarif public de
//	                            claude-sonnet-5-5 au 1er novembre 2026, 0 pour ollama)
//
// Le test échoue si, sur le corpus ou sur l'échantillon pilote, le taux de faux positifs
// dépasse maxFPRate ou le rappel est sous minRecall, si un composant accepté n'a pas de
// preuve vérifiée (checkProof), ou si un témoin d'un dépôt hostile atteint le fournisseur.

type evalPrices struct{ Input, Output, CacheRead, CacheWrite float64 }

func (p evalPrices) cost(u llm.Usage) float64 {
	return (float64(u.InputTokens)*p.Input + float64(u.OutputTokens)*p.Output +
		float64(u.CacheReadTokens)*p.CacheRead + float64(u.CacheWriteTokens)*p.CacheWrite) / 1e6
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envFloat(t *testing.T, name string, def float64) float64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		t.Fatalf("%s : %v", name, err)
	}
	return f
}

func evalProvider(t *testing.T) (llm.Provider, evalPrices) {
	switch envOr("LOTOR_EVAL_AI_PROVIDER", "") {
	case "anthropic":
		key, err := ReadSecret(envOr("LOTOR_EVAL_AI_API_KEY_FILE", ""))
		if err != nil {
			t.Fatalf("LOTOR_EVAL_AI_API_KEY_FILE : %v", err)
		}
		p, err := llm.NewAnthropic(llm.AnthropicConfig{APIKey: strings.TrimSpace(string(key)),
			Model: envOr("LOTOR_EVAL_AI_MODEL", llm.DefaultAnthropicModel), BaseURL: envOr("LOTOR_EVAL_AI_BASE_URL", llm.DefaultAnthropicURL),
			Timeout: 5 * time.Minute, MaxRetries: 3})
		if err != nil {
			t.Fatal(err)
		}
		return p, evalPrices{Input: envFloat(t, "LOTOR_EVAL_AI_PRICE_INPUT", 2), Output: envFloat(t, "LOTOR_EVAL_AI_PRICE_OUTPUT", 10),
			CacheRead: envFloat(t, "LOTOR_EVAL_AI_PRICE_CACHE_READ", 0.2), CacheWrite: envFloat(t, "LOTOR_EVAL_AI_PRICE_CACHE_WRITE", 2.5)}
	case "ollama":
		model := envOr("LOTOR_EVAL_AI_MODEL", "")
		if model == "" {
			t.Fatal("LOTOR_EVAL_AI_MODEL obligatoire pour ollama")
		}
		p, err := llm.NewOllama(llm.OllamaConfig{URL: envOr("LOTOR_EVAL_AI_OLLAMA_URL", "http://127.0.0.1:11434"), Model: model,
			ContextTokens: 32768, Timeout: 10 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return p, evalPrices{Input: envFloat(t, "LOTOR_EVAL_AI_PRICE_INPUT", 0), Output: envFloat(t, "LOTOR_EVAL_AI_PRICE_OUTPUT", 0)}
	default:
		t.Fatal("LOTOR_EVAL_AI_PROVIDER : anthropic ou ollama (voir docs/operations.md, « Évaluer l'enrichissement IA »)")
	}
	return nil, evalPrices{}
}

type evalCaseReport struct {
	Case           string         `json:"case"`
	Run            int            `json:"run"`
	Status         string         `json:"status"`
	Error          string         `json:"error,omitempty"`
	TP             int            `json:"tp"`
	FP             int            `json:"fp"`
	FN             int            `json:"fn"`
	Ignored        int            `json:"ignored"`
	FalsePositives []string       `json:"false_positives,omitempty"`
	Missed         []string       `json:"missed,omitempty"`
	Rejected       map[string]int `json:"rejected,omitempty"`
	Turns          int            `json:"turns"`
	InputTokens    int64          `json:"input_tokens"`
	OutputTokens   int64          `json:"output_tokens"`
	CostUSD        float64        `json:"cost_usd"`
	DurationMS     int64          `json:"duration_ms"`
}

// evalSetReport est le rapport d'un jeu : le corpus synthétique ou l'échantillon pilote.
type evalSetReport struct {
	Name          string           `json:"name"`
	Analyses      int              `json:"analyses"`
	Incomplete    int              `json:"incomplete"`
	TP            int              `json:"tp"`
	FP            int              `json:"fp"`
	FN            int              `json:"fn"`
	Ignored       int              `json:"ignored"`
	Precision     float64          `json:"precision"`
	FPRate        float64          `json:"fp_rate"`
	Recall        float64          `json:"recall"`
	ProofChecked  int              `json:"proof_checked"`
	MeanCostUSD   float64          `json:"mean_cost_usd"`
	MeanTokensIn  float64          `json:"mean_input_tokens"`
	MeanTokensOut float64          `json:"mean_output_tokens"`
	Rejected      map[string]int   `json:"rejected,omitempty"`
	Cases         []evalCaseReport `json:"cases"`
}

type evalReport struct {
	Model  string          `json:"model"`
	Prompt string          `json:"prompt_version"`
	Date   string          `json:"date"`
	Runs   int             `json:"runs"`
	Sets   []evalSetReport `json:"sets"`
}

// pilotDir est l'annotation de l'échantillon pilote (testdata/ai-pilot/README.md) ; les
// dépôts eux-mêmes sont clonés par scripts/ai-pilot-fetch.sh dans
// LOTOR_EVAL_AI_PILOT_DIR.
const pilotDir = "../../testdata/ai-pilot"

func loadPilot(t *testing.T, clones string) []corpusCase {
	cases := loadAnnotations(t, pilotDir, func(name string) string { return filepath.Join(clones, name) })
	for _, c := range cases {
		out, err := exec.Command("git", "-C", c.Dir, "rev-parse", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(out)) != c.Source.Commit {
			t.Fatalf("%s : clone absent ou pas au commit %s (scripts/ai-pilot-fetch.sh %s) : %v", c.Name, c.Source.Commit, clones, err)
		}
	}
	return cases
}

// TestEvalAI évalue l'enrichissement sur le corpus et, avec LOTOR_EVAL_AI_PILOT_DIR, sur
// l'échantillon pilote. Avec LOTOR_EVAL_AI_PROVIDER=credulous, sans modèle ni clé, un
// modèle fictif soumet tout ce qu'il trouve (composants annotés, pièges, versions
// inventées, lignes porteuses d'un numéro, chemins détournés) : les seuils ne s'appliquent
// pas (ce modèle n'écarte aucun piège), mais aucun composant annoté ne doit être perdu
// (annotations prouvables) et chaque composant accepté doit avoir une preuve vérifiée.
// Pour tout fournisseur, chaque composant accepté est revérifié par checkProof.
func TestEvalAI(t *testing.T) {
	mode := envOr("LOTOR_EVAL_AI_PROVIDER", "")
	runs, err := strconv.Atoi(envOr("LOTOR_EVAL_AI_RUNS", "3"))
	if err != nil || runs < 1 {
		t.Fatal("LOTOR_EVAL_AI_RUNS : entier positif")
	}
	type set struct {
		name  string
		cases []corpusCase
	}
	sets := []set{{"corpus", loadCorpus(t)}}
	if dir := os.Getenv("LOTOR_EVAL_AI_PILOT_DIR"); dir != "" {
		sets = append(sets, set{"pilote", loadPilot(t, dir)})
	}
	var provider llm.Provider
	var prices evalPrices
	model := "fictif (credulous)"
	if mode == "credulous" {
		runs = 1
	} else {
		provider, prices = evalProvider(t)
		model = provider.Model()
	}
	cfg := testAIConfig()
	cfg.Timeout = 15 * time.Minute
	report := evalReport{Model: model, Prompt: PromptVersion, Date: time.Now().UTC().Format(time.RFC3339), Runs: runs}
	for _, st := range sets {
		sr := evalSetReport{Name: st.name, Rejected: map[string]int{}}
		var total score
		var cost, in, out float64
		for run := 1; run <= runs; run++ {
			for _, c := range st.cases {
				dir := stage(t, c)
				start := time.Now()
				var cr evalCaseReport
				var accepted []AcceptedComponent
				if provider == nil {
					r := runAdversarial(t, c, dir, adversarialCandidates(t, c, dir))
					accepted, sr.ProofChecked = r.Accepts, sr.ProofChecked+r.Checked
					cr = evalCaseReport{Case: c.Name, Run: run, Status: EnrichmentComplete, Rejected: map[string]int{"total": r.Rejected}}
				} else {
					rec := llmtest.Record(provider)
					local, external, aiMode := llm.Provider(nil), llm.Provider(rec), AIExternal
					if !provider.External() {
						local, external, aiMode = rec, nil, AILocal
					}
					e, err := newEnricher(cfg, local, external, testLogger(io.Discard))
					if err != nil {
						t.Fatal(err)
					}
					res := e.enrich(context.Background(), enrichInput{Dir: dir, Project: c.Name, Commit: commitN(run), Mode: aiMode})
					accepted = res.Accepted
					sr.ProofChecked += assertEveryAIComponentProven(t, c.Name, dir, res)
					cr = evalCaseReport{Case: c.Name, Run: run, Status: res.Status, Rejected: res.Verdict.Rejected, Turns: res.Turns,
						InputTokens: res.Usage.Input(), OutputTokens: res.Usage.OutputTokens, CostUSD: prices.cost(res.Usage)}
					if res.Err != nil {
						cr.Error = res.Err.Error()
						sr.Incomplete++
					}
					sent := rec.Sent()
					for _, leak := range append([]string{outsideCanary, "-----BEGIN"}, c.Canaries...) {
						if strings.Contains(sent, leak) {
							t.Errorf("%s : témoin %q envoyé au fournisseur", c.Name, leak)
						}
					}
				}
				cr.DurationMS = time.Since(start).Milliseconds()
				s := scoreCase(t, c, accepted)
				cr.TP, cr.FP, cr.FN, cr.Ignored, cr.FalsePositives, cr.Missed = s.TP, s.FP, s.FN, s.Ignored, s.FalsePositives, s.Missed
				for k, v := range cr.Rejected {
					sr.Rejected[k] += v
				}
				total = total.add(s)
				cost += cr.CostUSD
				in += float64(cr.InputTokens)
				out += float64(cr.OutputTokens)
				sr.Cases = append(sr.Cases, cr)
				t.Logf("%s/%s #%d : %s, %d/%d/%d/%d (TP/FP/FN/ignorés), %d tours, %.4f $", st.name, c.Name, run, cr.Status, s.TP, s.FP, s.FN, s.Ignored, cr.Turns, cr.CostUSD)
			}
		}
		sr.Analyses = len(sr.Cases)
		sr.TP, sr.FP, sr.FN, sr.Ignored = total.TP, total.FP, total.FN, total.Ignored
		sr.FPRate, sr.Recall = total.FPRate(), total.Recall()
		if total.TP+total.FP > 0 {
			sr.Precision = 1 - sr.FPRate
		}
		n := float64(sr.Analyses)
		sr.MeanCostUSD, sr.MeanTokensIn, sr.MeanTokensOut = cost/n, in/n, out/n
		sort.SliceStable(sr.Cases, func(i, j int) bool { return sr.Cases[i].Case < sr.Cases[j].Case })
		report.Sets = append(report.Sets, sr)

		fmt.Printf("Évaluation de l'enrichissement IA — %s — %s, prompt v%s, %d passage(s), %d analyses (%d incomplètes)\n",
			st.name, report.Model, report.Prompt, runs, sr.Analyses, sr.Incomplete)
		fmt.Printf("  acceptés à raison %d, faux positifs %d, oubliés %d, ignorés %d ; preuves revérifiées %d\n",
			total.TP, total.FP, total.FN, total.Ignored, sr.ProofChecked)
		fmt.Printf("  taux de faux positifs %.1f %% (seuil %.0f %%), rappel %.1f %% (seuil %.0f %%)\n",
			100*sr.FPRate, 100*maxFPRate, 100*sr.Recall, 100*minRecall)
		fmt.Printf("  coût moyen par analyse %.4f $ (%.0f jetons d'entrée, %.0f de sortie)\n", sr.MeanCostUSD, sr.MeanTokensIn, sr.MeanTokensOut)
		if len(total.FalsePositives) > 0 {
			fmt.Printf("  faux positifs : %s\n", strings.Join(total.FalsePositives, " ; "))
		}
		if len(total.Missed) > 0 {
			fmt.Printf("  oubliés : %s\n", strings.Join(total.Missed, " ; "))
		}
		if provider == nil {
			if total.FN != 0 {
				t.Errorf("%s : composants annotés non prouvables : %v", st.name, total.Missed)
			}
			continue
		}
		if sr.FPRate > maxFPRate {
			t.Errorf("%s : taux de faux positifs %.1f %% au-delà du seuil de %.0f %%", st.name, 100*sr.FPRate, 100*maxFPRate)
		}
		if sr.Recall < minRecall {
			t.Errorf("%s : rappel %.1f %% sous le seuil de %.0f %%", st.name, 100*sr.Recall, 100*minRecall)
		}
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	if path := os.Getenv("LOTOR_EVAL_AI_REPORT"); path != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
