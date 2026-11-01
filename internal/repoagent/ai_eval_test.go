//go:build evalai

package repoagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
//	LOTOR_EVAL_AI_PROVIDER      anthropic ou ollama (obligatoire)
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
// Le test échoue si le taux de faux positifs dépasse maxFPRate ou si le rappel est sous
// minRecall, ou si un témoin d'un dépôt hostile atteint le fournisseur.

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
	FalsePositives []string       `json:"false_positives,omitempty"`
	Missed         []string       `json:"missed,omitempty"`
	Rejected       map[string]int `json:"rejected,omitempty"`
	Turns          int            `json:"turns"`
	InputTokens    int64          `json:"input_tokens"`
	OutputTokens   int64          `json:"output_tokens"`
	CostUSD        float64        `json:"cost_usd"`
	DurationMS     int64          `json:"duration_ms"`
}

type evalReport struct {
	Model         string           `json:"model"`
	Prompt        string           `json:"prompt_version"`
	Date          string           `json:"date"`
	Runs          int              `json:"runs"`
	Analyses      int              `json:"analyses"`
	Incomplete    int              `json:"incomplete"`
	TP            int              `json:"tp"`
	FP            int              `json:"fp"`
	FN            int              `json:"fn"`
	Precision     float64          `json:"precision"`
	FPRate        float64          `json:"fp_rate"`
	Recall        float64          `json:"recall"`
	MeanCostUSD   float64          `json:"mean_cost_usd"`
	MeanTokensIn  float64          `json:"mean_input_tokens"`
	MeanTokensOut float64          `json:"mean_output_tokens"`
	Cases         []evalCaseReport `json:"cases"`
}

func TestEvalAI(t *testing.T) {
	provider, prices := evalProvider(t)
	runs, err := strconv.Atoi(envOr("LOTOR_EVAL_AI_RUNS", "3"))
	if err != nil || runs < 1 {
		t.Fatal("LOTOR_EVAL_AI_RUNS : entier positif")
	}
	cfg := testAIConfig()
	cfg.Timeout = 15 * time.Minute
	report := evalReport{Model: provider.Model(), Prompt: PromptVersion, Date: time.Now().UTC().Format(time.RFC3339), Runs: runs}
	var total score
	var cost, in, out float64
	for run := 1; run <= runs; run++ {
		for _, c := range loadCorpus(t) {
			dir := stage(t, c)
			rec := llmtest.Record(provider)
			local, external, mode := llm.Provider(nil), llm.Provider(rec), AIExternal
			if !provider.External() {
				local, external, mode = rec, nil, AILocal
			}
			e, err := newEnricher(cfg, local, external, testLogger(io.Discard))
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			res := e.enrich(context.Background(), enrichInput{Dir: dir, Project: c.Name, Commit: commitN(run), Mode: mode})
			cr := evalCaseReport{Case: c.Name, Run: run, Status: res.Status, Rejected: res.Verdict.Rejected, Turns: res.Turns,
				InputTokens: res.Usage.Input(), OutputTokens: res.Usage.OutputTokens, CostUSD: prices.cost(res.Usage),
				DurationMS: time.Since(start).Milliseconds()}
			if res.Err != nil {
				cr.Error = res.Err.Error()
				report.Incomplete++
			}
			s := scoreCase(t, c, res.Accepted)
			cr.TP, cr.FP, cr.FN, cr.FalsePositives, cr.Missed = s.TP, s.FP, s.FN, s.FalsePositives, s.Missed
			total = total.add(s)
			cost += cr.CostUSD
			in += float64(cr.InputTokens)
			out += float64(cr.OutputTokens)
			report.Cases = append(report.Cases, cr)
			sent := rec.Sent()
			for _, leak := range append([]string{outsideCanary, "-----BEGIN"}, c.Canaries...) {
				if strings.Contains(sent, leak) {
					t.Errorf("%s : témoin %q envoyé au fournisseur", c.Name, leak)
				}
			}
			t.Logf("%s #%d : %s, %d/%d/%d (TP/FP/FN), %d tours, %.4f $", c.Name, run, res.Status, s.TP, s.FP, s.FN, res.Turns, cr.CostUSD)
		}
	}
	report.Analyses = len(report.Cases)
	report.TP, report.FP, report.FN = total.TP, total.FP, total.FN
	report.FPRate, report.Recall = total.FPRate(), total.Recall()
	if total.TP+total.FP > 0 {
		report.Precision = 1 - report.FPRate
	}
	n := float64(report.Analyses)
	report.MeanCostUSD, report.MeanTokensIn, report.MeanTokensOut = cost/n, in/n, out/n
	sort.SliceStable(report.Cases, func(i, j int) bool { return report.Cases[i].Case < report.Cases[j].Case })
	data, _ := json.MarshalIndent(report, "", "  ")
	if path := os.Getenv("LOTOR_EVAL_AI_REPORT"); path != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("Évaluation de l'enrichissement IA — %s, prompt v%s, %d passage(s), %d analyses (%d incomplètes)\n",
		report.Model, report.Prompt, runs, report.Analyses, report.Incomplete)
	fmt.Printf("  acceptés à raison %d, faux positifs %d, oubliés %d\n", total.TP, total.FP, total.FN)
	fmt.Printf("  taux de faux positifs %.1f %% (seuil %.0f %%), rappel %.1f %% (seuil %.0f %%)\n",
		100*report.FPRate, 100*maxFPRate, 100*report.Recall, 100*minRecall)
	fmt.Printf("  coût moyen par analyse %.4f $ (%.0f jetons d'entrée, %.0f de sortie)\n", report.MeanCostUSD, report.MeanTokensIn, report.MeanTokensOut)
	if len(total.FalsePositives) > 0 {
		fmt.Printf("  faux positifs : %s\n", strings.Join(total.FalsePositives, " ; "))
	}
	if len(total.Missed) > 0 {
		fmt.Printf("  oubliés : %s\n", strings.Join(total.Missed, " ; "))
	}
	if report.FPRate > maxFPRate {
		t.Errorf("taux de faux positifs %.1f %% au-delà du seuil de %.0f %%", 100*report.FPRate, 100*maxFPRate)
	}
	if report.Recall < minRecall {
		t.Errorf("rappel %.1f %% sous le seuil de %.0f %%", 100*report.Recall, 100*minRecall)
	}
}
