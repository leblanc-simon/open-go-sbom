package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"leblanc.io/lotor/internal/llm"
	"leblanc.io/lotor/internal/llm/llmtest"
)

func echoHandlers(done *int) map[string]llm.Handler {
	return map[string]llm.Handler{
		"look": func(_ context.Context, in json.RawMessage) (llm.Result, error) {
			return llm.Result{Content: "seen " + string(in)}, nil
		},
		"submit": func(_ context.Context, in json.RawMessage) (llm.Result, error) {
			*done++
			return llm.Result{Content: "ok", Done: true}, nil
		},
	}
}

func TestRunEndsOnFinalTool(t *testing.T) {
	var done int
	script := &llmtest.Script{Usage: llm.Usage{InputTokens: 10, OutputTokens: 2}, Steps: []llmtest.Step{
		llmtest.Tools(llmtest.Call{Name: "look", Input: map[string]string{"p": "a"}}),
		llmtest.Tools(llmtest.Call{Name: "submit", Input: map[string]any{}}),
	}}
	rec := llmtest.Record(script)
	out, err := llm.Run(context.Background(), llm.Session{Provider: rec, System: "sys", Prompt: "go", Handlers: echoHandlers(&done)})
	if err != nil || !out.Done || out.Turns != 2 || done != 1 {
		t.Fatalf("Run = %+v, %v (done %d)", out, err, done)
	}
	if out.Usage.InputTokens != 20 || out.Usage.OutputTokens != 4 {
		t.Fatalf("usage = %+v", out.Usage)
	}
	ex := rec.Exchanges()
	last := ex[1].Request.Messages
	if len(last) != 3 || last[2].Blocks[0].ToolResult.Content != `seen {"p":"a"}` {
		t.Fatalf("résultat d'outil non renvoyé : %+v", last)
	}
}

func TestRunBudget(t *testing.T) {
	loop := llmtest.Tools(llmtest.Call{Name: "look", Input: 1})
	cases := []struct {
		name   string
		budget llm.Budget
		usage  llm.Usage
	}{
		{"tours", llm.Budget{MaxTurns: 3}, llm.Usage{}},
		{"jetons d'entrée", llm.Budget{MaxInputTokens: 25}, llm.Usage{InputTokens: 10}},
		{"jetons de sortie", llm.Budget{MaxOutputTokens: 5}, llm.Usage{OutputTokens: 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var done int
			script := &llmtest.Script{Usage: c.usage, Steps: []llmtest.Step{loop, loop, loop, loop, loop}}
			out, err := llm.Run(context.Background(), llm.Session{Provider: script, Handlers: echoHandlers(&done), Budget: c.budget})
			if !errors.Is(err, llm.ErrBudget) || out.Done {
				t.Fatalf("Run = %+v, %v ; ErrBudget attendue", out, err)
			}
			if script.Calls() >= 5 {
				t.Fatalf("le budget n'a pas arrêté la boucle (%d tours)", script.Calls())
			}
		})
	}
}

func TestRunAcceptsResultOnLastTurn(t *testing.T) {
	var done int
	script := &llmtest.Script{Steps: []llmtest.Step{llmtest.Tools(llmtest.Call{Name: "submit", Input: 1})}}
	out, err := llm.Run(context.Background(), llm.Session{Provider: script, Handlers: echoHandlers(&done), Budget: llm.Budget{MaxTurns: 1}})
	if err != nil || !out.Done {
		t.Fatalf("Run = %+v, %v", out, err)
	}
}

func TestRunReminderThenNoResult(t *testing.T) {
	var done int
	script := &llmtest.Script{Steps: []llmtest.Step{llmtest.Text("hmm"), llmtest.Text("still")}}
	rec := llmtest.Record(script)
	_, err := llm.Run(context.Background(), llm.Session{Provider: rec, Handlers: echoHandlers(&done), Reminder: "submit now"})
	if !errors.Is(err, llm.ErrNoResult) {
		t.Fatalf("err = %v", err)
	}
	if script.Calls() != 2 || rec.Exchanges()[1].Request.Messages[2].Blocks[0].Text != "submit now" {
		t.Fatal("relance attendue une seule fois")
	}
	script = &llmtest.Script{Steps: []llmtest.Step{llmtest.Text("hmm")}}
	if _, err := llm.Run(context.Background(), llm.Session{Provider: script, Handlers: echoHandlers(&done)}); !errors.Is(err, llm.ErrNoResult) {
		t.Fatalf("sans relance : %v", err)
	}
}

func TestRunStopsOnProviderTroubles(t *testing.T) {
	boom := errors.New("boom")
	refusal := func(llm.Request) (llm.Response, error) { return llm.Response{Stop: llm.StopRefusal}, nil }
	truncated := func(llm.Request) (llm.Response, error) { return llm.Response{Stop: llm.StopMaxTokens}, nil }
	for _, c := range []struct {
		step llmtest.Step
		want error
	}{{llmtest.Fail(boom), boom}, {refusal, llm.ErrRefused}, {truncated, llm.ErrTruncated}} {
		var done int
		_, err := llm.Run(context.Background(), llm.Session{Provider: &llmtest.Script{Steps: []llmtest.Step{c.step}}, Handlers: echoHandlers(&done)})
		if !errors.Is(err, c.want) {
			t.Errorf("err = %v, attendu %v", err, c.want)
		}
	}
}

func TestRunUnknownToolAndHandlerError(t *testing.T) {
	var done int
	script := &llmtest.Script{Steps: []llmtest.Step{
		llmtest.Tools(llmtest.Call{Name: "rm", Input: "-rf"}),
		llmtest.Tools(llmtest.Call{Name: "submit", Input: 1}),
	}}
	rec := llmtest.Record(script)
	if _, err := llm.Run(context.Background(), llm.Session{Provider: rec, Handlers: echoHandlers(&done)}); err != nil {
		t.Fatal(err)
	}
	if r := rec.Exchanges()[1].Request.Messages[2].Blocks[0].ToolResult; !r.IsError {
		t.Fatalf("outil inconnu : %+v", r)
	}
	h := map[string]llm.Handler{"look": func(context.Context, json.RawMessage) (llm.Result, error) {
		return llm.Result{}, llm.ErrBudget
	}}
	script = &llmtest.Script{Steps: []llmtest.Step{llmtest.Tools(llmtest.Call{Name: "look", Input: 1})}}
	if _, err := llm.Run(context.Background(), llm.Session{Provider: script, Handlers: h}); !errors.Is(err, llm.ErrBudget) {
		t.Fatalf("erreur d'outil : %v", err)
	}
}

func TestRunWithoutProvider(t *testing.T) {
	if _, err := llm.Run(context.Background(), llm.Session{}); err == nil {
		t.Fatal("erreur attendue")
	}
}
