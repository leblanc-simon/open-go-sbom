package llm_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/llm"
)

var tools = []llm.Tool{{Name: "read_file", Description: "Read a file", Schema: map[string]any{
	"type": "object", "additionalProperties": false, "required": []string{"path"},
	"properties": map[string]any{"path": map[string]any{"type": "string"}},
}}}

func TestAnthropicRequestAndReplay(t *testing.T) {
	// L'environnement ne doit rien changer : ni adresse, ni clé, ni en-tête.
	t.Setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:1")
	t.Setenv("ANTHROPIC_API_KEY", "env-key")
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Leak: yes")
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || !strings.Contains(r.Header.Get("X-Api-Key")+r.Header.Get("Authorization"), "cfg-key") || r.Header.Get("X-Leak") != "" {
			t.Errorf("requête inattendue : %s %v", r.URL.Path, r.Header)
		}
		var body map[string]any
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		if len(bodies) == 1 {
			_, _ = io.WriteString(w, `{"id":"m1","type":"message","role":"assistant","model":"claude-sonnet-5-5",
				"content":[{"type":"thinking","thinking":"","signature":"sig"},{"type":"text","text":"Je lis."},
				{"type":"tool_use","id":"tu1","name":"read_file","input":{"path":"a.js"}}],
				"stop_reason":"tool_use","usage":{"input_tokens":100,"output_tokens":20,"cache_read_input_tokens":5,"cache_creation_input_tokens":7}}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"m2","type":"message","role":"assistant","model":"claude-sonnet-5-5",
			"content":[{"type":"text","text":"fini"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer srv.Close()
	p, err := llm.NewAnthropic(llm.AnthropicConfig{APIKey: "cfg-key", BaseURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if p.Model() != llm.DefaultAnthropicModel || !p.External() {
		t.Fatalf("modèle %q", p.Model())
	}
	req := llm.Request{System: "sys", Tools: tools, MaxTokens: 1000,
		Messages: []llm.Message{{Role: llm.RoleUser, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "go"}}}}}
	resp, err := p.Complete(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	uses := resp.ToolUses()
	if resp.Stop != llm.StopToolUse || len(uses) != 1 || uses[0].Name != "read_file" || string(uses[0].Input) != `{"path":"a.js"}` {
		t.Fatalf("réponse = %+v", resp)
	}
	if resp.Usage != (llm.Usage{InputTokens: 100, OutputTokens: 20, CacheReadTokens: 5, CacheWriteTokens: 7}) {
		t.Fatalf("usage = %+v", resp.Usage)
	}
	b := bodies[0]
	if b["model"] != "claude-sonnet-5-5" || b["max_tokens"] != float64(1000) {
		t.Fatalf("corps = %v", b)
	}
	for _, k := range []string{"temperature", "top_p", "top_k", "thinking", "tool_choice"} {
		if _, ok := b[k]; ok {
			t.Errorf("champ %q envoyé", k)
		}
	}
	tool := b["tools"].([]any)[0].(map[string]any)
	schema := tool["input_schema"].(map[string]any)
	if schema["additionalProperties"] != false || schema["type"] != "object" {
		t.Fatalf("schéma = %v", schema)
	}
	// Second tour : la réponse d'origine (raisonnement compris) est renvoyée telle quelle.
	req.Messages = append(req.Messages, resp.Message, llm.Message{Role: llm.RoleUser, Blocks: []llm.Block{{Kind: llm.BlockToolResult,
		ToolResult: llm.ToolResult{ID: "tu1", Name: "read_file", Content: "data"}}}})
	resp, err = p.Complete(context.Background(), req)
	if err != nil || resp.Stop != llm.StopEnd {
		t.Fatalf("second tour : %+v, %v", resp, err)
	}
	msgs := bodies[1]["messages"].([]any)
	assistant := msgs[1].(map[string]any)["content"].([]any)
	if assistant[0].(map[string]any)["type"] != "thinking" || assistant[0].(map[string]any)["signature"] != "sig" {
		t.Fatalf("bloc de raisonnement perdu : %v", assistant)
	}
	result := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if result["type"] != "tool_result" || result["tool_use_id"] != "tu1" {
		t.Fatalf("résultat = %v", result)
	}
}

func TestAnthropicErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"secret echo"}}`)
	}))
	defer srv.Close()
	p, _ := llm.NewAnthropic(llm.AnthropicConfig{APIKey: "k", BaseURL: srv.URL})
	_, err := p.Complete(context.Background(), llm.Request{MaxTokens: 10})
	if err == nil || !strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "secret echo") {
		t.Fatalf("err = %v", err)
	}
	if _, err := llm.NewAnthropic(llm.AnthropicConfig{}); err == nil {
		t.Fatal("clé absente acceptée")
	}
}

func TestAnthropicStopReasons(t *testing.T) {
	for reason, want := range map[string]llm.StopReason{"refusal": llm.StopRefusal, "max_tokens": llm.StopMaxTokens, "pause_turn": llm.StopOther} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"m","type":"message","role":"assistant","model":"x","content":[],"stop_reason":"`+reason+`","usage":{"input_tokens":1,"output_tokens":1}}`)
		}))
		p, _ := llm.NewAnthropic(llm.AnthropicConfig{APIKey: "k", BaseURL: srv.URL, Model: "m"})
		resp, err := p.Complete(context.Background(), llm.Request{MaxTokens: 10})
		srv.Close()
		if err != nil || resp.Stop != want {
			t.Errorf("%s : %v, %v", reason, resp.Stop, err)
		}
	}
}

func TestOllama(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &got)
		_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"",
			"tool_calls":[{"function":{"name":"read_file","arguments":{"path":"a.js"}}}]},
			"done_reason":"stop","prompt_eval_count":42,"eval_count":7}`)
	}))
	defer srv.Close()
	p, err := llm.NewOllama(llm.OllamaConfig{URL: srv.URL + "/", Model: "qwen3", ContextTokens: 32768})
	if err != nil {
		t.Fatal(err)
	}
	if p.External() || p.Model() != "ollama/qwen3" {
		t.Fatalf("%v %q", p.External(), p.Model())
	}
	req := llm.Request{System: "sys", Tools: tools, MaxTokens: 500, Messages: []llm.Message{
		{Role: llm.RoleUser, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "go"}}},
		{Role: llm.RoleAssistant, Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolUse: llm.ToolUse{ID: "c", Name: "read_file", Input: json.RawMessage(`{"path":"b"}`)}}}},
		{Role: llm.RoleUser, Blocks: []llm.Block{{Kind: llm.BlockToolResult, ToolResult: llm.ToolResult{ID: "c", Name: "read_file", Content: "data"}}}},
	}}
	resp, err := p.Complete(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	uses := resp.ToolUses()
	if resp.Stop != llm.StopToolUse || len(uses) != 1 || uses[0].ID == "" || string(uses[0].Input) != `{"path":"a.js"}` {
		t.Fatalf("réponse = %+v", resp)
	}
	if resp.Usage.InputTokens != 42 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("usage = %+v", resp.Usage)
	}
	msgs := got["messages"].([]any)
	roles := []string{}
	for _, m := range msgs {
		roles = append(roles, m.(map[string]any)["role"].(string))
	}
	if strings.Join(roles, ",") != "system,user,assistant,tool" || got["stream"] != false {
		t.Fatalf("messages = %v", got)
	}
	opts := got["options"].(map[string]any)
	if opts["num_ctx"] != float64(32768) || opts["num_predict"] != float64(500) {
		t.Fatalf("options = %v", opts)
	}
}

func TestOllamaErrors(t *testing.T) {
	if _, err := llm.NewOllama(llm.OllamaConfig{URL: "ftp://x", Model: "m"}); err == nil {
		t.Error("URL non http acceptée")
	}
	if _, err := llm.NewOllama(llm.OllamaConfig{URL: "http://x"}); err == nil {
		t.Error("modèle absent accepté")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Bad") == "" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	p, _ := llm.NewOllama(llm.OllamaConfig{URL: srv.URL, Model: "m"})
	if _, err := p.Complete(context.Background(), llm.Request{}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"trop long"},"done_reason":"length"}`)
	}))
	defer srv2.Close()
	p, _ = llm.NewOllama(llm.OllamaConfig{URL: srv2.URL, Model: "m"})
	if resp, err := p.Complete(context.Background(), llm.Request{}); err != nil || resp.Stop != llm.StopMaxTokens {
		t.Fatalf("%+v %v", resp, err)
	}
}
