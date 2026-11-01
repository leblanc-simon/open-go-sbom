package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OllamaConfig configure le fournisseur Ollama (modèle local).
type OllamaConfig struct {
	// URL du serveur Ollama (http://127.0.0.1:11434).
	URL   string
	Model string
	// ContextTokens fixe la fenêtre de contexte demandée (num_ctx) ; 0 : celle du modèle.
	ContextTokens int
	// Timeout borne une requête (un modèle local peut être lent).
	Timeout    time.Duration
	HTTPClient *http.Client
}

// Ollama est un fournisseur local servi par l'API HTTP d'Ollama (/api/chat), sans SDK.
type Ollama struct {
	cfg  OllamaConfig
	http *http.Client
	chat string
}

// maxOllamaResponse borne une réponse lue (un modèle ne renvoie pas des mégaoctets).
const maxOllamaResponse = 8 << 20

// NewOllama construit le fournisseur.
func NewOllama(cfg OllamaConfig) (*Ollama, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("llm: URL d'Ollama http(s) absolue sans identifiants attendue")
	}
	if cfg.Model == "" {
		return nil, errors.New("llm: modèle Ollama absent")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	return &Ollama{cfg: cfg, http: hc, chat: strings.TrimRight(cfg.URL, "/") + "/api/chat"}, nil
}

// Model renvoie le modèle employé, préfixé pour le distinguer d'un modèle d'API.
func (o *Ollama) Model() string { return "ollama/" + o.cfg.Model }

// External : le serveur Ollama est dans l'infrastructure de l'exploitant.
func (o *Ollama) External() bool { return false }

type ollamaToolCall struct {
	ID       string `json:"id,omitempty"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

type ollamaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Tools    []ollamaTool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaResponse struct {
	Message         ollamaMessage `json:"message"`
	DoneReason      string        `json:"done_reason"`
	PromptEvalCount int64         `json:"prompt_eval_count"`
	EvalCount       int64         `json:"eval_count"`
}

// Complete envoie la conversation à /api/chat, sans flux.
func (o *Ollama) Complete(ctx context.Context, req Request) (Response, error) {
	body := ollamaRequest{Model: o.cfg.Model, Stream: false, Options: map[string]any{}}
	if req.MaxTokens > 0 {
		body.Options["num_predict"] = req.MaxTokens
	}
	if o.cfg.ContextTokens > 0 {
		body.Options["num_ctx"] = o.cfg.ContextTokens
	}
	if req.System != "" {
		body.Messages = append(body.Messages, ollamaMessage{Role: "system", Content: req.System})
	}
	for _, t := range req.Tools {
		var ot ollamaTool
		ot.Type = "function"
		ot.Function.Name, ot.Function.Description, ot.Function.Parameters = t.Name, t.Description, t.Schema
		body.Tools = append(body.Tools, ot)
	}
	for _, m := range req.Messages {
		body.Messages = append(body.Messages, ollamaMessages(m)...)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("ollama : %w", err)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.chat, bytes.NewReader(data))
	if err != nil {
		return Response{}, fmt.Errorf("ollama : %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := o.http.Do(hreq)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("ollama : requête en échec : %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOllamaResponse+1))
	if err != nil {
		return Response{}, fmt.Errorf("ollama : lecture : %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("ollama : statut %d", resp.StatusCode)
	}
	if len(raw) > maxOllamaResponse {
		return Response{}, errors.New("ollama : réponse trop volumineuse")
	}
	var or ollamaResponse
	if err := json.Unmarshal(raw, &or); err != nil {
		return Response{}, fmt.Errorf("ollama : réponse illisible : %w", err)
	}
	out := Response{Message: Message{Role: RoleAssistant}, Usage: Usage{InputTokens: or.PromptEvalCount, OutputTokens: or.EvalCount}}
	if strings.TrimSpace(or.Message.Content) != "" {
		out.Message.Blocks = append(out.Message.Blocks, Block{Kind: BlockText, Text: or.Message.Content})
	}
	for i, tc := range or.Message.ToolCalls {
		id := tc.ID
		if id == "" {
			// Ollama ne numérote pas toujours ses appels : l'identifiant ne sert qu'à
			// relier un résultat à son appel dans cette conversation.
			id = "call_" + strconv.Itoa(len(req.Messages)) + "_" + strconv.Itoa(i)
		}
		args := tc.Function.Arguments
		if len(args) == 0 {
			args = json.RawMessage("{}")
		}
		out.Message.Blocks = append(out.Message.Blocks, Block{Kind: BlockToolUse, ToolUse: ToolUse{ID: id, Name: tc.Function.Name, Input: args}})
	}
	switch {
	case len(or.Message.ToolCalls) > 0:
		out.Stop = StopToolUse
	case or.DoneReason == "length":
		out.Stop = StopMaxTokens
	case or.DoneReason == "stop" || or.DoneReason == "":
		out.Stop = StopEnd
	default:
		out.Stop = StopOther
	}
	return out, nil
}

// ollamaMessages convertit un message : un résultat d'outil devient un message de rôle
// « tool ».
func ollamaMessages(m Message) []ollamaMessage {
	var out []ollamaMessage
	main := ollamaMessage{Role: string(m.Role)}
	var text []string
	for _, b := range m.Blocks {
		switch b.Kind {
		case BlockText:
			text = append(text, b.Text)
		case BlockToolUse:
			var tc ollamaToolCall
			tc.ID = b.ToolUse.ID
			tc.Function.Name, tc.Function.Arguments = b.ToolUse.Name, b.ToolUse.Input
			main.ToolCalls = append(main.ToolCalls, tc)
		case BlockToolResult:
			out = append(out, ollamaMessage{Role: "tool", Content: b.ToolResult.Content, ToolName: b.ToolResult.Name})
		}
	}
	main.Content = strings.Join(text, "\n")
	if main.Content != "" || len(main.ToolCalls) > 0 {
		out = append([]ollamaMessage{main}, out...)
	}
	return out
}
