package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// DefaultAnthropicModel est le modèle Anthropic par défaut (décision du 1er novembre 2026,
// à confirmer au vu de l'évaluation sur le corpus annoté).
const DefaultAnthropicModel = "claude-sonnet-5-5"

// DefaultAnthropicURL est l'adresse de l'API d'Anthropic.
const DefaultAnthropicURL = "https://api.anthropic.com"

// AnthropicConfig configure le fournisseur Anthropic.
type AnthropicConfig struct {
	// APIKey est la clé d'API, lue par l'appelant dans un secret de l'agent.
	APIKey  string
	Model   string
	BaseURL string
	// Timeout borne chaque tentative ; MaxRetries est le nombre de nouvelles tentatives
	// du SDK (429, 5xx, erreurs réseau).
	Timeout    time.Duration
	MaxRetries int
	// HTTPClient remplace le client HTTP (mandataire, tests).
	HTTPClient *http.Client
}

// Anthropic est le fournisseur Anthropic (API Messages, SDK Go officiel).
type Anthropic struct {
	client anthropic.Client
	model  string
}

// NewAnthropic construit le fournisseur. Le client est créé sans aucune valeur par défaut
// lue dans l'environnement (ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL, profils, en-têtes
// supplémentaires…) : seule la configuration de l'agent décide où part le code et avec
// quelle clé (ADR 0042).
func NewAnthropic(cfg AnthropicConfig) (*Anthropic, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("llm: clé d'API Anthropic absente")
	}
	if cfg.Model == "" {
		cfg.Model = DefaultAnthropicModel
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultAnthropicURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	opts := []option.RequestOption{
		option.WithoutEnvironmentDefaults(),
		option.WithAPIKey(cfg.APIKey),
		option.WithBaseURL(cfg.BaseURL),
		option.WithHTTPClient(hc),
		option.WithMaxRetries(max(cfg.MaxRetries, 0)),
	}
	if cfg.Timeout > 0 {
		opts = append(opts, option.WithRequestTimeout(cfg.Timeout))
	}
	return &Anthropic{client: anthropic.NewClient(opts...), model: cfg.Model}, nil
}

// Model renvoie le modèle employé.
func (a *Anthropic) Model() string { return a.model }

// External : l'API d'Anthropic est hors de l'infrastructure de l'exploitant.
func (a *Anthropic) External() bool { return true }

// Complete envoie la conversation. Le prompt système et les outils, identiques d'un tour
// à l'autre, sont marqués pour le cache de prompt. Ni température ni réglage de
// raisonnement : les valeurs par défaut du modèle s'appliquent.
func (a *Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	params := anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: int64(req.MaxTokens),
		Messages:  make([]anthropic.MessageParam, 0, len(req.Messages)),
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System, CacheControl: anthropic.NewCacheControlEphemeralParam()}}
	}
	for _, t := range req.Tools {
		props, _ := t.Schema["properties"]
		var required []string
		if r, ok := t.Schema["required"].([]string); ok {
			required = r
		}
		extra := map[string]any{}
		for k, v := range t.Schema {
			if k != "properties" && k != "required" && k != "type" {
				extra[k] = v
			}
		}
		tp := anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.ToolInputSchemaParam{Properties: props, Required: required, ExtraFields: extra},
		}
		params.Tools = append(params.Tools, anthropic.ToolUnionParam{OfTool: &tp})
	}
	for _, m := range req.Messages {
		params.Messages = append(params.Messages, anthropicMessage(m))
	}
	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return Response{}, anthropicError(err)
	}
	out := Response{
		Message: Message{Role: RoleAssistant, Opaque: msg.ToParam()},
		Usage: Usage{InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens,
			CacheReadTokens: msg.Usage.CacheReadInputTokens, CacheWriteTokens: msg.Usage.CacheCreationInputTokens},
	}
	for _, block := range msg.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			out.Message.Blocks = append(out.Message.Blocks, Block{Kind: BlockText, Text: b.Text})
		case anthropic.ToolUseBlock:
			out.Message.Blocks = append(out.Message.Blocks, Block{Kind: BlockToolUse,
				ToolUse: ToolUse{ID: b.ID, Name: b.Name, Input: json.RawMessage(b.Input)}})
		}
	}
	switch msg.StopReason {
	case anthropic.StopReasonEndTurn, anthropic.StopReasonStopSequence:
		out.Stop = StopEnd
	case anthropic.StopReasonToolUse:
		out.Stop = StopToolUse
	case anthropic.StopReasonMaxTokens, anthropic.StopReasonModelContextWindowExceeded:
		out.Stop = StopMaxTokens
	case anthropic.StopReasonRefusal:
		out.Stop = StopRefusal
	default:
		out.Stop = StopOther
	}
	return out, nil
}

// anthropicMessage convertit un message ; une réponse d'Anthropic est renvoyée sous sa
// forme d'origine (blocs de raisonnement compris, que l'API exige inchangés).
func anthropicMessage(m Message) anthropic.MessageParam {
	if p, ok := m.Opaque.(anthropic.MessageParam); ok {
		return p
	}
	var blocks []anthropic.ContentBlockParamUnion
	for _, b := range m.Blocks {
		switch b.Kind {
		case BlockText:
			blocks = append(blocks, anthropic.NewTextBlock(b.Text))
		case BlockToolUse:
			blocks = append(blocks, anthropic.NewToolUseBlock(b.ToolUse.ID, b.ToolUse.Input, b.ToolUse.Name))
		case BlockToolResult:
			blocks = append(blocks, anthropic.NewToolResultBlock(b.ToolResult.ID, b.ToolResult.Content, b.ToolResult.IsError))
		}
	}
	if m.Role == RoleAssistant {
		return anthropic.NewAssistantMessage(blocks...)
	}
	return anthropic.NewUserMessage(blocks...)
}

// anthropicError résume une erreur du SDK par son statut et son type, sans reprendre le
// corps de la réponse ni la requête.
func anthropicError(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		return fmt.Errorf("anthropic : statut %d (%s)", apiErr.StatusCode, apiErr.Type())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("anthropic : %w", err)
}
