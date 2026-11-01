package llm

import (
	"context"
	"encoding/json"
	"errors"
)

// Role est l'auteur d'un message.
type Role string

// Auteurs des messages.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// BlockKind est la nature d'un bloc de message.
type BlockKind string

// Natures de blocs.
const (
	BlockText       BlockKind = "text"
	BlockToolUse    BlockKind = "tool_use"
	BlockToolResult BlockKind = "tool_result"
)

// ToolUse est un appel d'outil demandé par le modèle.
type ToolUse struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult est la réponse de l'appelant à un appel d'outil.
type ToolResult struct {
	ID      string
	Name    string
	Content string
	IsError bool
}

// Block est un élément d'un message ; seul le champ de sa nature est renseigné.
type Block struct {
	Kind       BlockKind
	Text       string
	ToolUse    ToolUse
	ToolResult ToolResult
}

// Message est un tour de la conversation.
type Message struct {
	Role   Role
	Blocks []Block
	// Opaque est la forme propre au fournisseur d'un message du modèle (blocs de
	// raisonnement compris), renvoyée telle quelle par ce fournisseur aux tours suivants.
	// Un autre fournisseur l'ignore.
	Opaque any
}

// Tool décrit un outil proposé au modèle ; Schema est un schéma JSON d'objet.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
}

// Request est une demande de complétion.
type Request struct {
	System    string
	Tools     []Tool
	Messages  []Message
	MaxTokens int
}

// StopReason dit pourquoi le modèle a rendu la main.
type StopReason string

// Raisons d'arrêt.
const (
	StopEnd       StopReason = "end"
	StopToolUse   StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
	StopRefusal   StopReason = "refusal"
	StopOther     StopReason = "other"
)

// Usage est la consommation de jetons d'une réponse ou d'une analyse.
type Usage struct {
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
}

// Add additionne deux consommations.
func (u Usage) Add(o Usage) Usage {
	return Usage{
		InputTokens: u.InputTokens + o.InputTokens, OutputTokens: u.OutputTokens + o.OutputTokens,
		CacheReadTokens: u.CacheReadTokens + o.CacheReadTokens, CacheWriteTokens: u.CacheWriteTokens + o.CacheWriteTokens,
	}
}

// Input renvoie tous les jetons d'entrée, cache compris.
func (u Usage) Input() int64 { return u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens }

// Response est la réponse du modèle.
type Response struct {
	Message Message
	Stop    StopReason
	Usage   Usage
}

// ToolUses renvoie les appels d'outils de la réponse, dans l'ordre.
func (r Response) ToolUses() []ToolUse {
	var out []ToolUse
	for _, b := range r.Message.Blocks {
		if b.Kind == BlockToolUse {
			out = append(out, b.ToolUse)
		}
	}
	return out
}

// Provider est un fournisseur de modèle.
type Provider interface {
	// Model nomme le modèle employé (propriété lotor:model des composants).
	Model() string
	// External dit si le contenu envoyé sort de l'infrastructure de l'exploitant.
	External() bool
	// Complete envoie la conversation et renvoie la réponse du modèle. Une erreur couvre
	// le transport, un refus du fournisseur et une réponse illisible.
	Complete(ctx context.Context, req Request) (Response, error)
}

// Erreurs de la boucle.
var (
	// ErrBudget : tours, jetons ou octets lus au-delà du budget de l'analyse.
	ErrBudget = errors.New("llm: budget de l'analyse épuisé")
	// ErrNoResult : le modèle a rendu la main sans appeler l'outil final.
	ErrNoResult = errors.New("llm: aucun résultat soumis")
	// ErrRefused : le fournisseur a refusé de répondre.
	ErrRefused = errors.New("llm: réponse refusée par le fournisseur")
	// ErrTruncated : réponse coupée par la limite de jetons de sortie.
	ErrTruncated = errors.New("llm: réponse tronquée")
)
