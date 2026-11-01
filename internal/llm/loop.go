package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Result est la réponse d'un Handler à un appel d'outil.
type Result struct {
	// Content est renvoyé au modèle comme résultat de l'outil.
	Content string
	IsError bool
	// Done termine la boucle après ce tour : l'outil final a été accepté.
	Done bool
}

// Handler exécute un appel d'outil. Une erreur (ErrBudget par exemple) arrête la boucle ;
// une erreur d'usage de l'outil par le modèle se renvoie en Result.IsError.
type Handler func(ctx context.Context, input json.RawMessage) (Result, error)

// Budget borne une analyse ; zéro dans un champ vaut « sans limite » pour ce champ.
type Budget struct {
	MaxTurns        int
	MaxInputTokens  int64
	MaxOutputTokens int64
	// MaxCallsPerTurn borne les appels d'outils exécutés pour une réponse du modèle ; les
	// suivants reçoivent une erreur sans être exécutés (SEC2-09 : une réponse ne fait pas
	// tourner une centaine d'outils).
	MaxCallsPerTurn int
}

// Session décrit une conversation avec outils.
type Session struct {
	Provider Provider
	System   string
	// Prompt est le premier message de l'utilisateur.
	Prompt   string
	Tools    []Tool
	Handlers map[string]Handler
	Budget   Budget
	// MaxTokens borne chaque réponse du modèle.
	MaxTokens int
	// Reminder est renvoyé une fois si le modèle rend la main sans appeler d'outil ; vide :
	// pas de relance.
	Reminder string
}

// Outcome résume une conversation, terminée ou non.
type Outcome struct {
	Turns int
	Usage Usage
	// Done : un Handler a signalé l'outil final accepté.
	Done bool
}

// Run mène la conversation : chaque réponse du modèle est suivie de l'exécution de ses
// appels d'outils par les Handler, jusqu'à ce qu'un Handler signale Done. Le budget est
// vérifié après chaque réponse ; un résultat final arrivé dans le dernier tour permis
// est accepté.
func Run(ctx context.Context, s Session) (Outcome, error) {
	var out Outcome
	if s.Provider == nil {
		return out, errors.New("llm: fournisseur absent")
	}
	msgs := []Message{{Role: RoleUser, Blocks: []Block{{Kind: BlockText, Text: s.Prompt}}}}
	reminded := false
	for {
		if s.Budget.MaxTurns > 0 && out.Turns >= s.Budget.MaxTurns {
			return out, fmt.Errorf("%w : %d tours", ErrBudget, out.Turns)
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		resp, err := s.Provider.Complete(ctx, Request{System: s.System, Tools: s.Tools, Messages: msgs, MaxTokens: s.MaxTokens})
		if err != nil {
			return out, fmt.Errorf("llm: fournisseur : %w", err)
		}
		out.Turns++
		out.Usage = out.Usage.Add(resp.Usage)
		resp.Message.Role = RoleAssistant
		msgs = append(msgs, resp.Message)
		switch resp.Stop {
		case StopRefusal:
			return out, ErrRefused
		case StopMaxTokens:
			return out, ErrTruncated
		}
		uses := resp.ToolUses()
		if len(uses) == 0 {
			if reminded || s.Reminder == "" {
				return out, ErrNoResult
			}
			reminded = true
			msgs = append(msgs, Message{Role: RoleUser, Blocks: []Block{{Kind: BlockText, Text: s.Reminder}}})
			if err := s.Budget.check(out.Usage); err != nil {
				return out, err
			}
			continue
		}
		results := make([]Block, 0, len(uses))
		for i, u := range uses {
			// Le délai est vérifié entre deux outils, pas seulement entre deux tours.
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if s.Budget.MaxCallsPerTurn > 0 && i >= s.Budget.MaxCallsPerTurn {
				results = append(results, Block{Kind: BlockToolResult, ToolResult: ToolResult{ID: u.ID, Name: u.Name,
					Content: fmt.Sprintf("not executed: at most %d tool calls per turn", s.Budget.MaxCallsPerTurn), IsError: true}})
				continue
			}
			r, err := s.call(ctx, u)
			if err != nil {
				return out, err
			}
			out.Done = out.Done || r.Done
			results = append(results, Block{Kind: BlockToolResult, ToolResult: ToolResult{ID: u.ID, Name: u.Name, Content: r.Content, IsError: r.IsError}})
		}
		if out.Done {
			return out, nil
		}
		if err := s.Budget.check(out.Usage); err != nil {
			return out, err
		}
		msgs = append(msgs, Message{Role: RoleUser, Blocks: results})
	}
}

func (s Session) call(ctx context.Context, u ToolUse) (Result, error) {
	h, ok := s.Handlers[u.Name]
	if !ok {
		return Result{Content: "unknown tool", IsError: true}, nil
	}
	return h(ctx, u.Input)
}

func (b Budget) check(u Usage) error {
	if b.MaxInputTokens > 0 && u.Input() > b.MaxInputTokens {
		return fmt.Errorf("%w : %d jetons d'entrée", ErrBudget, u.Input())
	}
	if b.MaxOutputTokens > 0 && u.OutputTokens > b.MaxOutputTokens {
		return fmt.Errorf("%w : %d jetons de sortie", ErrBudget, u.OutputTokens)
	}
	return nil
}
