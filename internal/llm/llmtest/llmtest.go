// Package llmtest fournit aux tests un faux fournisseur de modèle scénarisé (Script) et un
// enregistreur des échanges (Recorder), pour des tests déterministes de l'enrichissement
// IA : ce que l'agent envoie au fournisseur est relu tel quel, et le comportement du
// « modèle » (appels d'outils, candidats, erreurs) est fixé par le test.
package llmtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"leblanc.io/lotor/internal/llm"
)

// Step produit la réponse d'un tour à partir de la demande reçue.
type Step func(req llm.Request) (llm.Response, error)

// Script est un fournisseur dont chaque tour joue l'étape suivante. Au-delà de la dernière
// étape, il renvoie ErrExhausted.
type Script struct {
	ModelName  string
	IsExternal bool
	Steps      []Step
	// Usage est ajouté à chaque réponse qui n'en porte pas.
	Usage llm.Usage

	mu   sync.Mutex
	next int
}

// ErrExhausted : le scénario n'a plus d'étape.
var ErrExhausted = errors.New("llmtest: scénario épuisé")

// Model renvoie ModelName, « fake-model » par défaut.
func (s *Script) Model() string {
	if s.ModelName == "" {
		return "fake-model"
	}
	return s.ModelName
}

// External renvoie IsExternal.
func (s *Script) External() bool { return s.IsExternal }

// Complete joue l'étape suivante.
func (s *Script) Complete(ctx context.Context, req llm.Request) (llm.Response, error) {
	if err := ctx.Err(); err != nil {
		return llm.Response{}, err
	}
	s.mu.Lock()
	i := s.next
	s.next++
	s.mu.Unlock()
	if i >= len(s.Steps) {
		return llm.Response{}, ErrExhausted
	}
	resp, err := s.Steps[i](req)
	if err == nil && resp.Usage == (llm.Usage{}) {
		resp.Usage = s.Usage
	}
	return resp, err
}

// Calls renvoie le nombre de tours joués.
func (s *Script) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// Call est un appel d'outil d'une étape.
type Call struct {
	Name  string
	Input any
}

// Tools renvoie une étape qui appelle les outils donnés.
func Tools(calls ...Call) Step {
	return func(req llm.Request) (llm.Response, error) {
		resp := llm.Response{Stop: llm.StopToolUse, Message: llm.Message{Role: llm.RoleAssistant}}
		for i, c := range calls {
			in, err := json.Marshal(c.Input)
			if err != nil {
				return llm.Response{}, err
			}
			resp.Message.Blocks = append(resp.Message.Blocks, llm.Block{Kind: llm.BlockToolUse,
				ToolUse: llm.ToolUse{ID: fmt.Sprintf("tu_%d_%d", len(req.Messages), i), Name: c.Name, Input: in}})
		}
		return resp, nil
	}
}

// Text renvoie une étape qui répond par du texte et rend la main.
func Text(text string) Step {
	return func(llm.Request) (llm.Response, error) {
		return llm.Response{Stop: llm.StopEnd, Message: llm.Message{Role: llm.RoleAssistant,
			Blocks: []llm.Block{{Kind: llm.BlockText, Text: text}}}}, nil
	}
}

// Fail renvoie une étape en erreur (panne du fournisseur).
func Fail(err error) Step {
	return func(llm.Request) (llm.Response, error) { return llm.Response{}, err }
}

// WithUsage fixe la consommation d'une étape.
func WithUsage(step Step, u llm.Usage) Step {
	return func(req llm.Request) (llm.Response, error) {
		resp, err := step(req)
		resp.Usage = u
		return resp, err
	}
}

// Exchange est un tour enregistré : la demande envoyée et la réponse reçue.
type Exchange struct {
	Request  llm.Request
	Response llm.Response
	Err      error
}

// Recorder enveloppe un fournisseur et enregistre chaque échange.
type Recorder struct {
	llm.Provider
	mu        sync.Mutex
	exchanges []Exchange
}

// Record enveloppe p.
func Record(p llm.Provider) *Recorder { return &Recorder{Provider: p} }

// Complete transmet la demande et l'enregistre (copie profonde des messages).
func (r *Recorder) Complete(ctx context.Context, req llm.Request) (llm.Response, error) {
	resp, err := r.Provider.Complete(ctx, req)
	cp := req
	cp.Messages = make([]llm.Message, len(req.Messages))
	for i, m := range req.Messages {
		cp.Messages[i] = llm.Message{Role: m.Role, Blocks: append([]llm.Block(nil), m.Blocks...)}
	}
	r.mu.Lock()
	r.exchanges = append(r.exchanges, Exchange{Request: cp, Response: resp, Err: err})
	r.mu.Unlock()
	return resp, err
}

// Exchanges renvoie les échanges enregistrés.
func (r *Recorder) Exchanges() []Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Exchange(nil), r.exchanges...)
}

// Sent renvoie, en texte, tout ce que l'appelant a envoyé au fournisseur : prompt système,
// descriptions et schémas des outils, messages de l'utilisateur et résultats d'outils de
// tous les tours. Les messages du modèle, qui lui sont renvoyés tels quels, n'en font pas
// partie (ils viennent de lui). C'est la surface où un test cherche une fuite.
func (r *Recorder) Sent() string {
	var b strings.Builder
	for _, e := range r.Exchanges() {
		b.WriteString(e.Request.System)
		b.WriteByte('\n')
		for _, t := range e.Request.Tools {
			schema, _ := json.Marshal(t.Schema)
			fmt.Fprintf(&b, "%s %s %s\n", t.Name, t.Description, schema)
		}
		for _, m := range e.Request.Messages {
			if m.Role == llm.RoleAssistant {
				continue
			}
			for _, bl := range m.Blocks {
				switch bl.Kind {
				case llm.BlockText:
					b.WriteString(bl.Text)
				case llm.BlockToolResult:
					b.WriteString(bl.ToolResult.Content)
				}
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}
