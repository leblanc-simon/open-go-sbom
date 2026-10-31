package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/tenant"
)

// Execution est un job pris par un worker, tel que le handler le reçoit.
type Execution struct {
	ID    uuid.UUID
	Kind  string
	OrgID tenant.OrgID // zéro pour un job d'instance
	// Payload est la charge JSON telle que mise en file.
	Payload     json.RawMessage
	Priority    int
	UniqueKey   string
	Attempt     int // 1 à la première tentative
	MaxAttempts int
}

// Decode lit la charge utile dans v. Un champ inconnu ou une charge illisible donnent une
// erreur permanente : la réessayer ne la rendrait pas lisible.
func (e Execution) Decode(v any) error {
	dec := json.NewDecoder(bytes.NewReader(e.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return Permanent(fmt.Errorf("jobs: charge utile de %s illisible : %w", e.Kind, err))
	}
	return nil
}

// Handler traite un type de job. Il doit être idempotent : la file garantit au moins une
// exécution, pas exactement une (un bail expiré pendant qu'il finissait le fait rejouer).
// Il travaille dans InOrg(e.OrgID) dès qu'il touche des données d'organisation, et
// respecte l'annulation de ctx (arrêt du serveur, bail perdu, délai du type).
type Handler interface {
	Handle(ctx context.Context, e Execution) error
}

// HandlerFunc adapte une fonction en Handler.
type HandlerFunc func(ctx context.Context, e Execution) error

// Handle appelle f.
func (f HandlerFunc) Handle(ctx context.Context, e Execution) error { return f(ctx, e) }

type permanentError struct{ err error }

func (p *permanentError) Error() string { return p.err.Error() }
func (p *permanentError) Unwrap() error { return p.err }

// Permanent marque une erreur que les réessais ne corrigeront pas : le job passe
// directement au statut dead.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent indique si err a été marquée par Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}
