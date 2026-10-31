package tenant

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrZeroOrgID signale un identifiant d'organisation absent.
var ErrZeroOrgID = errors.New("tenant: identifiant d'organisation vide")

// OrgID identifie une organisation. Sa valeur zéro n'est pas valide.
type OrgID struct {
	id uuid.UUID
}

// NewOrgID génère un identifiant d'organisation (UUID v7, ordonné dans le temps).
func NewOrgID() (OrgID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return OrgID{}, fmt.Errorf("tenant: génération d'un identifiant : %w", err)
	}
	return OrgID{id: id}, nil
}

// ParseOrgID lit un identifiant d'organisation sous forme textuelle. Le zéro est refusé.
func ParseOrgID(s string) (OrgID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return OrgID{}, fmt.Errorf("tenant: identifiant d'organisation invalide : %w", err)
	}
	return FromUUID(id)
}

// FromUUID convertit un UUID en identifiant d'organisation. Le zéro est refusé.
func FromUUID(id uuid.UUID) (OrgID, error) {
	if id == uuid.Nil {
		return OrgID{}, ErrZeroOrgID
	}
	return OrgID{id: id}, nil
}

// UUID renvoie l'UUID sous-jacent.
func (o OrgID) UUID() uuid.UUID { return o.id }

// IsZero indique si l'identifiant est absent.
func (o OrgID) IsZero() bool { return o.id == uuid.Nil }

// String renvoie la forme textuelle canonique de l'UUID.
func (o OrgID) String() string { return o.id.String() }

// Value implémente driver.Valuer : un OrgID zéro ne part jamais en base.
func (o OrgID) Value() (driver.Value, error) {
	if o.IsZero() {
		return nil, ErrZeroOrgID
	}
	return o.id.String(), nil
}

// Scan implémente sql.Scanner. Une valeur NULL ou zéro est une erreur : une colonne
// org_id est toujours NOT NULL.
func (o *OrgID) Scan(src any) error {
	var id uuid.UUID
	if err := id.Scan(src); err != nil {
		return fmt.Errorf("tenant: lecture d'un identifiant d'organisation : %w", err)
	}
	parsed, err := FromUUID(id)
	if err != nil {
		return err
	}
	*o = parsed
	return nil
}

type ctxKey struct{}

// NewContext renvoie un contexte qui porte l'organisation courante.
func NewContext(ctx context.Context, org OrgID) context.Context {
	return context.WithValue(ctx, ctxKey{}, org)
}

// FromContext renvoie l'organisation courante, si le contexte en porte une.
func FromContext(ctx context.Context) (OrgID, bool) {
	org, ok := ctx.Value(ctxKey{}).(OrgID)
	return org, ok && !org.IsZero()
}
