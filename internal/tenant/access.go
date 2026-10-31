package tenant

import (
	"context"
	"errors"
	"fmt"
)

// Role est le rôle d'un compte dans une organisation.
type Role string

// Rôles d'organisation, du moins au plus privilégié.
const (
	RoleViewer  Role = "viewer"  // consulte
	RoleAnalyst Role = "analyst" // consulte et trie les constats
	RoleAdmin   Role = "admin"   // administre les membres et les paramètres
)

// Roles renvoie les rôles, du moins au plus privilégié.
func Roles() []Role { return []Role{RoleViewer, RoleAnalyst, RoleAdmin} }

// ErrInvalidRole : rôle d'organisation inconnu.
var ErrInvalidRole = errors.New("tenant: rôle d'organisation inconnu")

// ParseRole lit un rôle d'organisation.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleViewer, RoleAnalyst, RoleAdmin:
		return r, nil
	}
	return "", fmt.Errorf("%w : %q", ErrInvalidRole, s)
}

func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleAnalyst:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// AtLeast indique si le rôle vaut au moins min. Un rôle inconnu ne vaut rien.
func (r Role) AtLeast(min Role) bool { return r.rank() > 0 && r.rank() >= min.rank() }

// Access est l'organisation courante d'une requête et le rôle qu'y a le compte, établis
// par la garde d'organisation.
type Access struct {
	Org      OrgID
	Slug     string
	Name     string
	Language string // langue par défaut de l'organisation
	Role     Role
}

type accessKey struct{}

// WithAccess renvoie un contexte qui porte l'accès courant et son organisation.
func WithAccess(ctx context.Context, a Access) context.Context {
	return context.WithValue(NewContext(ctx, a.Org), accessKey{}, a)
}

// AccessFrom renvoie l'accès courant, si la garde d'organisation l'a établi.
func AccessFrom(ctx context.Context) (Access, bool) {
	a, ok := ctx.Value(accessKey{}).(Access)
	return a, ok && !a.Org.IsZero()
}
