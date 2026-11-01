package tenant

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// Role est le rôle d'un compte dans une organisation : membre ou administrateur. Les
// droits sur les projets viennent du rôle dans leur équipe (TeamRole, ADR 0034).
type Role string

// Rôles d'organisation, du moins au plus privilégié.
const (
	RoleMember Role = "member" // voit les projets de ses équipes, selon son rôle d'équipe
	RoleAdmin  Role = "admin"  // voit et gère tout dans l'organisation
)

// Roles renvoie les rôles d'organisation, du moins au plus privilégié.
func Roles() []Role { return []Role{RoleMember, RoleAdmin} }

// ErrInvalidRole : rôle d'organisation ou d'équipe inconnu.
var ErrInvalidRole = errors.New("tenant: rôle inconnu")

// ParseRole lit un rôle d'organisation.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleMember, RoleAdmin:
		return r, nil
	}
	return "", fmt.Errorf("%w : %q", ErrInvalidRole, s)
}

func (r Role) rank() int {
	switch r {
	case RoleMember:
		return 1
	case RoleAdmin:
		return 2
	}
	return 0
}

// AtLeast indique si le rôle vaut au moins min. Un rôle inconnu ne vaut rien.
func (r Role) AtLeast(min Role) bool { return r.rank() > 0 && r.rank() >= min.rank() }

// TeamRole est le rôle d'un membre dans une équipe.
type TeamRole string

// Rôles d'équipe, du moins au plus privilégié. TeamNone (vide) : aucun rôle dans l'équipe.
const (
	TeamNone    TeamRole = ""
	TeamReader  TeamRole = "reader"  // consulte les projets de l'équipe
	TeamAnalyst TeamRole = "analyst" // consulte et trie les constats, demande un scan
	TeamAdmin   TeamRole = "admin"   // gère les projets, les agents et les membres de l'équipe
)

// TeamRoles renvoie les rôles d'équipe, du moins au plus privilégié.
func TeamRoles() []TeamRole { return []TeamRole{TeamReader, TeamAnalyst, TeamAdmin} }

// ParseTeamRole lit un rôle d'équipe (TeamNone refusé).
func ParseTeamRole(s string) (TeamRole, error) {
	switch r := TeamRole(s); r {
	case TeamReader, TeamAnalyst, TeamAdmin:
		return r, nil
	}
	return "", fmt.Errorf("%w : %q", ErrInvalidRole, s)
}

func (r TeamRole) rank() int {
	switch r {
	case TeamReader:
		return 1
	case TeamAnalyst:
		return 2
	case TeamAdmin:
		return 3
	}
	return 0
}

// AtLeast indique si le rôle d'équipe vaut au moins min. TeamNone ne vaut rien.
func (r TeamRole) AtLeast(min TeamRole) bool { return r.rank() > 0 && r.rank() >= min.rank() }

// Access est l'organisation courante d'une requête, le compte et ses rôles, établis par
// la garde d'organisation (org.Service.Access).
type Access struct {
	Org      OrgID
	Slug     string
	Name     string
	Language string // langue par défaut de l'organisation
	UserID   int64
	Role     Role
	// Teams porte le rôle du compte dans chacune de ses équipes.
	Teams map[uuid.UUID]TeamRole
}

// Admin indique si le compte administre l'organisation.
func (a Access) Admin() bool { return a.Role == RoleAdmin }

// TeamRole renvoie le rôle du compte dans l'équipe team (TeamNone hors de l'équipe).
func (a Access) TeamRole(team uuid.UUID) TeamRole { return a.Teams[team] }

// Subject renvoie le sujet de la matrice des droits pour l'équipe team.
func (a Access) Subject(team uuid.UUID) Subject {
	return Subject{Role: a.Role, Team: a.TeamRole(team)}
}

// Can indique si le compte a la permission p sur une ressource de l'équipe team
// (uuid.Nil pour une permission d'organisation, ou une ressource sans équipe, comme un
// agent d'organisation : seul l'administrateur d'organisation y a des droits).
func (a Access) Can(p Permission, team uuid.UUID) bool {
	if a.Org.IsZero() {
		return false
	}
	return Allowed(a.Subject(team), p)
}

// CanAny indique si le compte a la permission p dans au moins une équipe (ou partout).
func (a Access) CanAny(p Permission) bool { return a.Admin() || len(a.TeamsWith(p)) > 0 }

// TeamsWith renvoie, triées, les équipes où le compte a la permission p. Pour un
// administrateur d'organisation, qui l'a partout, la liste est vide : l'appelant liste
// alors toutes les équipes.
func (a Access) TeamsWith(p Permission) []uuid.UUID {
	var out []uuid.UUID
	for team, role := range a.Teams {
		if Allowed(Subject{Role: a.Role, Team: role}, p) {
			out = append(out, team)
		}
	}
	slices.SortFunc(out, func(x, y uuid.UUID) int { return compareUUID(x, y) })
	return out
}

// Visibility renvoie les équipes dont le compte voit les projets.
func (a Access) Visibility() Visibility {
	if a.Org.IsZero() {
		return Visibility{}
	}
	if a.Admin() {
		return AllTeams()
	}
	ids := make([]uuid.UUID, 0, len(a.Teams))
	for team, role := range a.Teams {
		if role.AtLeast(TeamReader) {
			ids = append(ids, team)
		}
	}
	return OnlyTeams(ids...)
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
