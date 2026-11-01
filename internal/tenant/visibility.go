package tenant

import (
	"bytes"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Visibility désigne les équipes dont les projets sont visibles. Sa valeur zéro ne voit
// rien : une visibilité oubliée ferme l'accès au lieu de l'ouvrir.
//
// Les stores la déclarent à PostgreSQL pour la transaction (db.Visible, réglage
// lotor.teams) et filtrent leurs projets par lotor_team_visible(team_id) ; une requête
// qui appelle cette fonction sans visibilité déclarée échoue (ADR 0034).
type Visibility struct {
	all   bool
	teams []uuid.UUID
}

// AllTeams voit tous les projets de l'organisation (administrateur d'organisation).
func AllTeams() Visibility { return Visibility{all: true} }

// OnlyTeams voit les projets des équipes ids (aucune : rien).
func OnlyTeams(ids ...uuid.UUID) Visibility {
	t := slices.Clone(ids)
	slices.SortFunc(t, compareUUID)
	return Visibility{teams: slices.Compact(t)}
}

// All indique si tous les projets sont visibles.
func (v Visibility) All() bool { return v.all }

// Teams renvoie les équipes visibles (vide si All).
func (v Visibility) Teams() []uuid.UUID { return slices.Clone(v.teams) }

// Sees indique si les projets de l'équipe team sont visibles.
func (v Visibility) Sees(team uuid.UUID) bool {
	if v.all {
		return true
	}
	_, found := slices.BinarySearchFunc(v.teams, team, compareUUID)
	return found
}

// Setting est la valeur du réglage lotor.teams : « * » pour toutes les équipes, sinon un
// tableau PostgreSQL d'uuid (« {} » : aucune).
func (v Visibility) Setting() string {
	if v.all {
		return "*"
	}
	parts := make([]string, len(v.teams))
	for i, t := range v.teams {
		parts[i] = t.String()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func compareUUID(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }
