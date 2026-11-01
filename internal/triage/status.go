package triage

import (
	"errors"
	"fmt"
	"slices"
)

// Status est le statut de triage d'un constat.
type Status string

// Statuts de triage, dans l'ordre des écrans.
const (
	StatusInTriage      Status = "in_triage"      // à analyser (défaut, sans décision)
	StatusAffected      Status = "affected"       // le code vulnérable est atteignable
	StatusNotAffected   Status = "not_affected"   // présent sans impact, justification VEX
	StatusFalsePositive Status = "false_positive" // composant ou version mal identifiés
	StatusRiskAccepted  Status = "risk_accepted"  // accepté jusqu'à une date
	StatusFixed         Status = "fixed"          // correctif déployé, à confirmer par un instantané
)

// Statuses renvoie les statuts, dans l'ordre des écrans.
func Statuses() []Status {
	return []Status{StatusInTriage, StatusAffected, StatusNotAffected, StatusFalsePositive, StatusRiskAccepted, StatusFixed}
}

// Hidden indique si les constats de ce statut sont masqués par défaut des listes : ni
// « non affecté » ni « faux positif » n'appellent d'action.
func (s Status) Hidden() bool { return s == StatusNotAffected || s == StatusFalsePositive }

// HiddenStatuses renvoie les statuts masqués par défaut.
func HiddenStatuses() []Status { return []Status{StatusNotAffected, StatusFalsePositive} }

// ErrInvalidStatus : statut inconnu.
var ErrInvalidStatus = errors.New("triage: statut inconnu")

// ParseStatus lit un statut.
func ParseStatus(s string) (Status, error) {
	if st := Status(s); slices.Contains(Statuses(), st) {
		return st, nil
	}
	return "", fmt.Errorf("%w : %q", ErrInvalidStatus, s)
}

// Scope est la portée d'une décision.
type Scope string

// Portées d'une décision.
const (
	ScopeProject Scope = "project" // le composant exact, dans un projet
	ScopeOrg     Scope = "org"     // la famille de composants (purl_base), dans toute l'organisation
)

// Action est la nature d'une ligne du journal des décisions.
type Action string

// Actions du journal des décisions.
const (
	ActionSet      Action = "set"      // décision
	ActionWithdraw Action = "withdraw" // retrait de la décision de la clé
	ActionExpire   Action = "expire"   // échéance d'un risque accepté : retour « à analyser »
)
