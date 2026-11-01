package triage

import (
	"bytes"
	"slices"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/version"
)

// Decision est une ligne du journal des décisions (table triage_decisions).
type Decision struct {
	ID        uuid.UUID
	Scope     Scope
	ProjectID uuid.UUID // ScopeProject
	VulnID    string
	PURL      string // ScopeProject : purl canonique du composant
	PURLBase  string
	Vers      string // ScopeOrg : plage vers normalisée, vide pour toutes les versions
	Action    Action
	Status    Status // vide pour un retrait
	// Justification d'origine, telle quelle (StatusNotAffected).
	Justification Justification
	Comment       string
	// ExpiresOn est le dernier jour d'acceptation d'un risque accepté (date UTC à minuit).
	ExpiresOn    *time.Time
	AuthorUserID int64 // 0 : système
	AuthorLabel  string
	// ExpiresID est la décision dont une échéance (ActionExpire) prend la suite.
	ExpiresID uuid.UUID
	CreatedAt time.Time

	// purlType sert à vérifier une plage vers à l'import ; il n'est pas enregistré.
	purlType string
}

// key identifie la décision courante d'une portée : la plus récente d'une même clé
// l'emporte.
type decisionKey struct {
	Scope     Scope
	ProjectID uuid.UUID
	PURL      string
	PURLBase  string
	Vers      string
	VulnID    string
}

func (d Decision) key() decisionKey {
	return decisionKey{Scope: d.Scope, ProjectID: d.ProjectID, PURL: d.PURL, PURLBase: d.PURLBase, Vers: d.Vers, VulnID: d.VulnID}
}

// ExpiresAt est l'instant où un risque accepté échoit : le lendemain du dernier jour
// d'acceptation, à minuit UTC. Zéro sans échéance.
func (d Decision) ExpiresAt() time.Time {
	if d.ExpiresOn == nil {
		return time.Time{}
	}
	y, m, day := d.ExpiresOn.UTC().Date()
	return time.Date(y, m, day+1, 0, 0, 0, 0, time.UTC)
}

// later dit si a est postérieure à b : date de création, puis identifiant (UUID v7).
func later(a, b Decision) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return bytes.Compare(a.ID[:], b.ID[:]) > 0
}

// Current ramène un journal à la décision courante de chaque clé, sans les retraits.
func Current(log []Decision) []Decision {
	last := map[decisionKey]Decision{}
	for _, d := range log {
		if prev, ok := last[d.key()]; !ok || later(d, prev) {
			last[d.key()] = d
		}
	}
	out := make([]Decision, 0, len(last))
	for _, d := range last {
		if d.Action != ActionWithdraw {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b Decision) int {
		if later(a, b) {
			return -1
		}
		if later(b, a) {
			return 1
		}
		return 0
	})
	return out
}

// Target est ce qu'il faut savoir d'un constat pour calculer son statut effectif.
type Target struct {
	ProjectID uuid.UUID
	PURL      string // purl canonique du composant
	PURLBase  string
	PURLType  string
	Version   string
	VulnID    string
}

// Effective est le statut effectif d'un constat et la décision qui le donne (nil : aucune,
// « à analyser » par défaut).
type Effective struct {
	Status   Status
	Decision *Decision
}

// Resolver calcule les statuts effectifs ; il compare les versions des plages vers.
type Resolver struct {
	cmp version.Comparer
}

// NewResolver renvoie un Resolver.
func NewResolver(cmp version.Comparer) Resolver { return Resolver{cmp: cmp} }

// Resolve calcule le statut effectif d'un constat à partir du journal des décisions du
// couple (purl_base, vulnérabilité) de l'organisation : la décision courante du projet
// pour ce composant l'emporte ; sinon la plus récente des décisions courantes de
// l'organisation dont la plage contient la version ; sinon « à analyser ». Une plage
// illisible, d'un autre schéma que le composant, ou une version qu'elle ne sait pas
// comparer ne s'applique pas.
func (r Resolver) Resolve(t Target, log []Decision) Effective {
	var org *Decision
	for _, d := range Current(log) {
		if d.VulnID != t.VulnID || d.PURLBase != t.PURLBase {
			continue
		}
		switch d.Scope {
		case ScopeProject:
			if d.ProjectID == t.ProjectID && d.PURL == t.PURL {
				return Effective{Status: d.Status, Decision: &d}
			}
		case ScopeOrg:
			if org == nil && r.covers(d.Vers, t) {
				org = &d
			}
		}
	}
	if org != nil {
		return Effective{Status: org.Status, Decision: org}
	}
	return Effective{Status: StatusInTriage}
}

func (r Resolver) covers(vers string, t Target) bool {
	if vers == "" {
		return true
	}
	rg, err := version.ParseVers(vers, r.cmp)
	if err != nil || rg.Scheme != version.ForPURLType(t.PURLType) {
		return false
	}
	in, err := rg.Contains(r.cmp, t.Version)
	return err == nil && in
}

// Applies indique si la décision d (courante ou non) concerne le constat t : même couple,
// même composant pour un projet, plage qui contient la version pour l'organisation.
func (r Resolver) Applies(d Decision, t Target) bool {
	if d.VulnID != t.VulnID || d.PURLBase != t.PURLBase {
		return false
	}
	if d.Scope == ScopeProject {
		return d.ProjectID == t.ProjectID && d.PURL == t.PURL
	}
	return r.covers(d.Vers, t)
}
