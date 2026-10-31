package finding

import (
	"cmp"
	"slices"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/vuln"
)

// Status est l'état d'un constat.
type Status string

// États d'un constat (le triage arrive en T14).
const (
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
)

// Resolution dit pourquoi un constat a été résolu.
type Resolution string

// Motifs de résolution.
const (
	// ResolutionComponentRemoved : le composant n'est plus dans l'inventaire courant
	// (retiré ou mis à jour vers une autre version).
	ResolutionComponentRemoved Resolution = "component_removed"
	// ResolutionNotMatched : le composant est toujours là, mais la base ne le juge plus
	// vulnérable (fiche corrigée ou retirée).
	ResolutionNotMatched Resolution = "not_matched"
)

// key identifie un constat dans une référence.
type key struct {
	Component uuid.UUID
	Vuln      string
}

// observed est un couple (composant, vulnérabilité) vu par une analyse, avec ses
// attributs du moment.
type observed struct {
	key
	Severity      vuln.Severity
	CVSS          float64 // 0 : sans score
	EPSS          *vuln.EPSS
	KEV           bool
	Risk          float64
	FixedVersions []string
	FixState      vuln.FixState
	MatchType     vuln.MatchType
}

// current est un constat existant de la référence.
type current struct {
	ID     uuid.UUID
	key    key
	Status Status
}

type change struct {
	ID     uuid.UUID
	Obs    observed
	Reopen bool
}

type resolution struct {
	ID     uuid.UUID
	Reason Resolution
}

// plan est l'effet d'une analyse sur les constats d'une référence.
type plan struct {
	Create  []observed
	Update  []change // constats revus (prolongés) ou rouverts
	Resolve []resolution
}

// typeRank classe les types de correspondance, le plus sûr d'abord.
func typeRank(t vuln.MatchType) int {
	switch t {
	case vuln.MatchExactDirect:
		return 0
	case vuln.MatchExactIndirect:
		return 1
	}
	return 2
}

// merge ramène les correspondances à un couple (composant, vulnérabilité) : plusieurs
// sources (NVD, distribution, GHSA ramenée au CVE) peuvent signaler le même. On garde la
// correspondance la plus sûre, puis la plus grave, et l'union des versions corrigées. Les
// correspondances sur un paquet absent de l'inventaire sont comptées dans unmatched.
func merge(ms []vuln.Match, components map[string]uuid.UUID, vulns map[string]vuln.Vulnerability) ([]observed, int) {
	byKey := map[key]observed{}
	unmatched := 0
	for _, m := range ms {
		id, ok := components[m.PURL]
		if !ok {
			unmatched++
			continue
		}
		v := vulns[m.VulnerabilityID]
		o := observed{key: key{Component: id, Vuln: m.VulnerabilityID}, Severity: m.Severity, CVSS: v.BaseScore(),
			EPSS: v.EPSS, KEV: v.KEV != nil, Risk: m.Risk, FixedVersions: m.FixedVersions, FixState: m.FixState, MatchType: m.Type}
		prev, seen := byKey[o.key]
		if !seen {
			byKey[o.key] = o
			continue
		}
		fixed := append(slices.Clone(prev.FixedVersions), o.FixedVersions...)
		if preferred(o, prev) {
			prev, o = o, prev
		}
		prev.FixedVersions = slices.Compact(slices.Sorted(slices.Values(fixed)))
		prev.Risk = max(prev.Risk, o.Risk)
		if prev.FixState == vuln.FixUnknown {
			prev.FixState = o.FixState
		}
		byKey[o.key] = prev
	}
	out := make([]observed, 0, len(byKey))
	for _, o := range byKey {
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b observed) int { return compareKeys(a.key, b.key) })
	return out, unmatched
}

// preferred : a l'emporte sur b (type de correspondance, puis sévérité, puis risque).
func preferred(a, b observed) bool {
	if r := cmp.Compare(typeRank(a.MatchType), typeRank(b.MatchType)); r != 0 {
		return r < 0
	}
	if r := cmp.Compare(a.Severity.Rank(), b.Severity.Rank()); r != 0 {
		return r > 0
	}
	return a.Risk > b.Risk
}

func compareKeys(a, b key) int {
	if c := cmp.Compare(a.Component.String(), b.Component.String()); c != 0 {
		return c
	}
	return cmp.Compare(a.Vuln, b.Vuln)
}

// planFor calcule l'effet d'une analyse : un couple nouveau crée un constat, un couple
// revu le prolonge, un couple résolu qui réapparaît est rouvert, un constat ouvert absent
// de l'analyse est résolu — composant retiré s'il n'est plus dans l'inventaire (inSet),
// sinon la base ne le juge plus vulnérable.
func planFor(existing []current, seen []observed, inSet map[uuid.UUID]bool) plan {
	byKey := make(map[key]current, len(existing))
	for _, c := range existing {
		byKey[c.key] = c
	}
	var p plan
	matched := make(map[key]bool, len(seen))
	for _, o := range seen {
		matched[o.key] = true
		c, ok := byKey[o.key]
		if !ok {
			p.Create = append(p.Create, o)
			continue
		}
		p.Update = append(p.Update, change{ID: c.ID, Obs: o, Reopen: c.Status == StatusResolved})
	}
	for _, c := range existing {
		if c.Status != StatusOpen || matched[c.key] {
			continue
		}
		reason := ResolutionNotMatched
		if !inSet[c.key.Component] {
			reason = ResolutionComponentRemoved
		}
		p.Resolve = append(p.Resolve, resolution{ID: c.ID, Reason: reason})
	}
	slices.SortFunc(p.Update, func(a, b change) int { return cmp.Compare(a.ID.String(), b.ID.String()) })
	slices.SortFunc(p.Resolve, func(a, b resolution) int { return cmp.Compare(a.ID.String(), b.ID.String()) })
	return p
}
