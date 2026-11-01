package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/api/gen/userapi"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// Clés d'erreur des comparaisons d'instantanés.
const (
	KeyNoPrevious  = "error.diff.no_previous"
	KeyKindInvalid = "error.diff.kind_invalid"
)

// project résout le projet du chemin parmi ceux que voit le propriétaire du jeton ; un
// projet invisible ou inconnu répond 404 (faux).
func (h *userAPI) project(w http.ResponseWriter, r *http.Request, slug string) (tenant.Access, project.Project, bool) {
	acc, _ := tenant.AccessFrom(r.Context())
	p, err := h.Projects.Get(r.Context(), acc.Org, acc.Visibility(), slug)
	if errors.Is(err, project.ErrNotFound) {
		problem.Write(w, r, h.Catalog, http.StatusNotFound, problem.KeyNotFound, nil)
		return acc, project.Project{}, false
	}
	if err != nil {
		h.internal(w, r, err)
		return acc, project.Project{}, false
	}
	return acc, p, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ListProjectSnapshots sert la frise des instantanés d'un projet.
func (h *userAPI) ListProjectSnapshots(w http.ResponseWriter, r *http.Request, _ userapi.Org, slug userapi.Project,
	params userapi.ListProjectSnapshotsParams) {
	acc, p, ok := h.project(w, r, slug)
	if !ok {
		return
	}
	limit, err := pagination.Limit(params.Limit, inventory.SnapshotPageDefault, inventory.SnapshotPageMax)
	var page pagination.Page[inventory.Snapshot]
	if err == nil {
		var ref uuid.UUID
		if params.Ref != nil {
			ref = *params.Ref
		}
		page, err = h.Inventory.Snapshots(r.Context(), acc.Org, p.ID, ref, deref(params.Cursor), limit)
	}
	if err != nil {
		if !problem.FromPagination(w, r, h.Catalog, err) {
			h.internal(w, r, err)
		}
		return
	}
	out := userapi.SnapshotPage{Snapshots: []userapi.SnapshotSummary{}}
	for _, s := range page.Items {
		out.Snapshots = append(out.Snapshots, snapshotSummary(s))
	}
	out.Page.NextCursor = nextCursor(page.NextCursor)
	writeJSON(w, out)
}

// CompareSnapshots sert la comparaison de deux instantanés d'un projet et son effet sur
// la sécurité.
func (h *userAPI) CompareSnapshots(w http.ResponseWriter, r *http.Request, _ userapi.Org, slug userapi.Project,
	params userapi.CompareSnapshotsParams) {
	acc, p, ok := h.project(w, r, slug)
	if !ok {
		return
	}
	req := inventory.DiffRequest{ProjectID: p.ID, To: params.To, Cursor: deref(params.Cursor)}
	if params.From != nil {
		req.From = *params.From
	}
	if params.Kind != nil {
		req.Kind = inventory.ChangeKind(*params.Kind)
	}
	limit, err := pagination.Limit(params.Limit, inventory.ChangePageDefault, inventory.ChangePageMax)
	var res inventory.DiffResult
	if err == nil {
		req.Limit = limit
		res, err = h.History.Diff(r.Context(), acc.Org, req)
	}
	switch {
	case err == nil:
	case errors.Is(err, inventory.ErrNotFound):
		problem.Write(w, r, h.Catalog, http.StatusNotFound, problem.KeyNotFound, nil)
		return
	case errors.Is(err, inventory.ErrNoPrevious):
		problem.Write(w, r, h.Catalog, http.StatusNotFound, KeyNoPrevious, nil)
		return
	case errors.Is(err, inventory.ErrInvalidChangeKind):
		problem.Write(w, r, h.Catalog, http.StatusBadRequest, KeyKindInvalid, nil)
		return
	default:
		if !problem.FromPagination(w, r, h.Catalog, err) {
			h.internal(w, r, err)
		}
		return
	}
	eff, err := h.Findings.Effect(r.Context(), acc.Org,
		finding.EffectSide{SnapshotID: res.From.ID, RefID: res.From.RefID, SetID: res.From.SetID},
		finding.EffectSide{SnapshotID: res.To.ID, RefID: res.To.RefID, SetID: res.To.SetID})
	if err != nil {
		h.internal(w, r, err)
		return
	}
	out := userapi.SnapshotComparison{From: snapshotSummary(res.From), To: snapshotSummary(res.To), Counts: changeCounts(res.Counts),
		Changes: []userapi.SnapshotChange{},
		Security: userapi.SecurityImpact{AnalysisPending: eff.Pending, IntroducedTotal: eff.IntroducedTotal,
			ResolvedTotal: eff.ResolvedTotal, Introduced: impactFindings(eff.Introduced), Resolved: impactFindings(eff.Resolved)}}
	for _, c := range res.Changes.Items {
		ch := userapi.SnapshotChange{Kind: userapi.SnapshotChangeKind(c.Kind), PurlBase: c.PURLBase, Name: c.Name, Type: c.Type,
			Approximate: c.Approximate, Old: changedComponent(c.Old), New: changedComponent(c.New)}
		out.Changes = append(out.Changes, ch)
	}
	out.Page.NextCursor = nextCursor(res.Changes.NextCursor)
	writeJSON(w, out)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nextCursor(c string) *string {
	if c == "" {
		return nil
	}
	return &c
}

func changeCounts(c inventory.DiffCounts) userapi.ChangeCounts {
	return userapi.ChangeCounts{Added: c.Added, Removed: c.Removed, Upgraded: c.Upgraded, Downgraded: c.Downgraded}
}

func changedComponent(s *inventory.ChangeSide) *userapi.ChangedComponent {
	if s == nil {
		return nil
	}
	return &userapi.ChangedComponent{ComponentId: s.ComponentID, Purl: s.PURL, Version: s.Version}
}

func snapshotSummary(s inventory.Snapshot) userapi.SnapshotSummary {
	out := userapi.SnapshotSummary{Id: s.ID, Ref: userapi.SearchRef{Id: s.RefID, Kind: userapi.SearchRefKind(s.RefKind), Name: s.RefName},
		ScannedAt: s.ScannedAt.UTC(), LastScannedAt: s.LastScannedAt.UTC(), AgentVersion: s.AgentVersion, Format: string(s.Format),
		SpecVersion: s.SpecVersion, Current: s.Current, ChangesPending: s.ChangesPending, PreviousId: s.PreviousID,
		Components: userapi.ComponentCounts{Total: s.Counts.Total, Syft: s.Counts.Syft, Ia: s.Counts.IA, Weak: s.Counts.Weak}}
	if s.Commit != "" {
		c := s.Commit
		out.Commit = &c
	}
	if s.Changes != nil {
		c := changeCounts(*s.Changes)
		out.Changes = &c
	}
	return out
}

func impactFindings(rows []finding.Row) []userapi.ImpactFinding {
	out := []userapi.ImpactFinding{}
	for _, f := range rows {
		fixed := f.FixedVersions
		if fixed == nil {
			fixed = []string{}
		}
		out = append(out, userapi.ImpactFinding{FindingId: f.ID, Vulnerability: f.VulnID, Severity: string(f.Severity), Kev: f.KEV,
			Risk: f.Risk, Status: string(f.Status), FixedVersions: fixed,
			Ref:       userapi.SearchRef{Id: f.RefID, Kind: userapi.SearchRefKind(f.RefKind), Name: f.RefName},
			Component: userapi.SearchComponent{Id: f.ComponentID, Purl: f.ComponentPURL, Name: f.ComponentName, Version: f.ComponentVersion}})
	}
	return out
}
