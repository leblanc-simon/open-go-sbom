package api

import (
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/language"

	"github.com/google/uuid"
	"leblanc.io/lotor/internal/api/gen"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/tenant"
)

// Verdicts donne le verdict des politiques sur un instantané (policy.Service).
type Verdicts interface {
	Verdict(ctx context.Context, org tenant.OrgID, agentID, snapshotID uuid.UUID) (policy.Verdict, error)
}

// maxSummary borne le résumé d'un verdict : la description d'un statut de commit GitHub
// ne dépasse pas 140 caractères.
const maxSummary = 140

// GetSnapshotVerdict renvoie le verdict d'un instantané envoyé par l'agent.
func (h *agentAPI) GetSnapshotVerdict(ctx context.Context, req gen.GetSnapshotVerdictRequestObject) (gen.GetSnapshotVerdictResponseObject, error) {
	p, _ := principalFrom(ctx)
	v, err := h.Verdicts.Verdict(ctx, p.Org, p.AgentID, req.Id)
	if err != nil {
		return nil, err
	}
	out := gen.Verdict{State: string(v.State), Blocking: v.Blocking, Warnings: v.Warnings, Policies: v.Policies,
		Summary: h.verdictSummary(v)}
	if out.Policies == nil {
		out.Policies = []string{}
	}
	if v.URL != "" {
		out.Url = &v.URL
	}
	return gen.GetSnapshotVerdict200JSONResponse(out), nil
}

// verdictSummary résume un verdict dans la langue de l'organisation.
func (h *agentAPI) verdictSummary(v policy.Verdict) string {
	tag, err := language.Parse(v.Language)
	if err != nil {
		tag = h.Catalog.Default()
	}
	loc := h.Catalog.Localizer(tag)
	var s string
	switch v.State {
	case policy.VerdictPending:
		s = loc.T("verdict.pending")
	case policy.VerdictFail:
		s = loc.T("verdict.fail", map[string]any{"Count": v.Blocking, "Policies": strings.Join(v.Policies, ", ")})
	default:
		if v.Warnings > 0 {
			s = loc.T("verdict.pass_warnings", map[string]any{"Count": v.Warnings})
		} else {
			s = loc.T("verdict.pass")
		}
	}
	if utf8.RuneCountInString(s) > maxSummary {
		r := []rune(s)
		s = string(r[:maxSummary-1]) + "…"
	}
	return s
}
