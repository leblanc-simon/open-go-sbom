package triage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/version"
)

// Statement est une déclaration VEX, indépendante du format : une vulnérabilité, un
// composant (purl), un statut et ce qui l'accompagne. C'est l'unité qu'échangent les
// exports et les imports (paquet triage/vex).
type Statement struct {
	VulnID        string
	PURL          string // purl du composant ; sans version à l'import : toutes les versions
	Status        Status
	Justification Justification // d'origine, OpenVEX ou CycloneDX
	Comment       string        // déclaration d'impact, ou d'action pour « affecté »
	ExpiresOn     *time.Time    // risque accepté
	Time          time.Time     // date de la décision
}

// Bornes des imports.
const (
	// MaxImportStatements borne les déclarations d'un import, produits développés.
	MaxImportStatements = 5000
	MaxSourceLen        = 100
)

// Clés de validation des imports.
const (
	KeySourceInvalid  = "validation.vex_source_invalid"
	KeyImportTooLarge = "validation.vex_too_many_statements"
	KeyImportEmpty    = "validation.vex_no_statement"
)

// ImportInput est un document VEX déjà décodé, à importer pour un projet ou pour toute
// l'organisation.
type ImportInput struct {
	Scope     Scope
	ProjectID uuid.UUID // ScopeProject
	// Source nomme l'éditeur du VEX : les décisions ont pour auteur « vex:<source> ».
	Source     string
	Format     string // openvex, cyclonedx (journal)
	Statements []Statement
}

// ImportResult résume un import.
type ImportResult struct {
	Decisions int // décisions enregistrées
	Ignored   int // déclarations écartées (purl ou vulnérabilité illisible, statut incohérent, composant absent du projet)
	Changed   int // constats dont le statut effectif a changé
}

// CleanSource normalise le nom d'une source : espaces de bord retirés et réduits, sans
// caractère de contrôle, MaxSourceLen caractères au plus.
func CleanSource(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxSourceLen || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	return s, true
}

type projectComponent struct {
	purl  string
	base  string
	vers  string
	quals map[string]string
}

// projectComponents renvoie les composants des constats d'un projet dont la famille est
// l'une des bases.
func projectComponents(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID, bases []string) (map[string][]projectComponent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT c.purl, c.purl_base, c.version FROM findings f
		  JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
		 WHERE f.project_id = $1 AND c.purl_base = ANY($2::text[]) ORDER BY c.purl`, projectID, bases)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]projectComponent{}
	for rows.Next() {
		var pc projectComponent
		if err := rows.Scan(&pc.purl, &pc.base, &pc.vers); err != nil {
			return nil, err
		}
		pc.quals = qualifiers(pc.purl)
		out[pc.base] = append(out[pc.base], pc)
	}
	return out, rows.Err()
}

func qualifiers(p string) map[string]string {
	out := map[string]string{}
	if u, err := packageurl.FromString(p); err == nil {
		for _, q := range u.Qualifiers {
			out[q.Key] = q.Value
		}
	}
	return out
}

// matches dit si le composant du projet répond au purl d'une déclaration : même version
// (toute version si la déclaration n'en a pas), et chaque qualificatif de la déclaration
// présent à l'identique.
func (pc projectComponent) matches(p sbom.PURL, quals map[string]string) bool {
	if p.Version != "" && p.Version != pc.vers {
		return false
	}
	for k, v := range quals {
		if pc.quals[k] != v {
			return false
		}
	}
	return true
}

// Import enregistre les déclarations d'un VEX comme décisions d'auteur « vex:<source> »
// (le compte qui importe est noté), recalcule les constats concernés et journalise
// l'import, dans une seule transaction. Pour un projet, une déclaration vise les
// composants de ses constats de même famille, de même version (toutes si elle n'en donne
// pas) et aux qualificatifs compatibles ; pour l'organisation, la famille (purl_base),
// restreinte à la version déclarée si elle en a une. Une même clé déclarée deux fois
// garde la dernière déclaration. Le droit de l'acteur est vérifié par l'appelant.
func (s *Service) Import(ctx context.Context, org tenant.OrgID, actor audit.Actor, in ImportInput) (ImportResult, error) {
	var res ImportResult
	source, ok := CleanSource(in.Source)
	if !ok {
		return res, invalid("source", KeySourceInvalid)
	}
	if in.Scope != ScopeProject && in.Scope != ScopeOrg || (in.Scope == ScopeProject) != (in.ProjectID != uuid.Nil) {
		return res, invalid("scope", KeyScopeInvalid)
	}
	if len(in.Statements) == 0 {
		return res, invalid("file", KeyImportEmpty)
	}
	if len(in.Statements) > MaxImportStatements {
		return res, invalid("file", KeyImportTooLarge)
	}
	type parsed struct {
		st    Statement
		p     sbom.PURL
		quals map[string]string
	}
	var ok2 []parsed
	var bases []string
	for _, st := range in.Statements {
		p, err := sbom.CanonicalPURL(st.PURL)
		vid := strings.TrimSpace(st.VulnID)
		if err != nil || vid == "" || len(vid) > 200 || strings.ContainsFunc(vid, unicode.IsSpace) {
			res.Ignored++
			continue
		}
		st.VulnID = vid
		ok2 = append(ok2, parsed{st: st, p: p, quals: qualifiers(p.String)})
		bases = append(bases, p.Base)
	}
	slices.Sort(bases)
	bases = slices.Compact(bases)
	now := s.now()
	label := "vex:" + source
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var comps map[string][]projectComponent
		if in.Scope == ScopeProject {
			var err error
			if comps, err = projectComponents(ctx, tx, in.ProjectID, bases); err != nil {
				return err
			}
		}
		byKey := map[decisionKey]Decision{}
		var order []decisionKey
		add := func(d Decision) {
			if err := s.validate(&d, false, purlType(d)); err != nil {
				res.Ignored++
				return
			}
			k := d.key()
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = d
		}
		for _, x := range ok2 {
			base := Decision{Scope: in.Scope, VulnID: x.st.VulnID, PURLBase: x.p.Base, Action: ActionSet, Status: x.st.Status,
				Justification: x.st.Justification, Comment: x.st.Comment, ExpiresOn: x.st.ExpiresOn,
				AuthorUserID: actor.UserID, AuthorLabel: label, CreatedAt: now}
			if in.Scope == ScopeOrg {
				if x.p.Version != "" {
					v, err := exactVers(x.p, s.o.Comparer)
					if err != nil {
						res.Ignored++
						continue
					}
					base.Vers = v
				}
				base.purlType = x.p.Type
				add(base)
				continue
			}
			matched := false
			for _, pc := range comps[x.p.Base] {
				if pc.matches(x.p, x.quals) {
					d := base
					d.ProjectID, d.PURL, d.purlType = in.ProjectID, pc.purl, x.p.Type
					add(d)
					matched = true
				}
			}
			if !matched {
				res.Ignored++
			}
		}
		if len(order) == 0 {
			return audit.RecordOrg(ctx, tx, actor, importEvent(in, source, res))
		}
		if err := lock(ctx, tx, true); err != nil {
			return err
		}
		ds := make([]Decision, 0, len(order))
		seen := map[pair]bool{}
		var pairs []pair
		for _, k := range order {
			d := byKey[k]
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			d.ID = id
			ds = append(ds, d)
			if p := (pair{d.PURLBase, d.VulnID}); !seen[p] {
				seen[p] = true
				pairs = append(pairs, p)
			}
		}
		if err := insertDecisions(ctx, tx, ds); err != nil {
			return err
		}
		for _, d := range ds {
			if err := s.scheduleExpiry(ctx, tx, d); err != nil {
				return err
			}
		}
		slices.SortFunc(pairs, comparePairs)
		changes, err := s.recompute(ctx, tx, pairs)
		if err != nil {
			return err
		}
		res.Decisions, res.Changed = len(ds), len(changes)
		return audit.RecordOrg(ctx, tx, actor, importEvent(in, source, res))
	})
	if err != nil {
		return ImportResult{}, wrap("import VEX", err)
	}
	return res, nil
}

func purlType(d Decision) string { return d.purlType }

// exactVers écrit la plage vers d'une seule version, dans le schéma du type du purl.
func exactVers(p sbom.PURL, cmp version.Comparer) (string, error) {
	r, err := version.ParseVers("vers:"+p.Type+"/"+url.PathEscape(p.Version), cmp)
	if err != nil {
		return "", err
	}
	if r.Scheme != version.ForPURLType(p.Type) {
		return "", fmt.Errorf("triage: schéma vers %s pour un purl %s", r.Scheme, p.Type)
	}
	return r.String(), nil
}

func importEvent(in ImportInput, source string, res ImportResult) audit.Event {
	e := audit.Event{Action: audit.TriageVEXImported, TargetType: "org", TargetLabel: "vex:" + source,
		Details: map[string]string{"scope": string(in.Scope), "format": in.Format, "source": source,
			"statements": fmt.Sprint(len(in.Statements)), "decisions": fmt.Sprint(res.Decisions),
			"ignored": fmt.Sprint(res.Ignored), "changed": fmt.Sprint(res.Changed)}}
	if in.Scope == ScopeProject {
		e.TargetType, e.TargetID = "project", in.ProjectID.String()
	}
	return e
}

// Statements renvoie les déclarations à exporter pour un projet : une par couple
// (composant, vulnérabilité) de ses constats ouverts qui ont une décision (du projet ou
// de l'organisation), avec cette décision. Les constats sans décision (« à analyser »
// par défaut) n'y figurent pas. Triées par purl puis vulnérabilité.
func (s *Service) Statements(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) (out []Statement, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (c.purl, f.vuln_id) c.purl, f.vuln_id, d.status, coalesce(d.justification, ''), d.comment,
			       d.expires_on, d.created_at
			  FROM findings f
			  JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			  JOIN triage_decisions d ON d.org_id = f.org_id AND d.id = f.triage_decision_id
			 WHERE f.project_id = $1 AND f.status = 'open'
			 ORDER BY c.purl, f.vuln_id, d.created_at DESC`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st Statement
			var status, just string
			var until sql.NullTime
			if err := rows.Scan(&st.PURL, &st.VulnID, &status, &just, &st.Comment, &until, &st.Time); err != nil {
				return err
			}
			st.Status, st.Justification, st.Time = Status(status), Justification(just), st.Time.UTC()
			if until.Valid {
				t := time.Date(until.Time.Year(), until.Time.Month(), until.Time.Day(), 0, 0, 0, 0, time.UTC)
				st.ExpiresOn = &t
			}
			out = append(out, st)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("déclarations du projet", err)
}
