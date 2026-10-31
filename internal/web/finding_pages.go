package web

import (
	"errors"
	"html/template"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/finding"
	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// findingPageSize : constats par page de l'onglet « Constats ».
const findingPageSize = 50

// sevBadge est une sévérité prête à afficher : classe du badge (forme et couleur), clé
// de traduction, score CVSS facultatif.
type sevBadge struct {
	Class    string
	LabelKey string
	Score    *float64
}

var sevClasses = map[vuln.Severity]string{
	vuln.SeverityCritical: "sev sev--critical", vuln.SeverityHigh: "sev sev--high", vuln.SeverityMedium: "sev sev--medium",
	vuln.SeverityLow: "sev sev--low", vuln.SeverityNegligible: "sev sev--none", vuln.SeverityUnknown: "sev sev--none",
}

func sevOf(s vuln.Severity, score *float64) sevBadge {
	class, ok := sevClasses[s]
	if !ok {
		s, class = vuln.SeverityUnknown, sevClasses[vuln.SeverityUnknown]
	}
	return sevBadge{Class: class, LabelKey: "severity." + string(s), Score: score}
}

// sevCount est un décompte par sévérité (pastilles de la liste des références).
type sevCount struct {
	Class    string
	LabelKey string
	Count    int
}

// sevCounts donne les décomptes des quatre sévérités affichées dans les pastilles.
func sevCounts(c finding.Counts) []sevCount {
	var out []sevCount
	for _, s := range []vuln.Severity{vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow} {
		class := sevClasses[s] + " sev--count"
		if c.Of(s) == 0 {
			class += " sev--zero"
		}
		out = append(out, sevCount{Class: class, LabelKey: "severity." + string(s), Count: c.Of(s)})
	}
	return out
}

// riskOf arrondit un risque (0 à 100) pour l'affichage et la jauge.
func riskOf(r float64) int { return int(math.Round(min(max(r, 0), 100))) }

type findingRow struct {
	ID            uuid.UUID
	VulnID        string
	VulnHref      string
	Sev           sevBadge
	EPSS          *float64
	KEV           bool
	Risk          int
	Component     string
	Version       string
	ComponentHref string
	Fixed         []string
	FixState      string
	RefName       string
	RefKind       string
	ProjectName   string
	ProjectKind   string
	ProjectHref   string
	Status        string
	Resolution    string
	FirstSeen     *stamp
	ResolvedAt    *stamp
}

func (id *identity) findingRow(base string, r finding.Row) findingRow {
	return findingRow{
		ID: r.ID, VulnID: r.VulnID, VulnHref: base + "/vulnerabilities/" + url.PathEscape(r.VulnID),
		Sev: sevOf(r.Severity, r.CVSS), EPSS: r.EPSS, KEV: r.KEV, Risk: riskOf(r.Risk),
		Component: r.ComponentName, Version: r.ComponentVersion, ComponentHref: base + "/components/" + r.ComponentID.String(),
		Fixed: r.FixedVersions, FixState: string(r.FixState), RefName: r.RefName, RefKind: r.RefKind,
		ProjectName: r.ProjectName, ProjectKind: r.ProjectKind, ProjectHref: base + "/projects/" + r.ProjectSlug,
		Status: string(r.Status), Resolution: string(r.Resolution), FirstSeen: stampAt(r.FirstSeen), ResolvedAt: stampOf(r.ResolvedAt),
	}
}

type findingRefRow struct {
	ID       uuid.UUID
	Kind     string
	Name     string
	Removed  bool
	Href     string
	Selected bool
	Open     int
	KEV      int
	Sev      []sevCount
}

// segment est un lien d'un sélecteur segmenté (état des constats).
type segment struct {
	LabelKey string
	Href     template.URL
	Count    int
	Current  bool
}

type findingsView struct {
	render.Page
	Base       string
	Project    projectRow
	Tabs       []projectTab
	Refs       []findingRefRow
	Selected   *findingRefRow
	Analyzed   *stamp
	Built      *stamp
	States     []segment
	Severities []option
	KEVOnly    bool
	Resolved   bool
	// StatusValue reporte l'état choisi dans le formulaire des filtres.
	StatusValue string
	Filtered    bool
	Rows        []findingRow
	NextHref    template.URL
}

// findings est l'onglet « Constats » d'un projet : constats de la référence choisie, par
// risque décroissant, filtrables par sévérité et KEV, ouverts ou résolus.
func (id *identity) findings(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	acc := access(r)
	ctx := r.Context()
	q := r.URL.Query()
	base := orgBase(acc) + "/projects/" + p.Slug
	states, err := id.Inventory.RefStates(ctx, acc.Org, p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	counts, err := id.Findings.RefCounts(ctx, acc.Org, p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	analyses, err := id.Findings.Analyses(ctx, acc.Org, p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &findingsView{
		Page: render.Page{TitleKey: "findings.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "findings"),
	}
	selected := selectedRef(states, q.Get("ref"))
	for _, st := range states {
		c := counts[st.RefID]
		row := findingRefRow{ID: st.RefID, Kind: st.Kind, Name: st.Name, Removed: st.Removed,
			Href: base + "/findings?ref=" + st.RefID.String(), Selected: st.RefID == selected, Open: c.Open, KEV: c.KEV, Sev: sevCounts(c)}
		view.Refs = append(view.Refs, row)
	}
	f := finding.Filter{RefID: selected, KEVOnly: q.Get("kev") == "1"}
	if q.Get("status") == string(finding.StatusResolved) {
		f.Status, view.Resolved, view.StatusValue = finding.StatusResolved, true, string(finding.StatusResolved)
	}
	if s := vuln.Severity(q.Get("severity")); s != "" && slices.Contains(vuln.Severities(), s) {
		f.Severity = s
	}
	view.KEVOnly, view.Filtered = f.KEVOnly, f.KEVOnly || f.Severity != ""
	view.Severities = append(view.Severities, option{Value: "", LabelKey: "common.all", Selected: f.Severity == ""})
	for _, s := range vuln.Severities() {
		view.Severities = append(view.Severities, option{Value: string(s), LabelKey: "severity." + string(s), Selected: f.Severity == s})
	}
	if i := slices.IndexFunc(view.Refs, func(r findingRefRow) bool { return r.Selected }); i >= 0 {
		view.Selected = &view.Refs[i]
		if a, ok := analyses[selected]; ok {
			view.Analyzed, view.Built = stampAt(a.AnalyzedAt), dateOf(&a.Built)
		}
		c := counts[selected]
		keep := url.Values{"ref": {selected.String()}}
		resolved := url.Values{"ref": {selected.String()}, "status": {string(finding.StatusResolved)}}
		// Requêtes construites ici par url.Values : sûres comme URL.
		view.States = []segment{
			{LabelKey: "findings.state_open", Href: template.URL("?" + keep.Encode()), Count: c.Open, Current: !view.Resolved},
			{LabelKey: "findings.state_resolved", Href: template.URL("?" + resolved.Encode()), Count: c.Resolved, Current: view.Resolved},
		}
		page, err := id.Findings.Project(ctx, acc.Org, p.ID, f, q.Get("cursor"), findingPageSize)
		if isPaginationError(err) {
			id.rd.Error(w, r, http.StatusBadRequest)
			return
		}
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		for _, row := range page.Items {
			view.Rows = append(view.Rows, id.findingRow(orgBase(acc), row))
		}
		if page.NextCursor != "" {
			next := url.Values{"ref": {selected.String()}}
			for _, k := range []string{"status", "severity", "kev"} {
				if v := q.Get(k); v != "" {
					next.Set(k, v)
				}
			}
			next.Set("cursor", page.NextCursor)
			view.NextHref = template.URL("?" + next.Encode())
		}
	}
	id.rd.Render(w, r, http.StatusOK, "projects/findings", view)
}

// cvssView est un score CVSS prêt à afficher.
type cvssView struct {
	Version string
	Source  string
	Vector  string
	Score   float64
	Sev     sevBadge
	Metrics []metricView
}

type metricView struct {
	NameKey  string
	ValueKey string
}

// cvssSeverity déduit la sévérité qualitative d'un score CVSS 3 (spécification FIRST).
func cvssSeverity(score float64) vuln.Severity {
	switch {
	case score >= 9:
		return vuln.SeverityCritical
	case score >= 7:
		return vuln.SeverityHigh
	case score >= 4:
		return vuln.SeverityMedium
	case score > 0:
		return vuln.SeverityLow
	}
	return vuln.SeverityUnknown
}

type linkView struct {
	Href  string
	Label string
}

type vulnerabilityView struct {
	render.Page
	Base        string
	ID          string
	Aliases     []string
	Sev         sevBadge
	Namespace   string
	Description string
	Primary     *cvssView
	Others      []cvssView
	EPSS        *vuln.EPSS
	EPSSDate    *stamp
	KEV         *vuln.KEV
	KEVAdded    *stamp
	KEVDue      *stamp
	CWEs        []string
	Links       []linkView
	Built       *stamp
	States      []segment
	Resolved    bool
	Counts      finding.Counts
	Rows        []findingRow
	Truncated   bool
}

// vulnerability est la fiche d'une vulnérabilité : catalogue public, constats de
// l'organisation.
func (id *identity) vulnerability(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	vid := chi.URLParam(r, "vulnID")
	status := finding.StatusOpen
	if r.URL.Query().Get("state") == string(finding.StatusResolved) {
		status = finding.StatusResolved
	}
	e, rows, counts, err := id.Findings.Vulnerability(r.Context(), acc.Org, vid, status)
	if errors.Is(err, vuln.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &vulnerabilityView{
		Page: render.Page{TitleKey: "vulnerability.title", TitleArgs: map[string]any{"ID": e.ID}, Nav: orgNav(acc, "")},
		Base: orgBase(acc), ID: e.ID, Aliases: e.Aliases, Namespace: e.Namespace, Description: e.Description,
		EPSS: e.EPSS, KEV: e.KEV, CWEs: e.CWEs, Built: dateOf(&e.Built), Counts: counts, Resolved: status == finding.StatusResolved,
		Truncated: len(rows) >= finding.ListMax,
	}
	var primary *float64
	if c, ok := e.PrimaryCVSS(); ok {
		score := c.BaseScore
		primary = &score
		view.Primary = cvssOf(c)
	}
	view.Sev = sevOf(e.Severity, primary)
	for _, c := range e.CVSS {
		if view.Primary != nil && c.Vector == view.Primary.Vector && c.Source == view.Primary.Source {
			continue
		}
		view.Others = append(view.Others, *cvssOf(c))
	}
	if e.EPSS != nil && !e.EPSS.Date.IsZero() {
		view.EPSSDate = dateOf(&e.EPSS.Date)
	}
	if e.KEV != nil {
		view.KEVAdded, view.KEVDue = dateOf(e.KEV.DateAdded), dateOf(e.KEV.DueDate)
	}
	for _, u := range append([]string{e.DataSource}, e.URLs...) {
		if l, ok := linkOf(u); ok && !slices.ContainsFunc(view.Links, func(x linkView) bool { return x.Href == l.Href }) {
			view.Links = append(view.Links, l)
		}
	}
	open := "?state=open"
	view.States = []segment{
		{LabelKey: "vulnerability.state_open", Href: template.URL(open), Count: counts.Open, Current: !view.Resolved},
		{LabelKey: "vulnerability.state_resolved", Href: template.URL("?state=resolved"), Count: counts.Resolved, Current: view.Resolved},
	}
	for _, row := range rows {
		view.Rows = append(view.Rows, id.findingRow(orgBase(acc), row))
	}
	id.rd.Render(w, r, http.StatusOK, "vulnerabilities/show", view)
}

func cvssOf(c vuln.CVSS) *cvssView {
	v := &cvssView{Version: c.Version, Source: c.Source, Vector: c.Vector, Score: c.BaseScore, Sev: sevOf(cvssSeverity(c.BaseScore), nil)}
	for _, m := range vuln.ParseCVSS3(c.Vector) {
		v.Metrics = append(v.Metrics, metricView{NameKey: "cvss.metric_" + m.Name, ValueKey: "cvss." + m.Name + "_" + m.Value})
	}
	return v
}

// linkOf garde une référence http(s) et l'affiche par son hôte et son chemin.
func linkOf(raw string) (linkView, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return linkView{}, false
	}
	label := u.Host + strings.TrimSuffix(u.Path, "/")
	if len(label) > 80 {
		label = label[:77] + "…"
	}
	return linkView{Href: u.String(), Label: label}, true
}

type versionBar struct {
	Version    string
	Width      int // part des occurrences, en pourcentage de la version la plus utilisée
	Vulnerable bool
	Count      int
	Projects   int
}

type matrixRow struct {
	VulnID   string
	VulnHref string
	Sev      sevBadge
	KEV      bool
	Fixed    []string
	Hits     []bool // une case par version de Versions
}

type usageRow struct {
	ProjectName string
	ProjectKind string
	ProjectHref string
	RefName     string
	RefKind     string
	Version     string
	Origin      string
	Confidence  *int
	Open        int
	KEV         bool
	Scanned     *stamp
	SnapshotURL string
	CommitShort string
	Current     bool // version de la fiche
}

type componentView struct {
	render.Page
	Base      string
	Component inventory.Component
	Projects  int
	Versions  []versionBar
	Columns   []string
	Matrix    []matrixRow
	Usage     []usageRow
	Licenses  []string
	Truncated bool
}

// component est la fiche d'un composant : projets qui l'utilisent (inventaire courant de
// chaque référence), répartition des versions et vulnérabilités par version, toutes
// versions de même purl_base confondues.
func (id *identity) component(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	cid, err := uuid.Parse(chi.URLParam(r, "componentID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	c, usage, err := id.Inventory.Component(r.Context(), acc.Org, cid)
	if errors.Is(err, inventory.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	rows, err := id.Findings.Component(r.Context(), acc.Org, c.PURLBase)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &componentView{
		Page: render.Page{TitleKey: "component.title", TitleArgs: map[string]any{"Name": c.Name}, Nav: orgNav(acc, "")},
		Base: base, Component: c, Truncated: len(usage) >= inventory.UsageMax || len(rows) >= finding.ListMax,
	}
	// Constats ouverts par (référence, composant) et versions vulnérables.
	type refComp struct{ ref, comp uuid.UUID }
	open := map[refComp]int{}
	kev := map[refComp]bool{}
	vulnerable := map[string]bool{}
	for _, f := range rows {
		k := refComp{f.RefID, f.ComponentID}
		open[k]++
		kev[k] = kev[k] || f.KEV
		vulnerable[f.ComponentVersion] = true
	}
	occ, projs := map[string]int{}, map[string]map[uuid.UUID]bool{}
	allProjects, licenses := map[uuid.UUID]bool{}, map[string]bool{}
	for _, u := range usage {
		k := refComp{u.RefID, u.ComponentID}
		row := usageRow{ProjectName: u.ProjectName, ProjectKind: u.ProjectKind, ProjectHref: base + "/projects/" + u.ProjectSlug,
			RefName: u.RefName, RefKind: u.RefKind, Version: u.Version, Origin: string(u.Origin), Open: open[k], KEV: kev[k],
			Scanned: stampAt(u.ScannedAt), SnapshotURL: base + "/projects/" + u.ProjectSlug + "/snapshots/" + u.SnapshotID.String(),
			CommitShort: shortCommit(u.Commit), Current: u.ComponentID == c.ID}
		if u.Confidence != nil {
			pct := int(math.Round(*u.Confidence * 100))
			row.Confidence = &pct
		}
		view.Usage = append(view.Usage, row)
		occ[u.Version]++
		if projs[u.Version] == nil {
			projs[u.Version] = map[uuid.UUID]bool{}
		}
		projs[u.Version][u.ProjectID] = true
		allProjects[u.ProjectID] = true
		for _, l := range u.Licenses {
			licenses[l] = true
		}
	}
	view.Projects = len(allProjects)
	view.Licenses = slices.Sorted(maps.Keys(licenses))
	maxOcc := 0
	for _, n := range occ {
		maxOcc = max(maxOcc, n)
	}
	versions := slices.Sorted(maps.Keys(occ))
	for _, v := range versions {
		view.Versions = append(view.Versions, versionBar{Version: v, Width: occ[v] * 100 / maxOcc, Vulnerable: vulnerable[v],
			Count: occ[v], Projects: len(projs[v])})
	}
	// Matrice : une ligne par vulnérabilité, une colonne par version présente.
	view.Columns = versions
	byVuln := map[string]*matrixRow{}
	var order []string
	for _, f := range rows {
		m, ok := byVuln[f.VulnID]
		if !ok {
			m = &matrixRow{VulnID: f.VulnID, VulnHref: base + "/vulnerabilities/" + url.PathEscape(f.VulnID),
				Sev: sevOf(f.Severity, f.CVSS), KEV: f.KEV, Hits: make([]bool, len(versions))}
			byVuln[f.VulnID] = m
			order = append(order, f.VulnID)
		}
		if i := slices.Index(versions, f.ComponentVersion); i >= 0 {
			m.Hits[i] = true
		}
		for _, v := range f.FixedVersions {
			if !slices.Contains(m.Fixed, v) {
				m.Fixed = append(m.Fixed, v)
			}
		}
	}
	for _, v := range order {
		view.Matrix = append(view.Matrix, *byVuln[v])
	}
	id.rd.Render(w, r, http.StatusOK, "components/show", view)
}
