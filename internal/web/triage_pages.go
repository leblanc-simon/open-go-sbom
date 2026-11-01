package web

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/triage/vex"
)

// Triage des constats et VEX (T14, ADR 0035 à 0037) : fiche d'un constat avec son
// panneau de triage et son historique, retrait d'une décision, page VEX d'un projet
// (export et import) et décisions de l'organisation.

// statusBadge est un statut de triage prêt à afficher : la forme du repère et le libellé
// le portent, pas seulement la couleur.
type statusBadge struct {
	Class    string
	LabelKey string
}

func triageBadge(s triage.Status) statusBadge {
	if _, err := triage.ParseStatus(string(s)); err != nil {
		s = triage.StatusInTriage
	}
	return statusBadge{Class: "status status--" + strings.ReplaceAll(string(s), "_", "-"), LabelKey: "status." + string(s)}
}

// statusChoice est un statut proposé par le panneau de triage.
type statusChoice struct {
	Value   string
	Badge   statusBadge
	DescKey string
	Checked bool
	Current bool // statut effectif actuel
}

// scopeChoice est une portée proposée par le panneau.
type scopeChoice struct {
	Value    string
	LabelKey string
	DescKey  string
	Args     map[string]any
	Checked  bool
}

// triageForm est la saisie du panneau, renvoyée telle quelle en cas d'erreur.
type triageForm struct {
	Status        string
	Justification string
	Comment       string
	ExpiresOn     string
	Scope         string
	Vers          string
}

// historyRow est une ligne de l'historique d'un constat : une décision, ou un événement
// de l'analyse (ouverture, résolution, réouverture).
type historyRow struct {
	When          *stamp
	Who           string // auteur d'une décision
	SystemKey     string // auteur système (analyse, échéance)
	ActionKey     string
	Args          map[string]any
	Badge         *statusBadge
	ScopeKey      string
	Vers          string
	Justification string
	JustVocabKey  string
	Comment       string
	ExpiresOn     *stamp
	Applied       bool
	WithdrawHref  string
}

type triageView struct {
	render.Page
	Base       string
	Project    projectRow
	Tabs       []projectTab
	Finding    findingRow
	PURL       string
	Effective  statusBadge
	SourceKey  string // origine du statut effectif
	CanTriage  bool
	Statuses   []statusChoice
	JustOVX    []option
	JustCDX    []option
	Scopes     []scopeChoice
	ShowVers   bool
	Form       triageForm
	Error      formError
	FlashKey   string
	History    []historyRow
	Action     string
	Back       string
	MinExpiry  string
	MaxExpiry  string
	VulnHref   string
	CommentMax int
}

// findingFromPath lit le constat {findingID} du projet de la route.
func (id *identity) findingFromPath(w http.ResponseWriter, r *http.Request) (project.Project, finding.Row, bool) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return p, finding.Row{}, false
	}
	fid, err := uuid.Parse(chi.URLParam(r, "findingID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return p, finding.Row{}, false
	}
	row, err := id.Findings.Get(r.Context(), access(r).Org, p.ID, fid)
	if errors.Is(err, finding.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return p, finding.Row{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return p, finding.Row{}, false
	}
	return p, row, true
}

// findingPage est la fiche d'un constat : résumé, panneau de triage (analyste ou
// administrateur de l'équipe du projet) et historique.
func (id *identity) findingPage(w http.ResponseWriter, r *http.Request) {
	p, row, ok := id.findingFromPath(w, r)
	if !ok {
		return
	}
	id.renderFinding(w, r, http.StatusOK, p, row, triageForm{}, formError{})
}

func (id *identity) renderFinding(w http.ResponseWriter, r *http.Request, status int, p project.Project, row finding.Row, form triageForm, fe formError) {
	acc := access(r)
	ctx := r.Context()
	base := orgBase(acc)
	history, err := id.Triage.History(ctx, acc.Org, p.ID, row.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	events, err := id.Findings.Events(ctx, acc.Org, row.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	canOrg := acc.Can(tenant.PermTriageOrg, uuid.Nil)
	projectURL := base + "/projects/" + p.Slug
	view := &triageView{
		Page: render.Page{TitleKey: "triage.title", TitleArgs: map[string]any{"ID": row.VulnID, "Component": row.ComponentName},
			Nav: orgNav(acc, "projects")},
		Base: base, Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "findings"),
		Finding: id.findingRow(base, row), PURL: row.ComponentPURL, Effective: triageBadge(row.TriageStatus),
		CanTriage: acc.Can(tenant.PermFindingTriage, p.TeamID), Form: form, Error: fe, FlashKey: flashKey(r),
		Action: projectURL + "/findings/" + row.ID.String() + "/triage",
		Back:   projectURL + "/findings?ref=" + row.RefID.String(), VulnHref: base + "/vulnerabilities/" + url.PathEscape(row.VulnID),
		CommentMax: triage.MaxComment,
	}
	if view.Form.Scope == "" {
		view.Form.Scope = string(triage.ScopeProject)
	}
	if view.Form.Status == "" {
		view.Form.Status = string(row.TriageStatus)
	}
	today := id.Agents.Now().UTC()
	view.MinExpiry = today.Format(time.DateOnly)
	view.MaxExpiry = today.Add(triage.MaxAcceptance).Format(time.DateOnly)
	view.SourceKey = "triage.source_default"
	for _, h := range history {
		if !h.Applied {
			continue
		}
		switch {
		case h.Action == triage.ActionExpire:
			view.SourceKey = "triage.source_expired"
		case h.Scope == triage.ScopeOrg:
			view.SourceKey = "triage.source_org"
		default:
			view.SourceKey = "triage.source_project"
		}
	}
	for _, s := range triage.Statuses() {
		view.Statuses = append(view.Statuses, statusChoice{Value: string(s), Badge: triageBadge(s),
			DescKey: "triage.desc_" + string(s), Checked: view.Form.Status == string(s), Current: s == row.TriageStatus})
	}
	for _, j := range triage.CycloneDXJustifications() {
		view.JustCDX = append(view.JustCDX, option{Value: string(j), LabelKey: "vex_justification." + string(j),
			Selected: view.Form.Justification == string(j)})
	}
	for _, j := range triage.OpenVEXJustifications() {
		view.JustOVX = append(view.JustOVX, option{Value: string(j), LabelKey: "vex_justification." + string(j),
			Selected: view.Form.Justification == string(j)})
	}
	view.Scopes = []scopeChoice{{Value: string(triage.ScopeProject), LabelKey: "triage.scope_project",
		DescKey: "triage.scope_project_desc", Args: map[string]any{"Project": p.Name}, Checked: view.Form.Scope == string(triage.ScopeProject)}}
	if canOrg && view.CanTriage {
		n, err := id.Triage.PairCount(ctx, acc.Org, row.ComponentPURLBase, row.VulnID)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		view.Scopes = append(view.Scopes, scopeChoice{Value: string(triage.ScopeOrg), LabelKey: "triage.scope_org",
			DescKey: "triage.scope_org_desc", Args: map[string]any{"Count": n, "Component": row.ComponentName, "ID": row.VulnID},
			Checked: view.Form.Scope == string(triage.ScopeOrg)})
		view.ShowVers = true
	}
	view.History = id.historyRows(acc, p, history, events)
	id.rd.Render(w, r, status, "projects/finding", view)
}

// historyRows fusionne décisions et événements de l'analyse, du plus récent au plus
// ancien.
func (id *identity) historyRows(acc tenant.Access, p project.Project, hs []triage.HistoryEntry, events []finding.Event) []historyRow {
	type dated struct {
		at  time.Time
		row historyRow
	}
	var all []dated
	base := orgBase(acc)
	for _, h := range hs {
		row := historyRow{When: stampAt(h.CreatedAt), Who: h.AuthorLabel, ScopeKey: "triage.scope_short_" + string(h.Scope),
			Vers: h.Vers, Comment: h.Comment, Applied: h.Applied, Justification: string(h.Justification)}
		if h.Justification != "" {
			row.JustVocabKey = "vex_vocabulary." + string(h.Justification.Vocabulary())
		}
		switch h.Action {
		case triage.ActionSet:
			row.ActionKey = "triage.history_set"
			b := triageBadge(h.Status)
			row.Badge = &b
			row.ExpiresOn = dateOf(h.ExpiresOn)
		case triage.ActionWithdraw:
			row.ActionKey = "triage.history_withdrawn"
		case triage.ActionExpire:
			row.ActionKey, row.Who, row.SystemKey = "triage.history_expired", "", "triage.history_system"
			b := triageBadge(h.Status)
			row.Badge = &b
		}
		if h.Current && h.Action != triage.ActionExpire {
			switch {
			case h.Scope == triage.ScopeProject && acc.Can(tenant.PermFindingTriage, p.TeamID):
				row.WithdrawHref = base + "/projects/" + p.Slug + "/decisions/" + h.ID.String() + "/withdraw"
			case h.Scope == triage.ScopeOrg && acc.Can(tenant.PermTriageOrg, uuid.Nil):
				row.WithdrawHref = base + "/triage/decisions/" + h.ID.String() + "/withdraw"
			}
		}
		all = append(all, dated{h.CreatedAt, row})
	}
	for _, e := range events {
		row := historyRow{When: stampAt(e.At), SystemKey: "triage.history_analysis", ActionKey: "triage.history_" + e.Kind}
		if e.Resolution != "" {
			row.Args = map[string]any{"Reason": e.Resolution}
			row.ActionKey = "triage.history_resolved_" + string(e.Resolution)
		}
		all = append(all, dated{e.At, row})
	}
	// Tri stable du plus récent au plus ancien (insertion : listes courtes et bornées).
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].at.After(all[j-1].at); j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	out := make([]historyRow, len(all))
	for i, d := range all {
		out[i] = d.row
	}
	return out
}

func readTriageForm(r *http.Request) triageForm {
	return triageForm{
		Status: r.PostFormValue("status"), Justification: r.PostFormValue("justification"),
		Comment: r.PostFormValue("comment"), ExpiresOn: strings.TrimSpace(r.PostFormValue("expires_on")),
		Scope: r.PostFormValue("scope"), Vers: strings.TrimSpace(r.PostFormValue("vers")),
	}
}

// triageFinding enregistre une décision sur un constat. La portée « organisation » exige
// en plus le droit triage.org (403 sinon).
func (id *identity) triageFinding(w http.ResponseWriter, r *http.Request) {
	p, row, ok := id.findingFromPath(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	f := readTriageForm(r)
	in := triage.Input{ProjectID: p.ID, FindingID: row.ID, Scope: triage.Scope(f.Scope), Status: triage.Status(f.Status),
		Comment: f.Comment, Vers: f.Vers}
	if in.Scope == triage.ScopeOrg && !acc.Can(tenant.PermTriageOrg, uuid.Nil) {
		id.rd.Error(w, r, http.StatusForbidden)
		return
	}
	if in.Status == triage.StatusNotAffected {
		// Dans l'interface, la justification VEX est exigée (un import peut n'avoir
		// qu'une déclaration d'impact).
		if f.Justification == "" {
			id.renderFinding(w, r, http.StatusUnprocessableEntity, p, row, f, formError{Key: triage.KeyJustificationNeeded, Field: "justification"})
			return
		}
		in.Justification = triage.Justification(f.Justification)
	}
	if in.Status == triage.StatusRiskAccepted && f.ExpiresOn != "" {
		d, err := time.Parse(time.DateOnly, f.ExpiresOn)
		if err != nil {
			id.renderFinding(w, r, http.StatusUnprocessableEntity, p, row, f, formError{Key: triage.KeyExpiryInvalid, Field: "expires_on"})
			return
		}
		in.ExpiresOn = &d
	}
	if in.Scope != triage.ScopeOrg {
		in.Vers = ""
	}
	_, _, err := id.Triage.Decide(r.Context(), acc.Org, id.actor(r), in)
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(acc)+"/projects/"+p.Slug+"/findings/"+row.ID.String(), "triage_saved")
	case errors.Is(err, triage.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			id.renderFinding(w, r, http.StatusUnprocessableEntity, p, row, f, fe)
			return
		}
		id.serverError(w, r, err)
	}
}

// decisionFromPath lit la décision courante {decisionID} : du projet de la route, ou
// d'organisation (p nul).
func (id *identity) decisionFromPath(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) (triage.Decision, bool) {
	did, err := uuid.Parse(chi.URLParam(r, "decisionID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return triage.Decision{}, false
	}
	d, err := id.Triage.Current(r.Context(), access(r).Org, did, projectID)
	if errors.Is(err, triage.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return triage.Decision{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return triage.Decision{}, false
	}
	return d, true
}

func decisionArgs(d triage.Decision) map[string]any {
	component := d.PURL
	if component == "" {
		component = d.PURLBase
		if d.Vers != "" {
			component += " " + d.Vers
		}
	}
	return map[string]any{"ID": d.VulnID, "Component": component, "Status": d.Status}
}

// confirmWithdrawProjectDecision : retrait d'une décision du projet.
func (id *identity) confirmWithdrawProjectDecision(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	d, ok := id.decisionFromPath(w, r, p.ID)
	if !ok {
		return
	}
	acc := access(r)
	id.confirm(w, r, confirmation{nav: orgNav(acc, "projects"), heading: "confirm.triage_withdraw_heading",
		text: "confirm.triage_withdraw_project_text", submit: "confirm.triage_withdraw_submit", args: decisionArgs(d),
		cancel: orgBase(acc) + "/projects/" + p.Slug + "/findings"})
}

func (id *identity) withdrawProjectDecision(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	did, err := uuid.Parse(chi.URLParam(r, "decisionID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	acc := access(r)
	_, _, err = id.Triage.Withdraw(r.Context(), acc.Org, id.actor(r), did, p.ID)
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(acc)+"/projects/"+p.Slug+"/findings", "triage_withdrawn")
	case errors.Is(err, triage.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		id.serverError(w, r, err)
	}
}

// confirmWithdrawOrgDecision : retrait d'une décision d'organisation.
func (id *identity) confirmWithdrawOrgDecision(w http.ResponseWriter, r *http.Request) {
	d, ok := id.decisionFromPath(w, r, uuid.Nil)
	if !ok {
		return
	}
	acc := access(r)
	id.confirm(w, r, confirmation{nav: orgNav(acc, "triage"), heading: "confirm.triage_withdraw_heading",
		text: "confirm.triage_withdraw_org_text", submit: "confirm.triage_withdraw_submit", args: decisionArgs(d),
		cancel: orgBase(acc) + "/triage"})
}

func (id *identity) withdrawOrgDecision(w http.ResponseWriter, r *http.Request) {
	did, err := uuid.Parse(chi.URLParam(r, "decisionID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	acc := access(r)
	_, _, err = id.Triage.Withdraw(r.Context(), acc.Org, id.actor(r), did, uuid.Nil)
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(acc)+"/triage", "triage_withdrawn")
	case errors.Is(err, triage.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		id.serverError(w, r, err)
	}
}

// importResult est le compte rendu d'un import affiché après le POST.
type importResult struct {
	Decisions int
	Ignored   int
	Changed   int
	Source    string
}

type vexView struct {
	render.Page
	Base       string
	Project    projectRow
	Tabs       []projectTab
	Statements int
	Exports    []linkView
	CanImport  bool
	Action     string
	Source     string
	Error      formError
	Result     *importResult
	FlashKey   string
	MaxKiB     int
}

// vexPage est la page VEX d'un projet : exports OpenVEX et CycloneDX de ses décisions, et
// import d'un VEX d'éditeur pour le projet (analyste ou administrateur de l'équipe).
func (id *identity) vexPage(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	id.renderVEX(w, r, http.StatusOK, p, "", formError{}, nil)
}

func (id *identity) renderVEX(w http.ResponseWriter, r *http.Request, status int, p project.Project, source string, fe formError, res *importResult) {
	acc := access(r)
	stmts, err := id.Triage.Statements(r.Context(), acc.Org, p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc) + "/projects/" + p.Slug
	view := &vexView{
		Page: render.Page{TitleKey: "vex.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "vex"),
		Statements: len(stmts), CanImport: acc.Can(tenant.PermFindingTriage, p.TeamID), Action: base + "/vex/import",
		Source: source, Error: fe, Result: res, FlashKey: flashKey(r), MaxKiB: vex.MaxDocument >> 10,
	}
	for _, f := range vex.Formats() {
		view.Exports = append(view.Exports, linkView{Href: base + "/vex/export?format=" + string(f), Label: "vex.format_" + string(f)})
	}
	id.rd.Render(w, r, status, "projects/vex", view)
}

// vexExport télécharge les décisions d'un projet en OpenVEX ou CycloneDX.
func (id *identity) vexExport(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	f, err := vex.ParseFormat(r.URL.Query().Get("format"))
	if err != nil {
		id.rd.Error(w, r, http.StatusBadRequest)
		return
	}
	acc := access(r)
	data, err := id.exportVEX(r, acc, p, f)
	if errors.Is(err, vex.ErrNoStatement) {
		redirectDone(w, r, orgBase(acc)+"/projects/"+p.Slug+"/vex", "vex_empty")
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	writeVEX(w, p.Slug, f, data)
}

// exportVEX produit le VEX d'un projet : auteur l'organisation, outil lotor et sa
// version.
func (id *identity) exportVEX(r *http.Request, acc tenant.Access, p project.Project, f vex.Format) ([]byte, error) {
	return vex.Export(r.Context(), id.Triage, acc.Org, p.ID, f, vex.Meta{Author: acc.Name, Tooling: "lotor " + id.rd.Version()})
}

// writeVEX écrit un VEX en pièce jointe.
func writeVEX(w http.ResponseWriter, slug string, f vex.Format, data []byte) {
	name := slug + ".openvex.json"
	ctype := "application/json"
	if f == vex.FormatCycloneDX {
		name, ctype = slug+".vex.cdx.json", "application/vnd.cyclonedx+json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// readVEXUpload lit le fichier d'un formulaire d'import (déjà borné par uploadGate).
func readVEXUpload(r *http.Request) (vex.Document, string, error) {
	source := r.PostFormValue("source")
	file, _, err := r.FormFile("file")
	if err != nil {
		return vex.Document{}, source, vex.ErrInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, vex.MaxDocument+1))
	if err != nil {
		return vex.Document{}, source, vex.ErrInvalid
	}
	doc, err := vex.Decode(data)
	if err != nil {
		return vex.Document{}, source, err
	}
	if strings.TrimSpace(source) == "" {
		source = doc.Author
	}
	return doc, source, nil
}

// vexError traduit une erreur de lecture d'un VEX en erreur de formulaire.
func vexError(err error) (formError, bool) {
	switch {
	case errors.Is(err, vex.ErrTooLarge):
		return formError{Key: "validation.vex_too_large", Field: "file"}, true
	case errors.Is(err, vex.ErrTooManyStatements):
		return formError{Key: triage.KeyImportTooLarge, Field: "file"}, true
	case errors.Is(err, vex.ErrInvalid):
		return formError{Key: "validation.vex_invalid", Field: "file"}, true
	}
	return validationOf(err)
}

// vexImport importe un VEX d'éditeur pour le projet.
func (id *identity) vexImport(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	acc := access(r)
	doc, source, err := readVEXUpload(r)
	var res triage.ImportResult
	if err == nil {
		res, err = id.Triage.Import(r.Context(), acc.Org, id.actor(r), triage.ImportInput{Scope: triage.ScopeProject,
			ProjectID: p.ID, Source: source, Format: string(doc.Format), Statements: doc.Statements})
	}
	if err != nil {
		if fe, ok := vexError(err); ok {
			id.renderVEX(w, r, http.StatusUnprocessableEntity, p, r.PostFormValue("source"), fe, nil)
			return
		}
		id.serverError(w, r, err)
		return
	}
	clean, _ := triage.CleanSource(source)
	id.renderVEX(w, r, http.StatusOK, p, "", formError{}, &importResult{Decisions: res.Decisions,
		Ignored: res.Ignored + doc.Skipped, Changed: res.Changed, Source: clean})
}

type orgDecisionRow struct {
	VulnID        string
	VulnHref      string
	PURLBase      string
	Vers          string
	Badge         statusBadge
	Justification string
	Comment       string
	ExpiresOn     *stamp
	Who           string
	When          *stamp
	Findings      int
	WithdrawHref  string
}

type orgTriageView struct {
	render.Page
	Base      string
	Rows      []orgDecisionRow
	Truncated bool
	Action    string
	Source    string
	Error     formError
	Result    *importResult
	FlashKey  string
	MaxKiB    int
}

// orgTriage liste les décisions d'organisation courantes et importe un VEX d'éditeur
// pour toute l'organisation (administrateurs de l'organisation).
func (id *identity) orgTriage(w http.ResponseWriter, r *http.Request) {
	id.renderOrgTriage(w, r, http.StatusOK, "", formError{}, nil)
}

func (id *identity) renderOrgTriage(w http.ResponseWriter, r *http.Request, status int, source string, fe formError, res *importResult) {
	acc := access(r)
	ds, err := id.Triage.OrgDecisions(r.Context(), acc.Org)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &orgTriageView{
		Page: render.Page{TitleKey: "org_triage.title", Nav: orgNav(acc, "triage")},
		Base: base, Truncated: len(ds) >= triage.OrgDecisionsMax, Action: base + "/triage/import", Source: source,
		Error: fe, Result: res, FlashKey: flashKey(r), MaxKiB: vex.MaxDocument >> 10,
	}
	for _, d := range ds {
		view.Rows = append(view.Rows, orgDecisionRow{VulnID: d.VulnID, VulnHref: base + "/vulnerabilities/" + url.PathEscape(d.VulnID),
			PURLBase: d.PURLBase, Vers: d.Vers, Badge: triageBadge(d.Status), Justification: string(d.Justification),
			Comment: d.Comment, ExpiresOn: dateOf(d.ExpiresOn), Who: d.AuthorLabel, When: stampAt(d.CreatedAt),
			Findings: d.Findings, WithdrawHref: base + "/triage/decisions/" + d.ID.String() + "/withdraw"})
	}
	id.rd.Render(w, r, status, "org/triage", view)
}

// orgVEXImport importe un VEX d'éditeur pour toute l'organisation.
func (id *identity) orgVEXImport(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	doc, source, err := readVEXUpload(r)
	var res triage.ImportResult
	if err == nil {
		res, err = id.Triage.Import(r.Context(), acc.Org, id.actor(r), triage.ImportInput{Scope: triage.ScopeOrg,
			Source: source, Format: string(doc.Format), Statements: doc.Statements})
	}
	if err != nil {
		if fe, ok := vexError(err); ok {
			id.renderOrgTriage(w, r, http.StatusUnprocessableEntity, r.PostFormValue("source"), fe, nil)
			return
		}
		id.serverError(w, r, err)
		return
	}
	clean, _ := triage.CleanSource(source)
	id.renderOrgTriage(w, r, http.StatusOK, "", formError{}, &importResult{Decisions: res.Decisions,
		Ignored: res.Ignored + doc.Skipped, Changed: res.Changed, Source: clean})
}
