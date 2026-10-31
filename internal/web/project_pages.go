package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/dashboard"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// stamp est un instant prêt à afficher : attribut datetime et texte en UTC.
type stamp struct {
	ISO     string
	Display string
}

func stampOf(t *time.Time) *stamp {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &stamp{ISO: u.Format(time.RFC3339), Display: u.Format("2006-01-02 15:04")}
}

func stampAt(t time.Time) *stamp { return stampOf(&t) }

// dateOf est un jour, pour les colonnes étroites (création et expiration d'un jeton).
func dateOf(t *time.Time) *stamp {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &stamp{ISO: u.Format(time.RFC3339), Display: u.Format("2006-01-02")}
}

// agentStatus est l'état d'un agent prêt à afficher.
type agentStatus struct {
	State agent.State
	Days  int // jours de silence (agent muet)
}

func statusOf(a agent.Activity, now time.Time) agentStatus {
	s := agentStatus{State: a.State(now)}
	if s.State == agent.StateSilent {
		s.Days = int(now.Sub(a.Since()) / (24 * time.Hour))
	}
	return s
}

// activityOf est l'activité de l'agent d'un projet.
func activityOf(a *project.AgentRef) agent.Activity {
	return agent.Activity{Kind: agent.Kind(a.Kind), LastSeen: a.LastSeenAt, LastInventory: a.LastInventoryAt,
		Created: a.CreatedAt, Disabled: a.Disabled}
}

func projectKindOptions(selected project.Kind, withAll bool) []option {
	var out []option
	if withAll {
		out = append(out, option{Value: "", LabelKey: "common.all", Selected: selected == ""})
	}
	for _, k := range project.Kinds() {
		out = append(out, option{Value: string(k), LabelKey: "project_type." + string(k), Selected: k == selected})
	}
	return out
}

type projectRow struct {
	project.Project
	Labels      []string
	AgentStatus *agentStatus
	LastSeen    *stamp
	// LastSnapshot est la date du dernier instantané (liste des projets).
	LastSnapshot *stamp
}

func (id *identity) projectRow(p project.Project, now time.Time) projectRow {
	row := projectRow{Project: p, Labels: p.Labels.Pairs()}
	if p.Agent != nil {
		st := statusOf(activityOf(p.Agent), now)
		row.AgentStatus, row.LastSeen = &st, stampOf(p.Agent.LastSeenAt)
	}
	return row
}

type projectsView struct {
	render.Page
	Base       string
	CanAdmin   bool
	Rows       []projectRow
	NextCursor string
	NextHref   template.URL
	Query      string
	Label      string
	Archived   bool
	Kinds      []option
	FlashKey   string
	Error      formError
}

func (id *identity) projects(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	q := r.URL.Query()
	f := project.Filter{Query: q.Get("q"), Label: q.Get("label"), Archived: q.Get("archived") == "1"}
	if k := q.Get("kind"); k != "" {
		if kind, err := project.ParseKind(k); err == nil {
			f.Kind = kind
		}
	}
	view := &projectsView{
		Page: render.Page{TitleKey: "projects.title", Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin),
		Query: f.Query, Label: f.Label, Archived: f.Archived, Kinds: projectKindOptions(f.Kind, true),
		FlashKey: flashKey(r),
	}
	status := http.StatusOK
	page, err := id.Projects.List(r.Context(), acc.Org, f, q.Get("cursor"), project.DefaultPage)
	if err != nil {
		fe, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.Error, status = fe, http.StatusBadRequest
	}
	last, err := id.lastSnapshots(r, acc.Org, page.Items)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	now := id.Agents.Now()
	for _, p := range page.Items {
		row := id.projectRow(p, now)
		if t, ok := last[p.ID]; ok {
			row.LastSnapshot = stampAt(t)
		}
		view.Rows = append(view.Rows, row)
	}
	if page.NextCursor != "" {
		next := url.Values{}
		for _, k := range []string{"q", "kind", "label", "archived"} {
			if v := q.Get(k); v != "" {
				next.Set(k, v)
			}
		}
		next.Set("cursor", page.NextCursor)
		// Requête construite ici par url.Values : sûre comme URL.
		view.NextHref = template.URL("?" + next.Encode())
	}
	id.rd.Render(w, r, status, "projects/list", view)
}

// projectForm est la saisie d'un projet telle qu'affichée par le formulaire.
type projectForm struct {
	Kind        project.Kind
	Slug        string
	Name        string
	Description string
	Labels      string
	ForgeURL    string
	Branches    string
	Tags        string
	HostRef     string
}

func formOf(p project.Project) projectForm {
	return projectForm{Kind: p.Kind, Slug: p.Slug, Name: p.Name, Description: p.Description, Labels: p.Labels.String(),
		ForgeURL: p.ForgeURL, Branches: joinLines(p.RefNames(project.RefBranch)), Tags: joinLines(p.RefNames(project.RefTag)),
		HostRef: p.HostRef()}
}

func joinLines(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += "\n"
		}
		out += v
	}
	return out
}

func readProjectForm(r *http.Request) projectForm {
	f := r.PostForm
	return projectForm{Kind: project.Kind(f.Get("kind")), Slug: f.Get("slug"), Name: f.Get("name"),
		Description: f.Get("description"), Labels: f.Get("labels"), ForgeURL: f.Get("forge_url"),
		Branches: f.Get("branches"), Tags: f.Get("tags"), HostRef: f.Get("host_ref")}
}

// input lit la saisie ; une erreur de lecture (étiquettes, références) est une erreur de
// saisie.
func (f projectForm) input() (project.Input, error) {
	labels, err := project.ParseLabels(f.Labels)
	if err != nil {
		return project.Input{}, err
	}
	in := project.Input{Kind: f.Kind, Slug: f.Slug, Name: f.Name, Description: f.Description, Labels: labels,
		ForgeURL: f.ForgeURL, HostRef: f.HostRef}
	if f.Kind == project.KindRepo {
		if in.Branches, err = project.ParseRefNames(f.Branches, "branches"); err != nil {
			return project.Input{}, err
		}
		if in.Tags, err = project.ParseRefNames(f.Tags, "tags"); err != nil {
			return project.Input{}, err
		}
	}
	return in, nil
}

type projectFormView struct {
	render.Page
	Base   string
	Form   projectForm
	Kinds  []option
	Error  formError
	IsNew  bool
	Action string
	Slug   string
}

func (id *identity) projectFormPage(w http.ResponseWriter, r *http.Request, status int, f projectForm, fe formError) {
	acc := access(r)
	if f.Kind == "" {
		f.Kind = project.KindRepo
	}
	id.rd.Render(w, r, status, "projects/new", &projectFormView{
		Page: render.Page{TitleKey: "project_new.title", Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Form: f, Kinds: projectKindOptions(f.Kind, false), Error: fe, IsNew: true,
		Action: orgBase(acc) + "/projects",
	})
}

func (id *identity) newProject(w http.ResponseWriter, r *http.Request) {
	kind := project.Kind(r.URL.Query().Get("kind"))
	if _, err := project.ParseKind(string(kind)); err != nil {
		kind = project.KindRepo
	}
	id.projectFormPage(w, r, http.StatusOK, projectForm{Kind: kind}, formError{})
}

func (id *identity) createProject(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	f := readProjectForm(r)
	in, err := f.input()
	if err == nil {
		var p project.Project
		if p, err = id.Projects.Create(r.Context(), id.actor(r), acc.Org, in); err == nil {
			redirectDone(w, r, orgBase(acc)+"/projects/"+p.Slug, "project_created")
			return
		}
	}
	if fe, ok := validationOf(err); ok {
		id.projectFormPage(w, r, http.StatusUnprocessableEntity, f, fe)
		return
	}
	id.serverError(w, r, err)
}

// loadProject lit le projet du chemin ; 404 s'il n'existe pas dans l'organisation.
func (id *identity) loadProject(w http.ResponseWriter, r *http.Request) (project.Project, bool) {
	p, err := id.Projects.Get(r.Context(), access(r).Org, chi.URLParam(r, "project"))
	if errors.Is(err, project.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return project.Project{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return project.Project{}, false
	}
	return p, true
}

// projectTab est un onglet de la fiche projet.
type projectTab struct {
	LabelKey string
	Href     string
	Current  bool
}

func projectTabs(acc tenant.Access, p project.Project, current string) []projectTab {
	base := orgBase(acc) + "/projects/" + p.Slug
	tabs := []projectTab{
		{LabelKey: "project.tab_overview", Href: base, Current: current == "overview"},
		{LabelKey: "project.tab_findings", Href: base + "/findings", Current: current == "findings"},
		{LabelKey: "project.tab_snapshots", Href: base + "/snapshots", Current: current == "snapshots"},
	}
	if acc.Role.AtLeast(tenant.RoleAdmin) {
		tabs = append(tabs, projectTab{LabelKey: "project.tab_settings", Href: base + "/settings", Current: current == "settings"})
	}
	return tabs
}

type projectView struct {
	render.Page
	Base       string
	CanAdmin   bool
	Project    projectRow
	Tabs       []projectTab
	Branches   []string
	Tags       []string
	HostRef    string
	Created    *stamp
	RepoAgents []option
	FlashKey   string
	Error      formError
	// Period et Summary : indicateurs du projet en tête de sa fiche (T10).
	Period  periodForm
	Summary summaryView
	// Host : agent serveur du projet (contexte de l'hôte, demande de scan).
	Host *hostAgentView
}

// hostAgentView est ce que la fiche d'un hôte montre de son agent serveur.
type hostAgentView struct {
	Context       *agent.HostContext
	ContextAt     *stamp
	ScanDuration  string
	ScanRequested *stamp
	LastInventory *stamp
	// CanScan : le visiteur peut demander un scan (analyste ou administrateur, agent actif).
	CanScan bool
}

func newHostAgentView(a agent.Agent, canScan bool) *hostAgentView {
	v := &hostAgentView{Context: a.Host, ContextAt: stampOf(a.HostAt), ScanRequested: stampOf(a.ScanRequestedAt),
		LastInventory: stampOf(a.LastInventoryAt), CanScan: canScan && a.DisabledAt == nil}
	if a.Host != nil && a.Host.ScanDuration > 0 {
		v.ScanDuration = a.Host.ScanDurationValue().Round(time.Second).String()
	}
	return v
}

func (id *identity) projectPage(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	id.renderProject(w, r, http.StatusOK, p, formError{})
}

func (id *identity) renderProject(w http.ResponseWriter, r *http.Request, status int, p project.Project, fe formError) {
	acc := access(r)
	view := &projectView{
		Page: render.Page{TitleKey: "project.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin), Project: id.projectRow(p, id.Agents.Now()),
		Tabs: projectTabs(acc, p, "overview"), Branches: p.RefNames(project.RefBranch), Tags: p.RefNames(project.RefTag),
		HostRef: p.HostRef(), Created: stampAt(p.CreatedAt), FlashKey: flashKey(r), Error: fe,
	}
	period := dashboard.ParsePeriod(r.URL.Query().Get("period"))
	summary, err := id.Dashboard.Project(r.Context(), acc.Org, p.ID, period)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view.Period, view.Summary = periodFormOf(orgBase(acc)+"/projects/"+p.Slug, period), summaryOf("project", summary)
	if p.Kind == project.KindHost && p.Agent != nil {
		a, err := id.Agents.Get(r.Context(), acc.Org, p.Agent.ID)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		view.Host = newHostAgentView(a, acc.Role.AtLeast(tenant.RoleAnalyst) && p.ArchivedAt == nil)
	}
	if view.CanAdmin && p.Kind == project.KindRepo && p.ArchivedAt == nil {
		agents, err := id.Agents.RepoAgents(r.Context(), acc.Org)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		view.RepoAgents = append(view.RepoAgents, option{Value: "", LabelKey: "project.no_agent", Selected: p.Agent == nil})
		for _, a := range agents {
			view.RepoAgents = append(view.RepoAgents, option{Value: a.ID.String(), Label: a.Name, Selected: p.Agent != nil && p.Agent.ID == a.ID})
		}
	}
	id.rd.Render(w, r, status, "projects/show", view)
}

func (id *identity) projectSettingsPage(w http.ResponseWriter, r *http.Request, status int, p project.Project, f projectForm, fe formError) {
	acc := access(r)
	id.rd.Render(w, r, status, "projects/settings", &projectSettingsView{
		projectFormView: projectFormView{
			Page: render.Page{TitleKey: "project_settings.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
			Base: orgBase(acc), Form: f, Error: fe, Action: orgBase(acc) + "/projects/" + p.Slug + "/settings", Slug: p.Slug,
		},
		Project: p, Tabs: projectTabs(acc, p, "settings"), FlashKey: flashKey(r),
	})
}

type projectSettingsView struct {
	projectFormView
	Project  project.Project
	Tabs     []projectTab
	FlashKey string
}

func (id *identity) projectSettings(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	id.projectSettingsPage(w, r, http.StatusOK, p, formOf(p), formError{})
}

func (id *identity) saveProject(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	f := readProjectForm(r)
	f.Kind, f.Slug = p.Kind, p.Slug
	in, err := f.input()
	if err == nil {
		err = id.Projects.Update(r.Context(), id.actor(r), access(r).Org, p.Slug, in)
	}
	id.projectResult(w, r, err, p, "project_saved", func(fe formError) {
		id.projectSettingsPage(w, r, http.StatusUnprocessableEntity, p, f, fe)
	})
}

// projectResult traite le résultat d'une modification de projet.
func (id *identity) projectResult(w http.ResponseWriter, r *http.Request, err error, p project.Project, done string, invalid func(formError)) {
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/projects/"+p.Slug, done)
	case errors.Is(err, project.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			invalid(fe)
			return
		}
		id.serverError(w, r, err)
	}
}

func (id *identity) setProjectArchived(archived bool, done string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := id.loadProject(w, r)
		if !ok {
			return
		}
		err := id.Projects.SetArchived(r.Context(), id.actor(r), access(r).Org, p.Slug, archived)
		id.projectResult(w, r, err, p, done, func(fe formError) {
			id.renderProject(w, r, http.StatusUnprocessableEntity, p, fe)
		})
	}
}

// requestScan demande un scan à l'agent serveur du projet, remis à son prochain signal de
// vie.
func (id *identity) requestScan(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	_, err := id.Agents.RequestScan(r.Context(), id.actor(r), access(r).Org, p.Slug)
	if errors.Is(err, agent.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	id.projectResult(w, r, err, p, "scan_requested", func(fe formError) {
		id.renderProject(w, r, http.StatusUnprocessableEntity, p, fe)
	})
}

func (id *identity) assignAgent(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	var agentID *uuid.UUID
	if v := r.PostForm.Get("agent"); v != "" {
		parsed, err := uuid.Parse(v)
		if err != nil {
			id.renderProject(w, r, http.StatusUnprocessableEntity, p, formError{Key: project.KeyAgentInvalid, Field: "agent"})
			return
		}
		agentID = &parsed
	}
	err := id.Projects.AssignAgent(r.Context(), id.actor(r), access(r).Org, p.Slug, agentID)
	id.projectResult(w, r, err, p, "project_agent_saved", func(fe formError) {
		id.renderProject(w, r, http.StatusUnprocessableEntity, p, fe)
	})
}

// atoiDefault lit un entier de formulaire, def s'il est absent ou illisible.
func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
