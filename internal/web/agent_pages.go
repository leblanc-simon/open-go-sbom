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

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

func agentKindOptions(selected agent.Kind) []option {
	out := []option{{Value: "", LabelKey: "common.all", Selected: selected == ""}}
	for _, k := range agent.Kinds() {
		out = append(out, option{Value: string(k), LabelKey: "agent_type." + string(k), Selected: k == selected})
	}
	return out
}

func lifetimeOptions(selected int) []option {
	var out []option
	for _, d := range agent.TokenLifetimes {
		out = append(out, option{Value: strconv.Itoa(d), LabelKey: "agents.expiry_" + strconv.Itoa(d), Selected: d == selected})
	}
	return out
}

func enrollmentLifetimeOptions(selected int) []option {
	var out []option
	for _, h := range agent.EnrollmentLifetimes {
		out = append(out, option{Value: strconv.Itoa(h), LabelKey: "enrollment.expiry_" + strconv.Itoa(h), Selected: h == selected})
	}
	return out
}

type agentRow struct {
	agent.Agent
	Status   agentStatus
	LastSeen *stamp
}

func agentRowOf(a agent.Agent, now time.Time) agentRow {
	return agentRow{Agent: a, Status: statusOf(a.Activity(), now), LastSeen: stampOf(a.LastSeenAt)}
}

type enrollmentRow struct {
	agent.EnrollmentToken
	Labels  []string
	Usable  bool
	Expires *stamp
	Created *stamp
}

type agentsView struct {
	render.Page
	Base        string
	CanAdmin    bool
	Rows        []agentRow
	NextHref    template.URL
	Kinds       []option
	Disabled    bool
	Enrollments []enrollmentRow
	FlashKey    string
	Error       formError
}

func (id *identity) agents(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	q := r.URL.Query()
	f := agent.Filter{Disabled: q.Get("disabled") == "1"}
	for _, k := range agent.Kinds() {
		if q.Get("kind") == string(k) {
			f.Kind = k
		}
	}
	view := &agentsView{
		Page: render.Page{TitleKey: "agents.title", Nav: orgNav(acc, "agents")},
		Base: orgBase(acc), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin), Kinds: agentKindOptions(f.Kind),
		Disabled: f.Disabled, FlashKey: flashKey(r),
	}
	status := http.StatusOK
	page, err := id.Agents.List(r.Context(), acc.Org, f, q.Get("cursor"), agent.DefaultPage)
	if err != nil {
		fe, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.Error, status = fe, http.StatusBadRequest
	}
	now := id.Agents.Now()
	for _, a := range page.Items {
		view.Rows = append(view.Rows, agentRowOf(a, now))
	}
	if page.NextCursor != "" {
		next := url.Values{"cursor": {page.NextCursor}}
		for _, k := range []string{"kind", "disabled"} {
			if v := q.Get(k); v != "" {
				next.Set(k, v)
			}
		}
		// Requête construite ici par url.Values : sûre comme URL.
		view.NextHref = template.URL("?" + next.Encode())
	}
	if view.CanAdmin {
		tokens, err := id.Agents.Enrollments(r.Context(), acc.Org)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		for _, t := range tokens {
			view.Enrollments = append(view.Enrollments, enrollmentRow{EnrollmentToken: t, Labels: t.Labels.Pairs(),
				Usable: t.UsableAt(now), Expires: stampAt(t.ExpiresAt), Created: stampAt(t.CreatedAt)})
		}
	}
	id.rd.Render(w, r, status, "agents/list", view)
}

type agentNewView struct {
	render.Page
	Base      string
	Name      string
	TokenName string
	Lifetimes []option
	Error     formError
}

func (id *identity) agentNewPage(w http.ResponseWriter, r *http.Request, status int, name, tokenName string, days int, fe formError) {
	acc := access(r)
	id.rd.Render(w, r, status, "agents/new", &agentNewView{
		Page: render.Page{TitleKey: "agent_new.title", Nav: orgNav(acc, "agents")},
		Base: orgBase(acc), Name: name, TokenName: tokenName, Lifetimes: lifetimeOptions(days), Error: fe,
	})
}

func (id *identity) newAgent(w http.ResponseWriter, r *http.Request) {
	id.agentNewPage(w, r, http.StatusOK, "", "initial", agent.DefaultTokenLifetime, formError{})
}

// secretView montre une seule fois le secret d'un jeton qui vient d'être créé.
type secretView struct {
	render.Page
	Base       string
	Enrollment bool
	Name       string // agent ou jeton d'inscription
	AgentID    string
	TokenName  string
	Plaintext  string
	Expires    *stamp
	// Install : étapes d'installation de l'agent serveur (jeton d'inscription).
	Install []installStep
}

func (id *identity) showSecret(w http.ResponseWriter, r *http.Request, v *secretView) {
	acc := access(r)
	v.Base = orgBase(acc)
	v.Page = render.Page{TitleKey: "token_created.title", Nav: orgNav(acc, "agents")}
	id.rd.Render(w, r, http.StatusOK, "agents/secret", v)
}

func (id *identity) createAgent(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	name, tokenName := r.PostForm.Get("name"), r.PostForm.Get("token_name")
	days := atoiDefault(r.PostForm.Get("expires_in"), -1)
	a, issued, err := id.Agents.CreateRepoAgent(r.Context(), id.actor(r), access(r).Org, name, tokenName, days)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.agentNewPage(w, r, http.StatusUnprocessableEntity, name, tokenName, days, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	var expires *time.Time
	if days > 0 {
		t := id.Agents.Now().Add(time.Duration(days) * 24 * time.Hour)
		expires = &t
	}
	id.showSecret(w, r, &secretView{Name: a.Name, AgentID: a.ID.String(), TokenName: tokenName,
		Plaintext: issued.Plaintext, Expires: stampOf(expires)})
}

type tokenRow struct {
	agent.Token
	Active   bool
	Created  *stamp
	LastUsed *stamp
	Expires  *stamp
	Revoked  *stamp
}

type agentView struct {
	render.Page
	Base      string
	CanAdmin  bool
	Agent     agentRow
	Tokens    []tokenRow
	Lifetimes []option
	TokenName string
	FlashKey  string
	Error     formError
	// Host : contexte de l'hôte d'un agent serveur.
	Host *hostAgentView
}

func (id *identity) agentFromPath(w http.ResponseWriter, r *http.Request) (agent.Agent, bool) {
	aid, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return agent.Agent{}, false
	}
	a, err := id.Agents.Get(r.Context(), access(r).Org, aid)
	if errors.Is(err, agent.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return agent.Agent{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return agent.Agent{}, false
	}
	return a, true
}

func (id *identity) agentPage(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok {
		return
	}
	id.renderAgent(w, r, http.StatusOK, a, "", agent.DefaultTokenLifetime, formError{})
}

func (id *identity) renderAgent(w http.ResponseWriter, r *http.Request, status int, a agent.Agent, tokenName string, days int, fe formError) {
	acc := access(r)
	now := id.Agents.Now()
	view := &agentView{
		Page: render.Page{TitleKey: "agent.title", TitleArgs: map[string]any{"Name": a.Name}, Nav: orgNav(acc, "agents")},
		Base: orgBase(acc), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin), Agent: agentRowOf(a, now),
		Lifetimes: lifetimeOptions(days), TokenName: tokenName, FlashKey: flashKey(r), Error: fe,
	}
	if a.Kind == agent.KindHost {
		view.Host = newHostAgentView(a, false)
	}
	for _, t := range a.Tokens {
		view.Tokens = append(view.Tokens, tokenRow{Token: t, Active: t.ActiveAt(now) && a.DisabledAt == nil,
			Created: dateOf(&t.CreatedAt), LastUsed: stampOf(t.LastUsedAt), Expires: dateOf(t.ExpiresAt), Revoked: dateOf(t.RevokedAt)})
	}
	id.rd.Render(w, r, status, "agents/show", view)
}

// agentResult traite le résultat d'une action sur un agent.
func (id *identity) agentResult(w http.ResponseWriter, r *http.Request, a agent.Agent, err error, done string) {
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/agents/"+a.ID.String(), done)
	case errors.Is(err, agent.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			id.renderAgent(w, r, http.StatusUnprocessableEntity, a, "", agent.DefaultTokenLifetime, fe)
			return
		}
		id.serverError(w, r, err)
	}
}

func (id *identity) createAgentToken(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	name := r.PostForm.Get("name")
	days := atoiDefault(r.PostForm.Get("expires_in"), -1)
	t, issued, err := id.Agents.CreateToken(r.Context(), id.actor(r), access(r).Org, a.ID, name, days)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.renderAgent(w, r, http.StatusUnprocessableEntity, a, name, days, fe)
			return
		}
		id.agentResult(w, r, a, err, "")
		return
	}
	id.showSecret(w, r, &secretView{Name: a.Name, AgentID: a.ID.String(), TokenName: t.Name,
		Plaintext: issued.Plaintext, Expires: stampOf(t.ExpiresAt)})
}

func (id *identity) revokeAgentToken(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok {
		return
	}
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err = id.Agents.RevokeToken(r.Context(), id.actor(r), access(r).Org, a.ID, tid)
	id.agentResult(w, r, a, err, "token_revoked")
}

func (id *identity) disableAgent(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok {
		return
	}
	err := id.Agents.Disable(r.Context(), id.actor(r), access(r).Org, a.ID)
	id.agentResult(w, r, a, err, "agent_disabled")
}

type enrollmentNewView struct {
	render.Page
	Base      string
	Name      string
	Lifetimes []option
	MaxUses   int
	Labels    string
	Projects  []option
	Error     formError
}

func (id *identity) enrollmentNewPage(w http.ResponseWriter, r *http.Request, status int, in agent.EnrollmentInput, labels string, fe formError) {
	acc := access(r)
	hosts, err := id.Projects.List(r.Context(), acc.Org, project.Filter{Kind: project.KindHost}, "", project.MaxPage)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &enrollmentNewView{
		Page: render.Page{TitleKey: "enrollment_new.title", Nav: orgNav(acc, "agents")},
		Base: orgBase(acc), Name: in.Name, Lifetimes: enrollmentLifetimeOptions(in.LifetimeHours), MaxUses: in.MaxUses,
		Labels: labels, Error: fe,
		Projects: []option{{Value: "", LabelKey: "enrollment.project_create", Selected: in.ProjectSlug == ""}},
	}
	for _, p := range hosts.Items {
		if p.Agent == nil {
			view.Projects = append(view.Projects, option{Value: p.Slug, Label: p.Name, Selected: p.Slug == in.ProjectSlug})
		}
	}
	id.rd.Render(w, r, status, "agents/enrollment_new", view)
}

func (id *identity) newEnrollment(w http.ResponseWriter, r *http.Request) {
	id.enrollmentNewPage(w, r, http.StatusOK, agent.EnrollmentInput{
		LifetimeHours: agent.DefaultEnrollmentLifetime, MaxUses: 1, ProjectSlug: r.URL.Query().Get("project"),
	}, "", formError{})
}

func (id *identity) createEnrollment(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	f := r.PostForm
	in := agent.EnrollmentInput{Name: f.Get("name"), LifetimeHours: atoiDefault(f.Get("expires_in"), -1),
		MaxUses: atoiDefault(f.Get("max_uses"), 0), ProjectSlug: f.Get("project")}
	labels, err := project.ParseLabels(f.Get("labels"))
	var t agent.EnrollmentToken
	var issued agent.IssuedToken
	if err == nil {
		in.Labels = labels
		t, issued, err = id.Agents.CreateEnrollment(r.Context(), id.actor(r), access(r).Org, in)
	}
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.enrollmentNewPage(w, r, http.StatusUnprocessableEntity, in, f.Get("labels"), fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	id.showSecret(w, r, &secretView{Enrollment: true, Name: t.Name, Plaintext: issued.Plaintext, Expires: stampAt(t.ExpiresAt),
		Install: hostAgentInstall(serverURL(r), issued.Plaintext)})
}

func (id *identity) revokeEnrollment(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err = id.Agents.RevokeEnrollment(r.Context(), id.actor(r), access(r).Org, tid)
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/agents", "enrollment_revoked")
	case errors.Is(err, agent.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if _, ok := validationOf(err); ok {
			redirectDone(w, r, orgBase(access(r))+"/agents", "enrollment_revoked")
			return
		}
		id.serverError(w, r, err)
	}
}
