package web

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/tenant"
)

func orgBase(acc tenant.Access) string { return "/o/" + acc.Slug }

func orgNav(acc tenant.Access, current string) []render.NavItem {
	base := orgBase(acc)
	nav := []render.NavItem{
		{LabelKey: "nav.org_overview", Href: base, Current: current == "overview"},
		{LabelKey: "nav.members", Href: base + "/members", Current: current == "members"},
	}
	if acc.Role.AtLeast(tenant.RoleAdmin) {
		nav = append(nav,
			render.NavItem{LabelKey: "nav.org_settings", Href: base + "/settings", Current: current == "settings"},
			render.NavItem{LabelKey: "nav.audit", Href: base + "/audit", Current: current == "audit"})
	}
	return nav
}

func access(r *http.Request) tenant.Access {
	acc, _ := tenant.AccessFrom(r.Context())
	return acc
}

type orgOverviewView struct {
	render.Page
	Name     string
	RoleKey  string
	CanAdmin bool
	Base     string
}

func (id *identity) orgOverview(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	id.rd.Render(w, r, http.StatusOK, "org/overview", &orgOverviewView{
		Page: render.Page{TitleKey: "org_overview.title", TitleArgs: map[string]any{"Name": acc.Name}, Nav: orgNav(acc, "overview")},
		Name: acc.Name, RoleKey: "role." + string(acc.Role), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin), Base: orgBase(acc),
	})
}

type memberRow struct {
	org.Member
	RoleKey string
	Self    bool
}

type membersView struct {
	render.Page
	Base       string
	CanAdmin   bool
	Members    []memberRow
	Roles      []option
	NextCursor string
	FlashKey   string
	Error      formError
	Email      string
}

func roleOptions(selected tenant.Role) []option {
	var out []option
	for _, role := range tenant.Roles() {
		out = append(out, option{Value: string(role), LabelKey: "role." + string(role), Selected: role == selected})
	}
	return out
}

func (id *identity) membersPage(w http.ResponseWriter, r *http.Request, status int, fe formError, email string) {
	acc := access(r)
	page, err := id.Orgs.Members(r.Context(), acc.Org, r.URL.Query().Get("cursor"), org.DefaultPage)
	if err != nil {
		if e, ok := validationOf(err); ok {
			fe, status = e, http.StatusBadRequest
		} else {
			id.serverError(w, r, err)
			return
		}
	}
	v := viewerFrom(r)
	view := &membersView{
		Page: render.Page{TitleKey: "members.title", Nav: orgNav(acc, "members")},
		Base: orgBase(acc), CanAdmin: acc.Role.AtLeast(tenant.RoleAdmin), Roles: roleOptions(tenant.RoleViewer),
		NextCursor: page.NextCursor, FlashKey: flashKey(r), Error: fe, Email: email,
	}
	for _, m := range page.Items {
		view.Members = append(view.Members, memberRow{Member: m, RoleKey: "role." + string(m.Role), Self: m.UserID == v.user.ID})
	}
	id.rd.Render(w, r, status, "org/members", view)
}

func (id *identity) members(w http.ResponseWriter, r *http.Request) {
	id.membersPage(w, r, http.StatusOK, formError{}, "")
}

// memberResult traite le résultat d'une modification des membres.
func (id *identity) memberResult(w http.ResponseWriter, r *http.Request, err error, done, email string) {
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/members", done)
	case errors.Is(err, org.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			id.membersPage(w, r, http.StatusUnprocessableEntity, fe, email)
			return
		}
		id.serverError(w, r, err)
	}
}

func (id *identity) addMember(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	email := r.PostForm.Get("email")
	err := id.Orgs.AddMember(r.Context(), id.actor(r), access(r).Org, email, tenant.Role(r.PostForm.Get("role")))
	id.memberResult(w, r, err, "member_added", email)
}

func (id *identity) setMemberRole(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if !id.parseForm(w, r) {
		return
	}
	err := id.Orgs.SetMemberRole(r.Context(), id.actor(r), access(r).Org, userID, tenant.Role(r.PostForm.Get("role")))
	id.memberResult(w, r, err, "member_updated", "")
}

func (id *identity) removeMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err := id.Orgs.RemoveMember(r.Context(), id.actor(r), access(r).Org, userID)
	id.memberResult(w, r, err, "member_removed", "")
}

type orgSettingsView struct {
	render.Page
	Base      string
	Name      string
	Languages []option
	FlashKey  string
	Error     formError
}

func languageOptions(selected string) []option {
	var out []option
	for _, l := range []string{"fr", "en"} {
		out = append(out, option{Value: l, LabelKey: "language." + l, Selected: l == selected})
	}
	return out
}

func (id *identity) orgSettingsPage(w http.ResponseWriter, r *http.Request, status int, name, lang string, fe formError) {
	acc := access(r)
	id.rd.Render(w, r, status, "org/settings", &orgSettingsView{
		Page: render.Page{TitleKey: "org_settings.title", Nav: orgNav(acc, "settings")},
		Base: orgBase(acc), Name: name, Languages: languageOptions(lang), FlashKey: flashKey(r), Error: fe,
	})
}

func (id *identity) orgSettings(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	id.orgSettingsPage(w, r, http.StatusOK, acc.Name, acc.Language, formError{})
}

func (id *identity) saveOrgSettings(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	name, lang := r.PostForm.Get("name"), r.PostForm.Get("language")
	if err := id.Orgs.Update(r.Context(), id.actor(r), acc.Org, name, lang); err != nil {
		if fe, ok := validationOf(err); ok {
			id.orgSettingsPage(w, r, http.StatusUnprocessableEntity, name, lang, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, orgBase(acc)+"/settings", "org_saved")
}

type auditRow struct {
	audit.Entry
	ActionKey string
	Args      map[string]any
}

type auditView struct {
	render.Page
	Rows       []auditRow
	NextCursor string
	Error      formError
}

func auditRows(entries []audit.Entry) []auditRow {
	out := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		actor := e.ActorEmail
		args := map[string]any{"Actor": actor, "Target": e.TargetLabel}
		for k, v := range e.Details {
			args["D_"+k] = v
		}
		out = append(out, auditRow{Entry: e, ActionKey: e.Action.Key(), Args: args})
	}
	return out
}

func (id *identity) orgAudit(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	view := &auditView{Page: render.Page{TitleKey: "audit.title", Nav: orgNav(acc, "audit")}}
	status := http.StatusOK
	err := id.Pool.InOrg(r.Context(), acc.Org, func(tx *db.OrgTx) error {
		page, err := audit.ListOrg(r.Context(), tx, r.URL.Query().Get("cursor"), audit.DefaultPage)
		if err != nil {
			return err
		}
		view.Rows, view.NextCursor = auditRows(page.Items), page.NextCursor
		return nil
	}, db.ReadOnly())
	if err != nil {
		fe, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.Error, status = fe, http.StatusBadRequest
	}
	id.rd.Render(w, r, status, "audit/list", view)
}
