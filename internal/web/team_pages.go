package web

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

// teamOptions renvoie les équipes où le compte a la permission perm, pour une liste de
// choix ; orgLabelKey, s'il n'est pas vide et que le compte a la permission sans équipe
// (administrateur d'organisation), ajoute en tête le choix « sans équipe » (valeur vide).
func (id *identity) teamOptions(w http.ResponseWriter, r *http.Request, perm tenant.Permission, selected, orgLabelKey string) ([]option, bool) {
	acc := access(r)
	teams, err := id.Orgs.Teams(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		id.serverError(w, r, err)
		return nil, false
	}
	var out []option
	if orgLabelKey != "" && acc.Can(perm, uuid.Nil) {
		out = append(out, option{Value: "", LabelKey: orgLabelKey, Selected: selected == ""})
	}
	for _, t := range teams {
		if acc.Can(perm, t.ID) {
			out = append(out, option{Value: t.ID.String(), Label: t.Name, Selected: t.ID.String() == selected})
		}
	}
	return out, true
}

// chosenTeam lit l'équipe choisie dans un formulaire et vérifie que le compte y a la
// permission perm. Une valeur vide désigne « sans équipe » si allowNone (administrateur
// d'organisation seulement). Tout autre choix est une erreur de saisie de clé key.
func chosenTeam(acc tenant.Access, perm tenant.Permission, value string, allowNone bool, key string) (*uuid.UUID, error) {
	refuse := &account.ValidationError{Field: "team", Key: key}
	if value == "" {
		if allowNone && acc.Can(perm, uuid.Nil) {
			return nil, nil
		}
		return nil, refuse
	}
	team, err := uuid.Parse(value)
	if err != nil || !acc.Can(perm, team) {
		return nil, refuse
	}
	return &team, nil
}

func teamRoleOptions(selected tenant.TeamRole) []option {
	var out []option
	for _, role := range tenant.TeamRoles() {
		out = append(out, option{Value: string(role), LabelKey: "team_role." + string(role), Selected: role == selected})
	}
	return out
}

type teamRow struct {
	org.Team
	Href    string
	RoleKey string // rôle du visiteur dans l'équipe, vide s'il n'en est pas membre
}

type teamsView struct {
	render.Page
	Base      string
	CanCreate bool
	Rows      []teamRow
	Name      string
	FlashKey  string
	Error     formError
}

func (id *identity) teamsPage(w http.ResponseWriter, r *http.Request, status int, name string, fe formError) {
	acc := access(r)
	teams, err := id.Orgs.Teams(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &teamsView{
		Page: render.Page{TitleKey: "teams.title", Nav: orgNav(acc, "teams")},
		Base: orgBase(acc), CanCreate: acc.Can(tenant.PermTeamsManage, uuid.Nil), Name: name, FlashKey: flashKey(r), Error: fe,
	}
	for _, t := range teams {
		row := teamRow{Team: t, Href: orgBase(acc) + "/teams/" + t.ID.String()}
		if role := acc.TeamRole(t.ID); role != tenant.TeamNone {
			row.RoleKey = "team_role." + string(role)
		}
		view.Rows = append(view.Rows, row)
	}
	id.rd.Render(w, r, status, "org/teams", view)
}

func (id *identity) teams(w http.ResponseWriter, r *http.Request) {
	id.teamsPage(w, r, http.StatusOK, "", formError{})
}

func (id *identity) createTeam(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	name := r.PostForm.Get("name")
	t, err := id.Orgs.CreateTeam(r.Context(), id.actor(r), acc.Org, name)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.teamsPage(w, r, http.StatusUnprocessableEntity, name, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, orgBase(acc)+"/teams/"+t.ID.String(), "team_created")
}

type teamMemberRow struct {
	org.TeamMember
	RoleKey string
	Self    bool
}

type teamView struct {
	render.Page
	Base        string
	Team        org.Team
	Href        string
	ProjectsURL string
	CanMembers  bool // ajouter, retirer, changer un rôle d'équipe
	CanManage   bool // renommer, supprimer
	Members     []teamMemberRow
	Roles       []option
	Email       string
	Name        string
	FlashKey    string
	Error       formError
}

// teamFromPath lit l'équipe du chemin, visible (la garde de la route l'a déjà vérifié).
func (id *identity) teamFromPath(w http.ResponseWriter, r *http.Request) (org.Team, bool) {
	acc := access(r)
	tid, err := uuid.Parse(chi.URLParam(r, "teamID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return org.Team{}, false
	}
	t, err := id.Orgs.Team(r.Context(), acc.Org, acc.Visibility(), tid)
	if errors.Is(err, org.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return org.Team{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return org.Team{}, false
	}
	return t, true
}

func (id *identity) renderTeam(w http.ResponseWriter, r *http.Request, status int, t org.Team, email, name string, fe formError) {
	acc := access(r)
	members, err := id.Orgs.TeamMembers(r.Context(), acc.Org, t.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	if name == "" {
		name = t.Name
	}
	href := orgBase(acc) + "/teams/" + t.ID.String()
	view := &teamView{
		Page: render.Page{TitleKey: "team.title", TitleArgs: map[string]any{"Name": t.Name}, Nav: orgNav(acc, "teams")},
		Base: orgBase(acc), Team: t, Href: href, ProjectsURL: orgBase(acc) + "/projects?team=" + t.ID.String(),
		CanMembers: acc.Can(tenant.PermTeamMembers, t.ID), CanManage: acc.Can(tenant.PermTeamsManage, t.ID),
		Roles: teamRoleOptions(tenant.TeamReader), Email: email, Name: name, FlashKey: flashKey(r), Error: fe,
	}
	self := viewerFrom(r).user.ID
	for _, m := range members {
		view.Members = append(view.Members, teamMemberRow{TeamMember: m, RoleKey: "team_role." + string(m.Role), Self: m.UserID == self})
	}
	id.rd.Render(w, r, status, "org/team", view)
}

func (id *identity) teamPage(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	id.renderTeam(w, r, http.StatusOK, t, "", "", formError{})
}

// teamResult traite le résultat d'une modification d'équipe.
func (id *identity) teamResult(w http.ResponseWriter, r *http.Request, t org.Team, err error, done, email, name string) {
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/teams/"+t.ID.String(), done)
	case errors.Is(err, org.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			id.renderTeam(w, r, http.StatusUnprocessableEntity, t, email, name, fe)
			return
		}
		id.serverError(w, r, err)
	}
}

func (id *identity) renameTeam(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	name := r.PostForm.Get("name")
	err := id.Orgs.RenameTeam(r.Context(), id.actor(r), access(r).Org, t.ID, name)
	id.teamResult(w, r, t, err, "team_renamed", "", name)
}

// confirmDeleteTeam : suppression d'une équipe (refusée tant qu'elle a des projets).
func (id *identity) confirmDeleteTeam(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	id.confirm(w, r, confirmation{nav: orgNav(acc, "teams"), heading: "confirm.team_heading", text: "confirm.team_text",
		submit: "confirm.team_submit", args: map[string]any{"Name": t.Name}, cancel: orgBase(acc) + "/teams/" + t.ID.String()})
}

func (id *identity) deleteTeam(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	err := id.Orgs.DeleteTeam(r.Context(), id.actor(r), acc.Org, t.ID)
	if err == nil {
		redirectDone(w, r, orgBase(acc)+"/teams", "team_deleted")
		return
	}
	id.teamResult(w, r, t, err, "", "", "")
}

func (id *identity) addTeamMember(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	email := r.PostForm.Get("email")
	err := id.Orgs.AddTeamMember(r.Context(), id.actor(r), access(r).Org, t.ID, email, tenant.TeamRole(r.PostForm.Get("role")))
	id.teamResult(w, r, t, err, "team_member_added", email, "")
}

func (id *identity) setTeamMemberRole(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if !id.parseForm(w, r) {
		return
	}
	err := id.Orgs.SetTeamMemberRole(r.Context(), id.actor(r), access(r).Org, t.ID, userID, tenant.TeamRole(r.PostForm.Get("role")))
	id.teamResult(w, r, t, err, "team_member_updated", "", "")
}

// confirmRemoveTeamMember : retrait d'un membre d'une équipe (il perd la vue de ses
// projets, mais reste membre de l'organisation).
func (id *identity) confirmRemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	acc := access(r)
	m, err := id.Orgs.TeamMember(r.Context(), acc.Org, t.ID, userID)
	if errors.Is(err, org.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.confirm(w, r, confirmation{nav: orgNav(acc, "teams"), heading: "confirm.team_member_heading",
		text: "confirm.team_member_text", submit: "confirm.team_member_submit",
		args: map[string]any{"Email": m.Email, "Team": t.Name}, cancel: orgBase(acc) + "/teams/" + t.ID.String()})
}

func (id *identity) removeTeamMember(w http.ResponseWriter, r *http.Request) {
	t, ok := id.teamFromPath(w, r)
	if !ok {
		return
	}
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err := id.Orgs.RemoveTeamMember(r.Context(), id.actor(r), access(r).Org, t.ID, userID)
	id.teamResult(w, r, t, err, "team_member_removed", "", "")
}

// moveProject rattache le projet du chemin à une autre équipe, où le compte doit aussi
// avoir le droit de rattachement.
func (id *identity) moveProject(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	team, err := chosenTeam(acc, tenant.PermProjectMove, r.PostForm.Get("team"), false, "validation.project_team_invalid")
	if err == nil {
		err = id.Projects.SetTeam(r.Context(), id.actor(r), acc.Org, p.Slug, *team)
	}
	id.projectResult(w, r, err, p, "project_team_changed", func(fe formError) {
		id.projectSettingsPage(w, r, http.StatusUnprocessableEntity, p, formOf(p), fe)
	})
}
