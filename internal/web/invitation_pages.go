package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/render"
)

// Invitations du compte (SEC-09, ADR 0034) : un compte ne devient membre d'une
// organisation qu'en acceptant l'invitation de l'un de ses administrateurs.

type pendingRow struct {
	ID      string
	OrgName string
	OrgSlug string
	RoleKey string
	Created *stamp
	Expires *stamp
}

type invitationsView struct {
	render.Page
	Rows     []pendingRow
	FlashKey string
	Error    formError
}

func (id *identity) invitationsPage(w http.ResponseWriter, r *http.Request, status int, fe formError) {
	v := viewerFrom(r)
	pending, err := id.Orgs.PendingInvitations(r.Context(), v.user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &invitationsView{Page: render.Page{TitleKey: "invitations.title", Nav: accountNav("invitations")},
		FlashKey: flashKey(r), Error: fe}
	for _, p := range pending {
		view.Rows = append(view.Rows, pendingRow{ID: p.ID.String(), OrgName: p.Name, OrgSlug: p.Slug,
			RoleKey: "role." + string(p.Role), Created: dateOf(&p.CreatedAt), Expires: dateOf(&p.ExpiresAt)})
	}
	id.rd.Render(w, r, status, "account/invitations", view)
}

func (id *identity) invitations(w http.ResponseWriter, r *http.Request) {
	id.invitationsPage(w, r, http.StatusOK, formError{})
}

// pendingFromPath retrouve, parmi les invitations du compte, celle du chemin ; 404 sinon.
func (id *identity) pendingFromPath(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	iid, err := uuid.Parse(chi.URLParam(r, "invitationID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return uuid.Nil, "", false
	}
	pending, err := id.Orgs.PendingInvitations(r.Context(), viewerFrom(r).user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return uuid.Nil, "", false
	}
	for _, p := range pending {
		if p.ID == iid {
			return iid, p.Name, true
		}
	}
	id.rd.Error(w, r, http.StatusNotFound)
	return uuid.Nil, "", false
}

// acceptInvitation fait du compte un membre de l'organisation (action réversible : il
// peut la quitter, un administrateur peut le retirer), puis l'y conduit.
func (id *identity) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	iid, _, ok := id.pendingFromPath(w, r)
	if !ok {
		return
	}
	if _, err := id.Orgs.AcceptInvitation(r.Context(), id.actor(r), viewerFrom(r).user.ID, iid); err != nil {
		if fe, ok := validationOf(err); ok {
			id.invitationsPage(w, r, http.StatusUnprocessableEntity, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, pathInvitations, "invitation_accepted")
}

// confirmDeclineInvitation : refus d'une invitation (elle disparaît ; une nouvelle
// invitation serait nécessaire).
func (id *identity) confirmDeclineInvitation(w http.ResponseWriter, r *http.Request) {
	_, name, ok := id.pendingFromPath(w, r)
	if !ok {
		return
	}
	id.confirm(w, r, confirmation{nav: accountNav("invitations"), heading: "confirm.decline_heading",
		text: "confirm.decline_text", submit: "confirm.decline_submit", args: map[string]any{"Org": name},
		cancel: pathInvitations})
}

func (id *identity) declineInvitation(w http.ResponseWriter, r *http.Request) {
	iid, _, ok := id.pendingFromPath(w, r)
	if !ok {
		return
	}
	if err := id.Orgs.DeclineInvitation(r.Context(), id.actor(r), viewerFrom(r).user.ID, iid); err != nil {
		if fe, ok := validationOf(err); ok {
			id.invitationsPage(w, r, http.StatusUnprocessableEntity, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, pathInvitations, "invitation_declined")
}
