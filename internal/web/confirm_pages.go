package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/render"
)

// Confirmation des actions irréversibles (RGAA 11.12, WCAG 3.3.4) : révoquer un jeton,
// désactiver un agent, retirer un membre, réinitialiser un mot de passe ou un TOTP,
// abandonner un traitement. L'écran qui propose l'action n'a qu'un lien vers l'URL de
// l'action ; un GET sur cette URL affiche la page de confirmation (ce qui va se passer,
// pour quel objet), dont le formulaire POST vers la même URL exécute l'action, avec un
// lien d'annulation. Sans JavaScript, compatible avec la CSP ; le GET ne modifie rien et
// répond 404 pour un objet absent ou d'une autre organisation, comme le POST.

// confirmView est la page de confirmation. Args sert au titre, au texte et au bouton.
type confirmView struct {
	render.Page
	HeadingKey string
	TextKey    string
	SubmitKey  string
	Args       map[string]any
	// Action est l'URL du POST : celle de la page.
	Action string
	// Cancel ramène à l'écran d'où vient l'action.
	Cancel string
}

// confirmation décrit une page de confirmation ; TitleKey vaut HeadingKey.
type confirmation struct {
	nav     []render.NavItem
	heading string
	text    string
	submit  string
	args    map[string]any
	cancel  string
}

func (id *identity) confirm(w http.ResponseWriter, r *http.Request, c confirmation) {
	id.rd.Render(w, r, http.StatusOK, "confirm/action", &confirmView{
		Page:       render.Page{TitleKey: c.heading, TitleArgs: c.args, Nav: c.nav},
		HeadingKey: c.heading, TextKey: c.text, SubmitKey: c.submit, Args: c.args,
		Action: r.URL.Path, Cancel: c.cancel,
	})
}

// confirmRevokeAgentToken : révocation d'un jeton d'agent.
func (id *identity) confirmRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	back := orgBase(acc) + "/agents/" + a.ID.String()
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	for _, t := range a.Tokens {
		if t.ID != tid {
			continue
		}
		if t.RevokedAt != nil {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		id.confirm(w, r, confirmation{nav: orgNav(acc, "agents"), heading: "confirm.agent_token_heading",
			text: "confirm.agent_token_text", submit: "confirm.agent_token_submit",
			args: map[string]any{"Name": t.Name, "Agent": a.Name}, cancel: back})
		return
	}
	id.rd.Error(w, r, http.StatusNotFound)
}

// confirmDisableAgent : désactivation d'un agent (jetons révoqués, projets retirés).
func (id *identity) confirmDisableAgent(w http.ResponseWriter, r *http.Request) {
	a, ok := id.agentFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	back := orgBase(acc) + "/agents/" + a.ID.String()
	if a.DisabledAt != nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	id.confirm(w, r, confirmation{nav: orgNav(acc, "agents"), heading: "confirm.agent_disable_heading",
		text: "confirm.agent_disable_text", submit: "agent.disable",
		args: map[string]any{"Agent": a.Name}, cancel: back})
}

// confirmRevokeEnrollment : révocation d'un jeton d'inscription de serveurs.
func (id *identity) confirmRevokeEnrollment(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	back := orgBase(acc) + "/agents"
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	list, err := id.Agents.Enrollments(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	for _, t := range list {
		if t.ID != tid {
			continue
		}
		if t.RevokedAt != nil {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		id.confirm(w, r, confirmation{nav: orgNav(acc, "agents"), heading: "confirm.enrollment_heading",
			text: "confirm.enrollment_text", submit: "confirm.enrollment_submit",
			args: map[string]any{"Name": t.Name}, cancel: back})
		return
	}
	id.rd.Error(w, r, http.StatusNotFound)
}

// confirmRemoveMember : retrait d'un membre, soi-même compris (on perd alors l'accès).
func (id *identity) confirmRemoveMember(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	m, err := id.Orgs.Member(r.Context(), acc.Org, userID)
	if errors.Is(err, org.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	text := "confirm.member_text"
	if m.UserID == viewerFrom(r).user.ID {
		text = "confirm.member_self_text"
	}
	id.confirm(w, r, confirmation{nav: orgNav(acc, "members"), heading: "confirm.member_heading", text: text,
		submit: "confirm.member_submit", args: map[string]any{"Email": m.Email, "Org": acc.Name},
		cancel: orgBase(acc) + "/members"})
}

// confirmRevokePersonalToken : révocation d'un jeton personnel du compte ; celui d'un
// autre compte n'existe pas pour lui (404).
func (id *identity) confirmRevokePersonalToken(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	list, err := id.Accounts.PersonalTokens(r.Context(), viewerFrom(r).user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	for _, t := range list {
		if t.ID != tid {
			continue
		}
		if t.RevokedAt != nil {
			http.Redirect(w, r, pathTokens, http.StatusSeeOther)
			return
		}
		id.confirm(w, r, confirmation{nav: accountNav("tokens"), heading: "confirm.personal_token_heading",
			text: "confirm.personal_token_text", submit: "confirm.personal_token_submit",
			args: map[string]any{"Name": t.Name, "Prefix": t.Prefix()}, cancel: pathTokens})
		return
	}
	id.rd.Error(w, r, http.StatusNotFound)
}

// confirmUserAction : réinitialisation du mot de passe ou du TOTP d'un compte. Les
// autres actions du compte sont réversibles (réactiver, rétablir le rôle) : pas de
// confirmation, et pas de GET.
func (id *identity) confirmUserAction(w http.ResponseWriter, r *http.Request) {
	var heading, text, submit string
	switch chi.URLParam(r, "action") {
	case "reset-password":
		heading, text, submit = "confirm.reset_password_heading", "confirm.reset_password_text", "admin_user.reset_password"
	case "reset-totp":
		heading, text, submit = "confirm.reset_totp_heading", "confirm.reset_totp_text", "admin_user.reset_totp"
	default:
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	u, ok := id.userFromPath(w, r)
	if !ok {
		return
	}
	id.confirm(w, r, confirmation{nav: adminNav("users"), heading: heading, text: text, submit: submit,
		args: map[string]any{"Email": u.Email}, cancel: "/admin/users/" + strconv.FormatInt(u.ID, 10)})
}

// confirmDiscardJob : abandon d'un traitement en échec, qui supprime le job et sa
// dernière erreur.
func (id *identity) confirmDiscardJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	// GetDead verrouille la ligne (FOR UPDATE) : transaction courte en écriture.
	var d jobs.DeadJob
	err = id.Pool.InTx(r.Context(), func(tx *db.Tx) error {
		var err error
		d, err = jobs.GetDead(r.Context(), tx, jobID)
		return err
	})
	if errors.Is(err, jobs.ErrNotFound) {
		// Déjà relancé ou abandonné : l'écran des traitements le dit.
		id.jobsPage(w, r, http.StatusNotFound, formError{Key: "admin_jobs.not_found"})
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.confirm(w, r, confirmation{nav: adminNav("jobs"), heading: "confirm.job_heading", text: "confirm.job_text",
		submit: "admin_jobs.discard", args: map[string]any{"Kind": d.Kind, "Attempts": d.Attempts}, cancel: "/admin/jobs"})
}
