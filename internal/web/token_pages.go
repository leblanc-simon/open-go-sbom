package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/render"
)

type personalTokenRow struct {
	ID       uuid.UUID
	Name     string
	Prefix   string
	Created  *stamp
	LastUsed *stamp
	Expires  *stamp
	Revoked  *stamp
	Active   bool
}

type personalTokensView struct {
	render.Page
	Tokens    []personalTokenRow
	Lifetimes []option
	Name      string
	Max       int
	FlashKey  string
	Error     formError
	// Plaintext : le jeton qui vient d'être créé, montré une seule fois.
	Plaintext string
	Created   *personalTokenRow
}

func personalTokenLifetimes(selected int) []option {
	var out []option
	for _, d := range account.PersonalTokenDays() {
		out = append(out, option{Value: strconv.Itoa(d), LabelKey: "tokens.expiry_" + strconv.Itoa(d), Selected: d == selected})
	}
	return out
}

func patRow(t account.PersonalToken, active bool) personalTokenRow {
	return personalTokenRow{ID: t.ID, Name: t.Name, Prefix: t.Prefix(), Created: stampAt(t.CreatedAt), LastUsed: stampOf(t.LastUsedAt),
		Expires: dateOf(&t.ExpiresAt), Revoked: stampOf(t.RevokedAt), Active: active}
}

// renderTokens affiche les jetons personnels du compte et le formulaire de création.
func (id *identity) renderTokens(w http.ResponseWriter, r *http.Request, status int, view *personalTokensView) {
	v := viewerFrom(r)
	tokens, err := id.Accounts.PersonalTokens(r.Context(), v.user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	at := time.Now()
	for _, t := range tokens {
		view.Tokens = append(view.Tokens, patRow(t, t.Active(at)))
	}
	view.Page = render.Page{TitleKey: "tokens.title", Nav: accountNav("tokens")}
	view.Max = account.MaxPersonalTokens
	if view.Lifetimes == nil {
		view.Lifetimes = personalTokenLifetimes(account.DefaultPersonalTokenDays)
	}
	id.rd.Render(w, r, status, "account/tokens", view)
}

// personalTokens est la page des jetons d'accès personnels du profil.
func (id *identity) personalTokens(w http.ResponseWriter, r *http.Request) {
	id.renderTokens(w, r, http.StatusOK, &personalTokensView{FlashKey: flashKey(r)})
}

// createPersonalToken tire un jeton ; son secret n'est montré que dans cette réponse
// (pas de redirection, page non mise en cache).
func (id *identity) createPersonalToken(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	v := viewerFrom(r)
	name := r.PostForm.Get("name")
	days := atoiDefault(r.PostForm.Get("expires_in"), -1)
	t, issued, err := id.Accounts.CreatePersonalToken(r.Context(), id.actor(r), v.user.ID, name, days)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.renderTokens(w, r, http.StatusUnprocessableEntity, &personalTokensView{Name: name, Error: fe,
				Lifetimes: personalTokenLifetimes(days)})
			return
		}
		id.serverError(w, r, err)
		return
	}
	row := patRow(t, true)
	id.renderTokens(w, r, http.StatusOK, &personalTokensView{Plaintext: issued.Plaintext, Created: &row})
}

// revokePersonalToken révoque un jeton du compte ; un jeton d'un autre compte n'existe pas
// pour lui (404).
func (id *identity) revokePersonalToken(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err = id.Accounts.RevokePersonalToken(r.Context(), id.actor(r), viewerFrom(r).user.ID, tid)
	switch {
	case errors.Is(err, account.ErrTokenNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	case err != nil:
		id.serverError(w, r, err)
	default:
		redirectDone(w, r, pathTokens, "personal_token_revoked")
	}
}
