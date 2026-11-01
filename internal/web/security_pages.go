package web

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"leblanc.io/open-go-base/mfax"

	"leblanc.io/lotor/internal/render"
)

// doneRecoverySignIn est le message d'arrivée sur la page du second facteur après une
// connexion par code de secours.
const doneRecoverySignIn = "recovery_signin"

// doneTOTPReconfigured est le message de la page de connexion après la reconfiguration du
// TOTP par son titulaire.
const doneTOTPReconfigured = "totp_reconfigured"

// lowRecoveryCodes : à partir de ce nombre de codes restants, la page invite à en régénérer.
const lowRecoveryCodes = 3

var totpCode = regexp.MustCompile(`^[0-9]{6}$`)

type securityView struct {
	render.Page
	Remaining int
	Total     int
	Low       bool
	FlashKey  string
	Error     formError
	// Codes : le jeu qui vient d'être généré, montré une seule fois.
	Codes []string
}

// renderSecurity affiche la page du second facteur : codes de secours restants,
// régénération, reconfiguration de l'application.
func (id *identity) renderSecurity(w http.ResponseWriter, r *http.Request, status int, view *securityView) {
	v := viewerFrom(r)
	remaining, err := id.mfa.RecoveryRemaining(v.user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view.Page = render.Page{TitleKey: "security.title", Nav: accountNav("security")}
	view.Remaining, view.Total, view.Low = remaining, id.recoveryTotal(), remaining <= lowRecoveryCodes
	if view.Codes != nil {
		// Les codes ne doivent survivre ni dans un cache ni dans l'historique.
		w.Header().Set("Cache-Control", "no-store")
	}
	id.rd.Render(w, r, status, "account/security", view)
}

// recoveryTotal est le nombre de codes d'un jeu (mfa.recovery_codes).
func (id *identity) recoveryTotal() int {
	if id.MFA.RecoveryCodes > 0 {
		return id.MFA.RecoveryCodes
	}
	return 10
}

func (id *identity) security(w http.ResponseWriter, r *http.Request) {
	id.renderSecurity(w, r, http.StatusOK, &securityView{FlashKey: flashKey(r)})
}

// regenerateRecoveryCodes remplace les codes de secours du compte après un code TOTP
// (réauthentification, comme la création d'un jeton personnel) et montre le nouveau jeu dans
// cette seule réponse.
func (id *identity) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	v := viewerFrom(r)
	ok, err := id.mfa.Confirm(r, v.user, strings.TrimSpace(r.PostForm.Get("code")))
	if fe, done := id.confirmFailure(w, r, ok, err, "code"); done {
		if fe.Key != "" {
			id.renderSecurity(w, r, http.StatusUnprocessableEntity, &securityView{Error: fe})
		}
		return
	}
	codes, err := id.mfa.GenerateRecoveryCodes(v.user.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	authRenderer{id}.recordRecoveryCodes(r, len(codes), "regenerated")
	id.renderSecurity(w, r, http.StatusOK, &securityView{Codes: codes})
}

// reconfigureTOTP retire le TOTP du compte à la demande de son titulaire, qui prouve
// détenir un facteur par un code TOTP ou, s'il a perdu son application, par un code de
// secours. Toutes ses sessions sont fermées : la connexion suivante (mot de passe) mène à un
// nouvel enrôlement, le TOTP restant obligatoire.
func (id *identity) reconfigureTOTP(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	v := viewerFrom(r)
	code := strings.TrimSpace(r.PostForm.Get("reconfigure_code"))
	var ok bool
	var err error
	if totpCode.MatchString(code) {
		ok, err = id.mfa.Confirm(r, v.user, code)
	} else {
		ok, err = id.mfa.ConfirmRecovery(r, v.user, code)
	}
	if fe, done := id.confirmFailure(w, r, ok, err, "reconfigure_code"); done {
		if fe.Key != "" {
			id.renderSecurity(w, r, http.StatusUnprocessableEntity, &securityView{Error: fe})
		}
		return
	}
	if err := id.Accounts.ReconfigureTOTP(r.Context(), id.actor(r), v.user.ID); err != nil {
		id.serverError(w, r, err)
		return
	}
	id.mgr.Logout(w, r)
	http.Redirect(w, r, pathLogin+"?done="+doneTOTPReconfigured, http.StatusSeeOther)
}

// confirmFailure traduit l'issue d'une réauthentification : done vaut vrai si la requête
// s'arrête, avec l'erreur de saisie à afficher (clé vide : erreur interne déjà rendue).
func (id *identity) confirmFailure(w http.ResponseWriter, r *http.Request, ok bool, err error, field string) (formError, bool) {
	switch {
	case errors.Is(err, mfax.ErrLocked):
		return formError{Field: field, Key: "security.error.locked"}, true
	case err != nil:
		id.serverError(w, r, err)
		return formError{}, true
	case !ok:
		return formError{Field: field, Key: "security.error.invalid_code"}, true
	}
	return formError{}, false
}
