package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	authsql "leblanc.io/open-go-base/authx/sqlstore"
	"leblanc.io/open-go-base/mfax"
	mfasql "leblanc.io/open-go-base/mfax/sqlstore"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/secret"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/web/middleware"
)

// Chemins du parcours de connexion.
const (
	pathLogin     = "/login"
	pathVerify    = "/login/2fa"
	pathTOTPSetup = "/account/totp/setup"
	pathTOTPOn    = "/account/totp/enable"
	pathPassword  = "/account/password"
	pathLogout    = "/logout"
	pathHome      = "/"
)

// IdentityOptions branche les comptes, les sessions, le TOTP et les organisations sur
// l'interface. Sans elles (tests du socle), l'interface n'a que ses pages publiques.
type IdentityOptions struct {
	Pool     *db.Pool
	Accounts *account.Service
	Orgs     *org.Service
	Projects *project.Service
	Agents   *agent.Service
	// Secrets chiffre les secrets TOTP en base.
	Secrets *secret.Box
	Auth    appconf.Auth
	MFA     appconf.MFA
	// LoginRateLimit borne les POST de /login et /login/2fa par minute et par IP (0 : sans).
	LoginRateLimit int
}

// identity porte authx, mfax et ce que l'interface en tire : visiteur, gardes, rendu des
// pages de connexion.
type identity struct {
	IdentityOptions
	mgr        *authx.Manager
	login      *authx.Handlers
	mfa        *mfax.Service
	challenges mfax.ChallengeStore
	rd         *render.Renderer
	cat        *locale.Catalog
	logger     *slog.Logger
	clientIP   func(*http.Request) string
}

func newIdentity(o IdentityOptions, rd *render.Renderer, cat *locale.Catalog, logger *slog.Logger, clientIP func(*http.Request) string) (*identity, error) {
	if o.Pool == nil || o.Accounts == nil || o.Orgs == nil || o.Projects == nil || o.Agents == nil || o.Secrets == nil {
		return nil, errors.New("web: dépendances de l'identité incomplètes")
	}
	id := &identity{IdentityOptions: o, rd: rd, cat: cat, logger: logger, clientIP: clientIP}
	d := appconf.DialectPostgres
	sqlDB := o.Pool.DB()
	sessions := account.NewSessionRecorder(authsql.NewSessionStore(sqlDB, d), o.Pool)
	id.mgr = authx.New(o.Auth, authsql.NewUserStore(sqlDB, d), sessions,
		authx.WithManagerErrorHandler(id.authError))
	id.challenges = mfasql.NewChallengeStore(sqlDB, d)
	totp := account.NewSealedTOTPStore(mfasql.NewTOTPStore(sqlDB, d), o.Secrets, o.Pool)
	// Enrôlement obligatoire : jamais mfax.WithOptionalEnrollment().
	id.mfa = mfax.New(o.MFA, id.mgr, totp, id.challenges,
		mfax.WithRenderer(authRenderer{id}),
		mfax.WithPaths(pathVerify, pathTOTPSetup, pathHome),
		mfax.WithErrorHandler(id.mfaError))
	id.login = authx.NewHandlers(id.mgr, authRenderer{id},
		authx.WithSecondFactor(id.mfa), authx.WithHomePath(pathHome), authx.WithErrorHandler(id.authError))
	return id, nil
}

func (id *identity) authError(w http.ResponseWriter, r *http.Request, status int, code authx.ErrorCode, err error) {
	id.fail(w, r, status, string(code), err)
}

func (id *identity) mfaError(w http.ResponseWriter, r *http.Request, status int, code mfax.ErrorCode, err error) {
	id.fail(w, r, status, string(code), err)
}

func (id *identity) fail(w http.ResponseWriter, r *http.Request, status int, code string, err error) {
	if err != nil {
		middleware.Logger(r.Context(), id.logger).Error("authentification", "code", code, "err", err)
	}
	id.rd.Error(w, r, status)
}

// serverError journalise err et rend la page 500.
func (id *identity) serverError(w http.ResponseWriter, r *http.Request, err error) {
	middleware.Logger(r.Context(), id.logger).Error("requête", "err", err)
	id.rd.Error(w, r, http.StatusInternalServerError)
}

// actor décrit l'auteur de la requête pour le journal d'audit.
func (id *identity) actor(r *http.Request) audit.Actor {
	a := audit.Actor{IP: id.clientIP(r), RequestID: middleware.RequestIDFrom(r.Context())}
	if v := viewerFrom(r); v != nil {
		a.UserID, a.Email = v.user.ID, v.user.Email
	}
	return a
}

// viewer est le compte connecté d'une requête.
type viewer struct {
	user    *authx.User
	session *authx.Session
	state   account.ViewerState
}

func (v *viewer) authenticated() bool { return v != nil && v.session.Purpose == authx.PurposeAuth }
func (v *viewer) admin() bool         { return v != nil && v.user.Role == account.RoleAdmin }

type viewerKey struct{}

func viewerFrom(r *http.Request) *viewer {
	v, _ := r.Context().Value(viewerKey{}).(*viewer)
	return v
}

// trustClientIP réécrit X-Forwarded-For avec l'IP résolue (mandataires de confiance
// seulement) et retire X-Forwarded-Proto d'un pair non fiable : authx, qui lit ces
// en-têtes sans vérifier le pair, enregistre alors la bonne IP de session.
func trustClientIP(proxies middleware.TrustedProxies, clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r2 := r.Clone(r.Context())
			r2.Header.Set("X-Forwarded-For", clientIP(r))
			if !proxies.Trusts(r) {
				r2.Header.Del("X-Forwarded-Proto")
			}
			next.ServeHTTP(w, r2)
		})
	}
}

// loadViewer suit authx.LoadSession : il refuse une session authentifiée sans méthode
// enregistrée ou dont le compte n'a plus de TOTP actif (réinitialisé entre-temps), et place
// le visiteur et l'en-tête dans le contexte.
func (id *identity) loadViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, sess := authx.UserFrom(r), authx.SessionFrom(r)
		if user == nil || sess == nil {
			next.ServeHTTP(w, r)
			return
		}
		st, err := id.Accounts.Viewer(r.Context(), user.ID, sess.Token)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		v := &viewer{user: user, session: sess, state: st}
		if v.authenticated() && (!st.HasMethod || !st.TOTPEnabled) {
			id.mgr.Logout(w, r)
			http.Redirect(w, r, pathLogin, http.StatusSeeOther)
			return
		}
		chrome := &render.Chrome{UserEmail: user.Email, Theme: st.Settings.Theme}
		if v.authenticated() {
			chrome.Admin = v.admin()
			for _, o := range st.Orgs {
				chrome.Orgs = append(chrome.Orgs, render.OrgEntry{Slug: o.Slug, Name: o.Name})
			}
		}
		ctx := context.WithValue(r.Context(), viewerKey{}, v)
		next.ServeHTTP(w, r.WithContext(render.WithChrome(ctx, chrome)))
	})
}

// accountLanguage est la source « préférence du compte » de l'ordre du § 18.
func accountLanguage(r *http.Request) string {
	if v := viewerFrom(r); v != nil {
		return v.state.Settings.Language
	}
	return ""
}

// mustChangePassword impose le changement d'un mot de passe temporaire avant toute autre
// page : ni authx ni mfax n'appliquent must_change_pwd.
func mustChangePassword(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := viewerFrom(r); v.authenticated() && v.user.MustChangePwd &&
			r.URL.Path != pathPassword && r.URL.Path != pathLogout {
			http.Redirect(w, r, pathPassword, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth exige une session pleinement authentifiée ; une session de configuration est
// renvoyée vers l'enrôlement du TOTP, un visiteur anonyme vers la connexion.
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r)
		switch {
		case v.authenticated():
			next.ServeHTTP(w, r)
		case v != nil:
			http.Redirect(w, r, pathTOTPSetup, http.StatusSeeOther)
		default:
			authx.RedirectToLogin(w, r)
		}
	})
}

// requireSession accepte aussi une session de configuration (enrôlement du TOTP).
func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if viewerFrom(r) == nil {
			authx.RedirectToLogin(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireInstanceAdmin réserve l'administration de l'instance à ses administrateurs ; les
// autres reçoivent 404, comme pour une page qui n'existe pas.
func (id *identity) requireInstanceAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !viewerFrom(r).admin() {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// orgGuard établit l'organisation de /o/{slug} : le compte doit en être membre et elle doit
// être active, sinon 404 (jamais 403, pour ne rien révéler de son existence). Il place
// tenant.Access dans le contexte et recalcule la langue avec celle de l'organisation.
func (id *identity) orgGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r)
		acc, err := crossorg.Access(r.Context(), id.Pool.DB(), chi.URLParam(r, "slug"), v.user.ID)
		if errors.Is(err, crossorg.ErrNoAccess) {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		ctx := tenant.WithAccess(r.Context(), acc)
		tag := middleware.ResolveLanguage(id.cat, r, middleware.LanguageSources{
			Account: accountLanguage,
			Org:     func(*http.Request) string { return acc.Language },
		})
		w.Header().Set("Content-Language", tag.String())
		ctx = locale.NewContext(ctx, id.cat.Localizer(tag))
		if c := render.ChromeFrom(ctx); c != nil {
			cc := *c
			cc.Orgs = make([]render.OrgEntry, len(c.Orgs))
			for i, o := range c.Orgs {
				o.Current = o.Slug == acc.Slug
				cc.Orgs[i] = o
			}
			cc.Current = &render.OrgEntry{Slug: acc.Slug, Name: acc.Name, Current: true}
			ctx = render.WithChrome(ctx, &cc)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireOrgRole réserve une page de l'organisation aux rôles au moins égaux à min (403
// sinon : le membre connaît déjà l'organisation).
func (id *identity) requireOrgRole(min tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if acc, ok := tenant.AccessFrom(r.Context()); !ok || !acc.Role.AtLeast(min) {
				id.rd.Error(w, r, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// safeNext ne garde qu'un chemin local pour ?next=.
func safeNext(next string) string {
	if p := authx.SafeRedirectPath(next, ""); p != "" && !strings.HasPrefix(p, pathLogin) {
		return p
	}
	return ""
}
