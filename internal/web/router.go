package web

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/corsx"
	"leblanc.io/open-go-base/csrfx"
	"leblanc.io/open-go-base/ratelimit"

	"leblanc.io/open-go-sbom/internal/api/problem"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/web/middleware"
)

// RouterOptions réunit les dépendances du routeur.
type RouterOptions struct {
	Logger   *slog.Logger
	Catalog  *locale.Catalog
	Renderer *render.Renderer
	Assets   *render.Assets
	Metrics  *middleware.HTTPMetrics
	// RateLimit est le nombre de requêtes par minute et par IP de l'interface (0 : sans).
	RateLimit int
	// TrustedProxies : mandataires dont on croit X-Forwarded-For et X-Forwarded-Proto.
	TrustedProxies []string
	// CORS s'applique à l'API utilisateur seulement.
	CORS appconf.CORS
	// CSRFSecure pilote l'attribut Secure du cookie CSRF : auto, on, off.
	CSRFSecure string
	// Identity branche comptes, sessions, TOTP et organisations ; nil, l'interface n'a que
	// sa page d'accueil publique (tests du socle).
	Identity *IdentityOptions

	// extraUI ajoute des routes à l'interface (tests du paquet).
	extraUI func(chi.Router)
}

// NewRouter construit le routeur public et ses trois groupes de routes.
func NewRouter(o RouterOptions) (http.Handler, error) {
	if o.Logger == nil || o.Catalog == nil || o.Renderer == nil || o.Assets == nil || o.Metrics == nil {
		return nil, errors.New("web: dépendances du routeur incomplètes")
	}
	proxies, err := middleware.ParseTrustedProxies(o.TrustedProxies)
	if err != nil {
		return nil, err
	}
	https := middleware.TLSDetector(proxies)
	uiHeaders := middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPInterface, HTTPS: https, NoStore: true})
	apiHeaders := middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPAPI, HTTPS: https, NoStore: true})

	tooMany := uiHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.Renderer.Error(w, r, http.StatusTooManyRequests)
	}))
	limiter, err := ratelimit.New(o.RateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany))
	if err != nil {
		return nil, err
	}
	accessLog := middleware.AccessLog(o.Logger, limiter.ClientIP)
	pageError := func(status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { o.Renderer.Error(w, r, status) })
	}

	csrfFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.Renderer.ErrorWithKey(w, r, http.StatusForbidden, "error.csrf")
	})
	csrf := csrfx.New(csrfx.WithSecure(o.CSRFSecure), csrfx.WithFailureHandler(csrfFailure)).Middleware

	var id *identity
	loginLimit := func(next http.Handler) http.Handler { return next }
	ui := chi.Chain(
		o.Metrics.Middleware("ui"),
		limiter.Middleware,
		accessLog,
		middleware.Recover(o.Logger, pageError(http.StatusInternalServerError)),
		uiHeaders,
		limitBody,
	)
	if o.Identity != nil {
		if id, err = newIdentity(*o.Identity, o.Renderer, o.Catalog, o.Logger, limiter.ClientIP); err != nil {
			return nil, err
		}
		login, err := ratelimit.New(o.Identity.LoginRateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany))
		if err != nil {
			return nil, err
		}
		loginLimit = login.Middleware
		// Session (authx) et visiteur, puis changement de mot de passe imposé (§ 14).
		ui = append(ui, trustClientIP(proxies, limiter.ClientIP), id.mgr.LoadSession, id.loadViewer, mustChangePassword)
	}
	// La langue précède la garde d'organisation, qui la recalcule (§ 18).
	ui = append(ui, csrf, middleware.Language(o.Catalog, middleware.LanguageSources{Account: accountLanguage}))
	api := func(group string) chi.Middlewares {
		return chi.Chain(
			o.Metrics.Middleware(group),
			accessLog,
			middleware.Recover(o.Logger, problem.Handler(o.Catalog, http.StatusInternalServerError, problem.KeyInternal)),
			apiHeaders,
			middleware.Language(o.Catalog, middleware.LanguageSources{}),
		)
	}
	apiNotFound := problem.Handler(o.Catalog, http.StatusNotFound, problem.KeyNotFound)
	apiNotAllowed := problem.Handler(o.Catalog, http.StatusMethodNotAllowed, problem.KeyMethodNotAllowed)

	r := chi.NewRouter()
	// GetHead sert HEAD par les routes GET ; il doit précéder le routage pour cela.
	r.Use(middleware.RequestID, chimw.GetHead)

	r.Group(func(r chi.Router) {
		r.Use(o.Metrics.Middleware("static"),
			middleware.Recover(o.Logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			})),
			middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPInterface, HTTPS: https}))
		r.Handle("/static/*", o.Assets.Handler())
	})

	// Les groupes d'API sont montés vides : leurs opérations arrivent avec T04. Ils n'ont
	// ni session ni CSRF.
	// Les middlewares d'un groupe d'API s'appliquent au montage (With) : chi ne passe pas
	// par ceux d'un sous-routeur qui n'a encore aucune route.
	r.With(api("agent")...).Route("/api/v1/agent", func(r chi.Router) {
		r.NotFound(apiNotFound.ServeHTTP)
		r.MethodNotAllowed(apiNotAllowed.ServeHTTP)
	})
	r.With(append(chi.Middlewares{corsx.Middleware(o.CORS)}, api("user")...)...).Route("/api/v1/orgs/{org}", func(r chi.Router) {
		r.NotFound(apiNotFound.ServeHTTP)
		r.MethodNotAllowed(apiNotAllowed.ServeHTTP)
	})
	r.With(api("api")...).Handle("/api/*", apiNotFound)

	r.Group(func(r chi.Router) {
		r.Use(ui...)
		registerUI(r, &handlers{renderer: o.Renderer, id: id}, loginLimit)
		if o.extraUI != nil {
			o.extraUI(r)
		}
	})
	r.NotFound(ui.Handler(pageError(http.StatusNotFound)).ServeHTTP)
	r.MethodNotAllowed(ui.Handler(pageError(http.StatusMethodNotAllowed)).ServeHTTP)
	return r, nil
}
