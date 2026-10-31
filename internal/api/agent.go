package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-base/ratelimit"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/api/gen"
	"leblanc.io/open-go-sbom/internal/api/problem"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/pagination"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/web/middleware"
)

// maxAgentJSON borne le corps JSON d'une requête d'agent (inscription, signal de vie).
// Les envois de SBOM (T05, multipart) ont leurs propres bornes.
const maxAgentJSON = 64 << 10

// Pages de GET /agent/projects.
const (
	agentProjectsDefault = 100
	agentProjectsMax     = project.AgentPageMax
)

// AgentOptions réunit les dépendances de l'API des agents.
type AgentOptions struct {
	Agents  *agent.Service
	Catalog *locale.Catalog
	Logger  *slog.Logger
	// RateLimit borne les requêtes par minute et par jeton (0 : sans limite).
	RateLimit int
	// FailureRateLimit borne les jetons refusés par minute et par IP (0 : sans limite).
	FailureRateLimit int
	TrustedProxies   []string
	// ClientIP résout l'IP du client (mandataires de confiance compris).
	ClientIP func(*http.Request) string
}

// MountAgent monte les opérations de l'API des agents sur r, routeur de /api/v1 : corps
// borné, authentification par jeton, limitation par jeton, puis le serveur strict généré.
func MountAgent(r chi.Router, o AgentOptions) error {
	if o.Agents == nil || o.Catalog == nil || o.Logger == nil || o.ClientIP == nil {
		return errors.New("api: dépendances de l'API des agents incomplètes")
	}
	h := &agentAPI{AgentOptions: o}
	tooMany := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem.Write(w, r, o.Catalog, http.StatusTooManyRequests, problem.KeyTooManyRequests, nil)
	})
	perToken, err := ratelimit.New(o.RateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany),
		ratelimit.WithKeyFunc(func(r *http.Request) string {
			if p, ok := principalFrom(r.Context()); ok {
				return p.RateKey()
			}
			return ""
		}))
	if err != nil {
		return err
	}
	failures, err := ratelimit.New(o.FailureRateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany))
	if err != nil {
		return err
	}
	// Un refus passe par le limiteur par IP : un client qui enchaîne les jetons refusés
	// reçoit 429, sans gêner les agents authentifiés derrière la même IP.
	h.refuse = failures.Middleware(http.HandlerFunc(h.writeRefusal))

	strict := gen.NewStrictHandlerWithOptions(h, []gen.StrictMiddlewareFunc{h.requireKind},
		gen.StrictHTTPServerOptions{RequestErrorHandlerFunc: h.badRequest, ResponseErrorHandlerFunc: h.responseError})
	r.Group(func(r chi.Router) {
		r.Use(limitJSON, h.authenticate, perToken.Middleware)
		gen.HandlerWithOptions(strict, gen.ChiServerOptions{BaseRouter: r, ErrorHandlerFunc: h.badRequest})
	})
	return nil
}

type agentAPI struct {
	AgentOptions
	refuse http.Handler
}

var _ gen.StrictServerInterface = (*agentAPI)(nil)

type principalKey struct{}

func principalFrom(ctx context.Context) (agent.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(agent.Principal)
	return p, ok
}

type refusalKey struct{}

// limitJSON borne le corps des requêtes JSON de l'API des agents.
func limitJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			r.Body = http.MaxBytesReader(w, r.Body, maxAgentJSON)
		}
		next.ServeHTTP(w, r)
	})
}

// bearer lit le jeton de l'en-tête Authorization.
func bearer(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// authenticate vérifie le jeton (d'agent ou d'inscription) et place le principal dans le
// contexte ; un refus répond 401 avec une clé traduisible, jamais avec le jeton.
func (h *agentAPI) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.Agents.Authenticate(r.Context(), bearer(r))
		if err != nil {
			var ae *agent.AuthError
			if !errors.As(err, &ae) {
				h.internal(w, r, err)
				return
			}
			h.refuse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), refusalKey{}, ae.Key)))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, clientIPKey{}, h.ClientIP(r))))
	})
}

func (h *agentAPI) writeRefusal(w http.ResponseWriter, r *http.Request) {
	key, _ := r.Context().Value(refusalKey{}).(string)
	if key == "" {
		key = agent.KeyTokenInvalid
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="ogsbom"`)
	problem.Write(w, r, h.Catalog, http.StatusUnauthorized, key, nil)
}

// operationKinds associe chaque opération à la nature de jeton qu'elle exige.
var operationKinds = map[string]agent.TokenKind{
	"Enroll":            agent.KindEnrollment,
	"Heartbeat":         agent.KindAgent,
	"ListAgentProjects": agent.KindAgent,
}

// requireKind refuse un jeton d'une autre nature que celle de l'opération : un jeton
// d'inscription n'ouvre que l'inscription, un jeton d'agent tout le reste.
func (h *agentAPI) requireKind(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		want, known := operationKinds[operationID]
		if p, ok := principalFrom(ctx); !known || !ok || p.Kind != want {
			return nil, &agent.AuthError{Key: agent.KeyTokenInvalid}
		}
		return f(ctx, w, r, request)
	}
}

// badRequest répond à une requête illisible (corps, paramètres).
func (h *agentAPI) badRequest(w http.ResponseWriter, r *http.Request, _ error) {
	problem.Write(w, r, h.Catalog, http.StatusBadRequest, problem.KeyInvalidRequest, nil)
}

func (h *agentAPI) internal(w http.ResponseWriter, r *http.Request, err error) {
	middleware.Logger(r.Context(), h.Logger).Error("api agent", "err", err)
	problem.Write(w, r, h.Catalog, http.StatusInternalServerError, problem.KeyInternal, nil)
}

// responseError traduit l'erreur d'un handler en problème.
func (h *agentAPI) responseError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *agent.AuthError
	var ce *agent.ConflictError
	switch {
	case errors.As(err, &ae):
		r = r.WithContext(context.WithValue(r.Context(), refusalKey{}, ae.Key))
		h.refuse.ServeHTTP(w, r)
	case errors.As(err, &ce):
		problem.Write(w, r, h.Catalog, http.StatusConflict, ce.Key, nil)
	case problem.FromPagination(w, r, h.Catalog, err):
	default:
		if v, ok := account.IsValidation(err); ok {
			problem.WriteValidation(w, r, h.Catalog, v.Key)
			return
		}
		h.internal(w, r, err)
	}
}

// Enroll inscrit un agent serveur.
func (h *agentAPI) Enroll(ctx context.Context, req gen.EnrollRequestObject) (gen.EnrollResponseObject, error) {
	p, _ := principalFrom(ctx)
	ip, _ := ctx.Value(clientIPKey{}).(string)
	res, err := h.Agents.Enroll(ctx, p, agent.EnrollRequest{Hostname: req.Body.Hostname, Version: req.Body.Version}, ip,
		middleware.RequestIDFrom(ctx))
	if err != nil {
		return nil, err
	}
	return gen.Enroll201JSONResponse{
		AgentId: res.Agent.ID,
		Token:   res.Token.Plaintext,
		Project: gen.ProjectRef{Id: res.Project.ID, Slug: res.Project.Slug},
	}, nil
}

// Heartbeat enregistre le signal de vie de l'agent.
func (h *agentAPI) Heartbeat(ctx context.Context, req gen.HeartbeatRequestObject) (gen.HeartbeatResponseObject, error) {
	p, _ := principalFrom(ctx)
	if err := h.Agents.Heartbeat(ctx, p, req.Body.Version); err != nil {
		return nil, err
	}
	return gen.Heartbeat200JSONResponse{ScanRequested: false, ServerTime: h.Agents.Now()}, nil
}

// ListAgentProjects renvoie les projets confiés à l'agent.
func (h *agentAPI) ListAgentProjects(ctx context.Context, req gen.ListAgentProjectsRequestObject) (gen.ListAgentProjectsResponseObject, error) {
	p, _ := principalFrom(ctx)
	limit, err := pagination.Limit(req.Params.Limit, agentProjectsDefault, agentProjectsMax)
	if err != nil {
		return nil, err
	}
	cursor := ""
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	projects, next, err := h.Agents.AssignedProjects(ctx, p, cursor, limit)
	if err != nil {
		return nil, err
	}
	out := gen.ListAgentProjects200JSONResponse{Projects: make([]gen.AgentProject, 0, len(projects))}
	if next != "" {
		out.Page.NextCursor = &next
	}
	for _, pr := range projects {
		ap := gen.AgentProject{Id: pr.ID, Slug: pr.Slug, Name: pr.Name, Kind: gen.AgentProjectKind(pr.Kind),
			Labels: pr.Labels, Refs: make([]gen.TrackedRef, 0, len(pr.Refs))}
		if pr.ForgeURL != "" {
			ap.ForgeUrl = &pr.ForgeURL
		}
		for _, ref := range pr.Refs {
			ap.Refs = append(ap.Refs, gen.TrackedRef{Id: ref.ID, Kind: gen.TrackedRefKind(ref.Kind), Name: ref.Name})
		}
		out.Projects = append(out.Projects, ap)
	}
	return out, nil
}

type clientIPKey struct{}
