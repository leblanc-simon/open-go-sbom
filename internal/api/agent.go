package api

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/open-go-base/ratelimit"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/api/gen"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/web/middleware"
)

// maxAgentJSON borne le corps de toute requête d'agent qui n'est pas un envoi de SBOM
// (inscription, signal de vie…).
const maxAgentJSON = 64 << 10

// multipartOverhead s'ajoute à la taille admise d'un SBOM pour borner le corps multipart
// entier (partie context, en-têtes et délimiteurs).
const multipartOverhead = 1 << 20

// Pages de GET /agent/projects.
const (
	agentProjectsDefault = 100
	agentProjectsMax     = project.AgentPageMax
)

// AgentOptions réunit les dépendances de l'API des agents.
type AgentOptions struct {
	Agents  *agent.Service
	Ingest  *ingest.Service
	Catalog *locale.Catalog
	Logger  *slog.Logger
	// RateLimit borne les requêtes par minute et par jeton (0 : sans limite).
	RateLimit int
	// FailureRateLimit borne les jetons refusés par minute et par IP (0 : sans limite).
	FailureRateLimit int
	TrustedProxies   []string
	// RequireClientCert exige un certificat client vérifié (mTLS) sur toute l'API des
	// agents : vrai quand le TLS natif et tls.client_ca_file sont configurés. Le serveur
	// TLS vérifie un certificat présenté ; c'est ici que son absence est refusée, l'interface
	// web restant accessible sans certificat.
	RequireClientCert bool
	// ClientIP résout l'IP du client (mandataires de confiance compris).
	ClientIP func(*http.Request) string
}

// MountAgent monte les opérations de l'API des agents sur r, routeur de /api/v1 : corps
// borné, authentification par jeton, limitation par jeton, puis le serveur strict généré.
func MountAgent(r chi.Router, o AgentOptions) error {
	if o.Agents == nil || o.Ingest == nil || o.Catalog == nil || o.Logger == nil || o.ClientIP == nil {
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
		if o.RequireClientCert {
			r.Use(h.requireClientCert)
		}
		r.Use(limitBody(o.Ingest.Limits().MaxUpload+multipartOverhead), h.authenticate, perToken.Middleware)
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

// limitBody borne le corps de toute requête de l'API des agents : maxMultipart pour un
// envoi multipart (SBOM), maxAgentJSON pour tout autre corps.
func limitBody(maxMultipart int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := int64(maxAgentJSON)
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				limit = maxMultipart
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
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
		// Les handlers du serveur strict n'ont que le contexte : ils y trouvent la langue
		// de la requête pour traduire une clé d'erreur d'ingestion.
		ctx = locale.NewContext(ctx, middleware.Localizer(h.Catalog, r))
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, clientIPKey{}, h.ClientIP(r))))
	})
}

// KeyClientCertRequired : requête de l'API des agents sans certificat client vérifié,
// alors que le mTLS est exigé.
const KeyClientCertRequired = "error.client_cert_required"

// requireClientCert refuse, avant toute lecture du jeton, une requête dont la connexion
// n'a pas présenté de certificat client vérifié par tls.client_ca_file. Le refus passe par
// le limiteur des refus, par IP.
func (h *agentAPI) requireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			h.refuse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), refusalKey{}, KeyClientCertRequired)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *agentAPI) writeRefusal(w http.ResponseWriter, r *http.Request) {
	key, _ := r.Context().Value(refusalKey{}).(string)
	if key == "" {
		key = agent.KeyTokenInvalid
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="lotor"`)
	problem.Write(w, r, h.Catalog, http.StatusUnauthorized, key, nil)
}

// operationKinds associe chaque opération à la nature de jeton qu'elle exige.
var operationKinds = map[string]agent.TokenKind{
	"Enroll":            agent.KindEnrollment,
	"Heartbeat":         agent.KindAgent,
	"ListAgentProjects": agent.KindAgent,
	"CreateIngestion":   agent.KindAgent,
	"GetIngestion":      agent.KindAgent,
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
	case errors.Is(err, ingest.ErrRefUnknown):
		problem.Write(w, r, h.Catalog, http.StatusNotFound, ingest.KeyRefUnknown, nil)
	case errors.Is(err, ingest.ErrNotFound):
		problem.Write(w, r, h.Catalog, http.StatusNotFound, problem.KeyNotFound, nil)
	case errors.Is(err, ingest.ErrUploadTooLarge):
		problem.Write(w, r, h.Catalog, http.StatusRequestEntityTooLarge, sbom.KeyTooLarge, nil)
	case errors.Is(err, ingest.ErrQuota):
		w.Header().Set("Retry-After", "3600")
		problem.Write(w, r, h.Catalog, http.StatusTooManyRequests, ingest.KeyQuota, nil)
	case errors.Is(err, errMissingPart):
		problem.Write(w, r, h.Catalog, http.StatusBadRequest, ingest.KeyMissingPart, nil)
	case errors.As(err, new(*requestError)):
		h.badRequest(w, r, err)
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
	er := agent.EnrollRequest{Hostname: req.Body.Hostname, Version: req.Body.Version}
	if req.Body.Labels != nil {
		er.Labels = *req.Body.Labels
	}
	res, err := h.Agents.Enroll(ctx, p, er, ip,
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

// Heartbeat enregistre le signal de vie de l'agent, avec le compte rendu d'un scan sans
// changement et le contexte de l'hôte s'ils sont joints.
func (h *agentAPI) Heartbeat(ctx context.Context, req gen.HeartbeatRequestObject) (gen.HeartbeatResponseObject, error) {
	p, _ := principalFrom(ctx)
	hb := agent.HeartbeatRequest{Version: req.Body.Version, Host: hostContextOf(req.Body.Host)}
	if r := req.Body.Inventory; r != nil {
		fp, err := hex.DecodeString(r.Fingerprint)
		if err != nil || len(fp) != 32 || r.Fingerprint != strings.ToLower(r.Fingerprint) {
			return nil, &account.ValidationError{Field: "inventory", Key: agent.KeyInventoryInvalid}
		}
		hb.Inventory = &agent.InventoryReport{ProjectID: r.ProjectId, RefName: r.Ref.Name, ScannedAt: r.ScannedAt}
		copy(hb.Inventory.Fingerprint[:], fp)
	}
	res, err := h.Agents.Heartbeat(ctx, p, hb)
	if err != nil {
		return nil, err
	}
	out := gen.Heartbeat200JSONResponse{ScanRequested: res.ScanRequested, ServerTime: h.Agents.Now()}
	if res.Inventory != "" {
		st := gen.HeartbeatStatusInventory(res.Inventory)
		out.Inventory = &st
	}
	return out, nil
}

// hostContextOf convertit le contexte d'hôte du contrat.
func hostContextOf(c *gen.HostContext) *agent.HostContext {
	if c == nil {
		return nil
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	out := &agent.HostContext{Hostname: str(c.Hostname), OSID: str(c.OsId), OSVersion: str(c.OsVersion),
		OSName: str(c.OsName), Kernel: str(c.Kernel), Arch: str(c.Arch)}
	if c.ScanDurationMs != nil {
		out.ScanDuration = int64(*c.ScanDurationMs)
	}
	return out
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
	var refIDs []uuid.UUID
	for _, pr := range projects {
		for _, ref := range pr.Refs {
			refIDs = append(refIDs, ref.ID)
		}
	}
	current, err := h.Agents.CurrentSnapshots(ctx, p, refIDs)
	if err != nil {
		return nil, err
	}
	for _, pr := range projects {
		ap := gen.AgentProject{Id: pr.ID, Slug: pr.Slug, Name: pr.Name, Kind: gen.AgentProjectKind(pr.Kind),
			Labels: pr.Labels, Refs: make([]gen.TrackedRef, 0, len(pr.Refs))}
		if pr.ForgeURL != "" {
			ap.ForgeUrl = &pr.ForgeURL
		}
		for _, ref := range pr.Refs {
			tr := gen.TrackedRef{Id: ref.ID, Kind: gen.TrackedRefKind(ref.Kind), Name: ref.Name}
			if c, ok := current[ref.ID]; ok {
				tr.LastSnapshot = &gen.SnapshotRef{Id: c.SnapshotID, ScannedAt: c.ScannedAt}
				if c.Commit != "" {
					tr.LastSnapshot.Commit = &c.Commit
				}
			}
			ap.Refs = append(ap.Refs, tr)
		}
		out.Projects = append(out.Projects, ap)
	}
	return out, nil
}

type clientIPKey struct{}
