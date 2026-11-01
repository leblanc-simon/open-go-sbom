package agentclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient/gen"
)

// apiPrefix est le préfixe des routes de l'API (servers du contrat).
const apiPrefix = "/api/v1/"

// Délai par tentative par défaut : l'envoi d'un gros SBOM sur un lien lent doit passer.
const defaultTimeout = 2 * time.Minute

// Options règle un client.
type Options struct {
	// ServerURL est l'adresse du serveur (https://sbom.example.org), sans /api/v1.
	ServerURL string
	// Token est le jeton d'agent (lotor_agt_…) ; vide avant l'inscription (Enroll prend
	// son jeton d'inscription en paramètre).
	Token string
	// UserAgent identifie l'agent et sa version (lotor-host-agent/1.4.0).
	UserAgent string
	// Language demande les messages des erreurs dans cette langue (Accept-Language).
	Language string
	// TLS règle l'autorité de certification et le certificat client.
	TLS TLSOptions
	// Proxy est l'URL du mandataire HTTP(S) ; vide : HTTPS_PROXY et NO_PROXY de
	// l'environnement.
	Proxy string
	// Timeout borne chaque tentative, corps compris (défaut 2 min).
	Timeout time.Duration
	// Retry règle les réessais (défauts : DefaultRetry).
	Retry Retry
	// Logger reçoit les réessais (niveau Warn) ; nil : aucun journal.
	Logger *slog.Logger
	// Transport remplace le transport HTTP construit depuis TLS et Proxy (tests).
	Transport http.RoundTripper
}

// Client appelle l'API des agents. Il est sûr pour un usage concurrent.
type Client struct {
	opts  Options
	base  string // ServerURL + /api/v1/
	doer  *retryDoer
	gen   *gen.ClientWithResponses
	token string
}

// New construit un client. L'adresse doit être en https (l'agent ne parle qu'en HTTPS
// sortant), sauf pour un transport de test fourni par Options.Transport.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(opts.ServerURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || opts.Transport == nil)) {
		return nil, fmt.Errorf("agentclient: adresse du serveur invalide (https://hôte attendu) : %q", opts.ServerURL)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("agentclient: l'adresse du serveur ne prend ni requête, ni fragment, ni identifiants")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	opts.Retry = opts.Retry.withDefaults()
	transport := opts.Transport
	if transport == nil {
		if transport, err = newTransport(opts.TLS, opts.Proxy); err != nil {
			return nil, err
		}
	}
	c := &Client{
		opts:  opts,
		base:  strings.TrimSuffix(u.String(), "/") + apiPrefix,
		token: opts.Token,
		doer: &retryDoer{
			client: &http.Client{Transport: transport, Timeout: opts.Timeout, CheckRedirect: noRedirect},
			retry:  opts.Retry, logger: opts.Logger, sleep: sleepContext,
		},
	}
	if c.gen, err = gen.NewClientWithResponses(c.base, gen.WithHTTPClient(c.doer)); err != nil {
		return nil, fmt.Errorf("agentclient: %w", err)
	}
	return c, nil
}

// noRedirect refuse de suivre une redirection : le jeton ne part jamais vers une autre
// adresse que celle configurée.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// WithToken renvoie un client qui présente token, sur le même transport.
func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.token = token
	return &cp
}

// editor pose les en-têtes communs ; token remplace celui du client (inscription).
func (c *Client) editor(token string) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if token == "" {
			token = c.token
		}
		if token == "" {
			return ErrNoToken
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if c.opts.UserAgent != "" {
			req.Header.Set("User-Agent", c.opts.UserAgent)
		}
		if c.opts.Language != "" {
			req.Header.Set("Accept-Language", c.opts.Language)
		}
		return nil
	}
}

// ErrNoToken : appel sans jeton.
var ErrNoToken = errors.New("agentclient: aucun jeton")

// Enroll échange un jeton d'inscription contre l'identité de l'agent (agent serveur). Le
// jeton d'agent renvoyé n'est donné qu'une fois : l'appelant le conserve.
func (c *Client) Enroll(ctx context.Context, enrollmentToken string, req gen.EnrollRequest) (gen.EnrollmentResult, error) {
	if enrollmentToken == "" {
		return gen.EnrollmentResult{}, ErrNoToken
	}
	rsp, err := c.gen.EnrollWithResponse(withOp(ctx, "enroll"), req, c.editor(enrollmentToken))
	if err != nil {
		return gen.EnrollmentResult{}, wrapTransport("enroll", err)
	}
	if rsp.JSON201 == nil {
		return gen.EnrollmentResult{}, responseError("enroll", rsp.HTTPResponse, rsp.Body)
	}
	return *rsp.JSON201, nil
}

// Heartbeat envoie un signal de vie et renvoie l'état que le serveur indique (scan
// demandé, heure du serveur…).
func (c *Client) Heartbeat(ctx context.Context, req gen.HeartbeatRequest) (gen.HeartbeatStatus, error) {
	rsp, err := c.gen.HeartbeatWithResponse(withOp(ctx, "heartbeat"), req, c.editor(""))
	if err != nil {
		return gen.HeartbeatStatus{}, wrapTransport("heartbeat", err)
	}
	if rsp.JSON200 == nil {
		return gen.HeartbeatStatus{}, responseError("heartbeat", rsp.HTTPResponse, rsp.Body)
	}
	return *rsp.JSON200, nil
}

// ReportContainers signale les conteneurs qui tournent sur l'hôte de l'agent serveur et
// renvoie, pour chacun, son projet enfant et la réponse à son compte rendu d'inventaire.
func (c *Client) ReportContainers(ctx context.Context, req gen.ContainerReport) (gen.ContainerReportResult, error) {
	rsp, err := c.gen.ReportContainersWithResponse(withOp(ctx, "reportContainers"), req, c.editor(""))
	if err != nil {
		return gen.ContainerReportResult{}, wrapTransport("reportContainers", err)
	}
	if rsp.JSON200 == nil {
		return gen.ContainerReportResult{}, responseError("reportContainers", rsp.HTTPResponse, rsp.Body)
	}
	return *rsp.JSON200, nil
}

// maxProjectPages borne le parcours des projets confiés (200 par page).
const maxProjectPages = 500

// Projects renvoie tous les projets confiés à l'agent, page après page.
func (c *Client) Projects(ctx context.Context) ([]gen.AgentProject, error) {
	var out []gen.AgentProject
	limit := 200
	params := &gen.ListAgentProjectsParams{Limit: &limit}
	for range maxProjectPages {
		rsp, err := c.gen.ListAgentProjectsWithResponse(withOp(ctx, "listAgentProjects"), params, c.editor(""))
		if err != nil {
			return nil, wrapTransport("listAgentProjects", err)
		}
		if rsp.JSON200 == nil {
			return nil, responseError("listAgentProjects", rsp.HTTPResponse, rsp.Body)
		}
		out = append(out, rsp.JSON200.Projects...)
		next := rsp.JSON200.Page.NextCursor
		if next == nil || *next == "" {
			return out, nil
		}
		params.Cursor = next
	}
	return nil, fmt.Errorf("agentclient: listAgentProjects : plus de %d pages", maxProjectPages)
}

// Ingestion renvoie l'état d'une ingestion envoyée par l'agent.
func (c *Client) Ingestion(ctx context.Context, id uuid.UUID) (gen.Ingestion, error) {
	rsp, err := c.gen.GetIngestionWithResponse(withOp(ctx, "getIngestion"), id, c.editor(""))
	if err != nil {
		return gen.Ingestion{}, wrapTransport("getIngestion", err)
	}
	if rsp.JSON200 == nil {
		return gen.Ingestion{}, responseError("getIngestion", rsp.HTTPResponse, rsp.Body)
	}
	return *rsp.JSON200, nil
}

// Final indique si une ingestion a atteint son état final (done ou failed).
func Final(in gen.Ingestion) bool {
	return in.Status == gen.Done || in.Status == gen.Failed
}

// Wait interroge une ingestion jusqu'à son état final, toutes les poll au début puis
// à intervalle doublé jusqu'à 30 s ; ctx borne l'attente. Une ingestion déjà finale (in)
// est renvoyée sans requête.
func (c *Client) Wait(ctx context.Context, in gen.Ingestion, poll time.Duration) (gen.Ingestion, error) {
	if poll <= 0 {
		poll = time.Second
	}
	const maxPoll = 30 * time.Second
	for !Final(in) {
		if err := sleepContext(ctx, poll); err != nil {
			return in, fmt.Errorf("agentclient: attente de l'ingestion %s : %w", in.Id, err)
		}
		poll = min(2*poll, maxPoll)
		next, err := c.Ingestion(ctx, in.Id)
		if err != nil {
			return in, err
		}
		in = next
	}
	return in, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
