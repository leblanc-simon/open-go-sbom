package repoagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/agentclient/gen"
	"leblanc.io/lotor/internal/forge"
)

// apiServer est l'implémentation de Server sur l'API des agents, par le client commun
// d'internal/agentclient : réessais bornés (erreurs réseau, 429, 5xx, Retry-After),
// autorité privée, mTLS facultatif, envoi gzip.
type apiServer struct {
	client *agentclient.Client
}

var _ Server = (*apiServer)(nil)

// ServerOptions complète ServerConfig.
type ServerOptions struct {
	// Version de l'agent, annoncée dans l'en-tête User-Agent.
	Version string
	Logger  *slog.Logger
	// Transport remplace le transport HTTPS (tests contre un serveur HTTP local).
	Transport http.RoundTripper
}

// NewServer prépare le client de l'API des agents à partir de la configuration et du
// jeton d'agent. La clé du certificat client est un secret (credential:<nom> ou fichier en
// 0600), vérifié comme les autres.
func NewServer(cfg ServerConfig, token string, o ServerOptions) (Server, error) {
	tlsOpts := agentclient.TLSOptions{CAFile: cfg.CAFile, ClientCertFile: cfg.ClientCertFile}
	if cfg.ClientKeyFile != "" {
		if _, err := ReadSecret(cfg.ClientKeyFile); err != nil {
			return nil, fmt.Errorf("repoagent: clé du certificat client : %w", err)
		}
		path, err := secretPath(cfg.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsOpts.ClientKeyFile = path
	}
	c, err := agentclient.New(agentclient.Options{
		ServerURL: cfg.URL, Token: token, UserAgent: "lotor-repo-agent/" + o.Version, TLS: tlsOpts,
		Proxy: cfg.Proxy, Timeout: cfg.Timeout, Logger: o.Logger, Transport: o.Transport,
		Retry: agentclient.Retry{Attempts: cfg.Retries, Base: 2 * time.Second, Max: 5 * time.Minute},
	})
	if err != nil {
		return nil, fmt.Errorf("repoagent: client de l'API : %w", err)
	}
	return &apiServer{client: c}, nil
}

// Projects lit toutes les pages des projets confiés et garde les dépôts.
func (s *apiServer) Projects(ctx context.Context) ([]Project, error) {
	projects, err := s.client.Projects(ctx)
	if err != nil {
		return nil, fmt.Errorf("repoagent: projets confiés : %w", err)
	}
	var out []Project
	for _, p := range projects {
		if p.Kind != gen.AgentProjectKindRepo || p.ForgeUrl == nil {
			continue
		}
		proj := Project{ID: p.Id.String(), Slug: p.Slug, ForgeURL: *p.ForgeUrl}
		for _, r := range p.Refs {
			tr := TrackedRef{Ref: forge.Ref{Kind: forge.RefKind(r.Kind), Name: r.Name}}
			if r.LastSnapshot != nil && r.LastSnapshot.Commit != nil {
				tr.LastCommit = strings.ToLower(*r.LastSnapshot.Commit)
			}
			proj.Refs = append(proj.Refs, tr)
		}
		out = append(out, proj)
	}
	return out, nil
}

// Heartbeat envoie le signal de vie.
func (s *apiServer) Heartbeat(ctx context.Context, version string) error {
	if _, err := s.client.Heartbeat(ctx, gen.HeartbeatRequest{Version: version}); err != nil {
		return fmt.Errorf("repoagent: signal de vie : %w", err)
	}
	return nil
}

// Upload envoie le SBOM (partie context puis sbom en gzip, réessais compris). Un refus du
// serveur autre que 429 ou 5xx (référence inconnue, trop gros, contexte invalide, jeton
// refusé) est définitif : l'erreur enveloppe ErrRejected et porte la clé du problème.
func (s *apiServer) Upload(ctx context.Context, u Upload) error {
	pid, err := uuid.Parse(u.ProjectID)
	if err != nil {
		return fmt.Errorf("repoagent: projet %q : %w", u.ProjectID, err)
	}
	ic := gen.IngestionContext{ProjectId: pid, AgentVersion: u.AgentVersion, Commit: &u.Commit, ScannedAt: u.ScannedAt}
	ic.Ref.Kind, ic.Ref.Name = gen.IngestionContextRefKind(u.Ref.Kind), u.Ref.Name
	if _, err := s.client.Upload(ctx, ic, u.SBOM); err != nil {
		var e *agentclient.Error
		if errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests {
			return fmt.Errorf("%w : statut %d %s", ErrRejected, e.Status, printable(e.Key))
		}
		return fmt.Errorf("repoagent: envoi : %w", err)
	}
	return nil
}
