package repoagent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	"leblanc.io/open-go-sbom/internal/agentclient/gen"
	"leblanc.io/open-go-sbom/internal/forge"
)

// maxPages borne la lecture paginée des projets confiés (200 par page).
const maxPages = 500

// APIServer est l'implémentation de Server sur l'API des agents, par le client généré.
//
// Adaptateur minimal, à remplacer par le client commun d'internal/agentclient (T07 :
// réessais bornés, délai exponentiel, Retry-After, mTLS) dès qu'il est fusionné : ici,
// aucune requête n'est retentée, le rattrapage suivant refait le travail perdu.
type APIServer struct {
	client *gen.ClientWithResponses
	token  string
}

var _ Server = (*APIServer)(nil)

// NewAPIServer prépare le client de l'API des agents. caFile (facultatif) remplace les
// autorités du système pour vérifier le certificat du serveur.
func NewAPIServer(cfg ServerConfig, token string) (*APIServer, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pemCA, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("repoagent: autorité du serveur : %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemCA) {
			return nil, errors.New("repoagent: autorité du serveur : aucun certificat PEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	httpClient := &http.Client{Timeout: cfg.Timeout, Transport: transport}
	c, err := gen.NewClientWithResponses(strings.TrimRight(cfg.URL, "/")+"/api/v1", gen.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("repoagent: client de l'API : %w", err)
	}
	return &APIServer{client: c, token: token}, nil
}

func (s *APIServer) auth(_ context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("User-Agent", "ogsbom-repo-agent")
	return nil
}

// Projects lit toutes les pages des projets confiés et garde les dépôts.
func (s *APIServer) Projects(ctx context.Context) ([]Project, error) {
	var out []Project
	var cursor *string
	limit := 200
	for range maxPages {
		resp, err := s.client.ListAgentProjectsWithResponse(ctx, &gen.ListAgentProjectsParams{Cursor: cursor, Limit: &limit}, s.auth)
		if err != nil {
			return nil, fmt.Errorf("repoagent: projets confiés : %w", err)
		}
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("repoagent: projets confiés : statut %d", resp.StatusCode())
		}
		for _, p := range resp.JSON200.Projects {
			if p.Kind != gen.AgentProjectKind("repo") || p.ForgeUrl == nil {
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
		cursor = resp.JSON200.Page.NextCursor
		if cursor == nil {
			return out, nil
		}
	}
	return nil, errors.New("repoagent: projets confiés : trop de pages")
}

// Heartbeat envoie le signal de vie.
func (s *APIServer) Heartbeat(ctx context.Context, version string) error {
	resp, err := s.client.HeartbeatWithResponse(ctx, gen.HeartbeatRequest{Version: version}, s.auth)
	if err != nil {
		return fmt.Errorf("repoagent: signal de vie : %w", err)
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("repoagent: signal de vie : statut %d", resp.StatusCode())
	}
	return nil
}

// Upload envoie le SBOM compressé en gzip : partie « context » puis « sbom ».
func (s *APIServer) Upload(ctx context.Context, u Upload) error {
	body, contentType, err := uploadBody(u)
	if err != nil {
		return err
	}
	// Appel brut : seuls le statut et, en cas de refus, la clé d'erreur comptent.
	resp, err := s.client.CreateIngestionWithBody(ctx, contentType, body, s.auth)
	if err != nil {
		return fmt.Errorf("repoagent: envoi : %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch code := resp.StatusCode; {
	case code == http.StatusOK || code == http.StatusAccepted:
		return nil
	case code == http.StatusTooManyRequests || code >= 500:
		return fmt.Errorf("repoagent: envoi : statut %d", code)
	default:
		return fmt.Errorf("%w : statut %d %s", ErrRejected, code, problemType(raw))
	}
}

// problemType extrait la clé d'une réponse RFC 9457, sans le reste du corps.
func problemType(body []byte) string {
	var p struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(body, &p) != nil {
		return ""
	}
	return printable(p.Type)
}

func uploadBody(u Upload) (*bytes.Buffer, string, error) {
	ictx := gen.IngestionContext{
		AgentVersion: u.AgentVersion, Commit: &u.Commit, ScannedAt: u.ScannedAt,
	}
	if err := ictx.ProjectId.UnmarshalText([]byte(u.ProjectID)); err != nil {
		return nil, "", fmt.Errorf("repoagent: projet %q : %w", u.ProjectID, err)
	}
	ictx.Ref.Kind = gen.IngestionContextRefKind(u.Ref.Kind)
	ictx.Ref.Name = u.Ref.Name
	rawCtx, err := json.Marshal(ictx)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="context"`)
	h.Set("Content-Type", "application/json")
	w, err := mw.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := w.Write(rawCtx); err != nil {
		return nil, "", err
	}
	h = textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="sbom"; filename="sbom.json.gz"`)
	h.Set("Content-Type", "application/gzip")
	if w, err = mw.CreatePart(h); err != nil {
		return nil, "", err
	}
	zw := gzip.NewWriter(w)
	if _, err := zw.Write(u.SBOM); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return &buf, mw.FormDataContentType(), nil
}
