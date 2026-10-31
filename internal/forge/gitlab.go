package forge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GitLabConfig décrit une instance GitLab accédée par un compte de service.
type GitLabConfig struct {
	Name string
	// URL est l'URL web de l'instance (https://gitlab.com, ou https://hôte/sous-chemin).
	URL string
	// Token est le jeton d'accès du compte de service (portées read_api et
	// read_repository, rôle Reporter sur les projets suivis).
	Token         string
	WebhookSecret []byte
	HTTPClient    *http.Client
}

// GitLab est une instance GitLab.
type GitLab struct {
	cfg    GitLabConfig
	web    baseURL
	client *http.Client
}

var _ Provider = (*GitLab)(nil)

// NewGitLab valide la configuration d'une instance GitLab.
func NewGitLab(cfg GitLabConfig) (*GitLab, error) {
	if cfg.Name == "" {
		return nil, errors.New("forge: GitLab : nom manquant")
	}
	if cfg.URL == "" {
		cfg.URL = "https://gitlab.com"
	}
	web, err := parseBaseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, errors.New("forge: GitLab : jeton du compte de service obligatoire")
	}
	if len(cfg.WebhookSecret) == 0 {
		return nil, errors.New("forge: GitLab : secret de webhook obligatoire")
	}
	return &GitLab{cfg: cfg, web: web, client: defaultClient(cfg.HTTPClient)}, nil
}

// Name renvoie le nom de la forge.
func (g *GitLab) Name() string { return g.cfg.Name }

// Kind renvoie KindGitLab.
func (g *GitLab) Kind() Kind { return KindGitLab }

// Repo reconnaît https://hôte/groupe[/sous-groupe…]/projet (avec ou sans « .git » ou une
// partie « /-/… »).
func (g *GitLab) Repo(forgeURL string) (string, bool) {
	segs, ok := g.web.repoPath(forgeURL)
	if !ok || len(segs) < 2 {
		return "", false
	}
	return strings.Join(segs, "/"), true
}

// CloneURL renvoie https://hôte/groupe/projet.git.
func (g *GitLab) CloneURL(repo string) string { return g.web.String() + "/" + repo + ".git" }

// Credentials renvoie le jeton du compte de service ; GitLab accepte tout nom
// d'utilisateur non vide avec un jeton d'accès, « oauth2 » est l'usage documenté.
func (g *GitLab) Credentials(context.Context, string) (Credentials, error) {
	return Credentials{Username: "oauth2", Password: g.cfg.Token}, nil
}

// ResolveRef lit le commit d'une branche ou d'une étiquette.
func (g *GitLab) ResolveRef(ctx context.Context, repo string, ref Ref) (string, error) {
	kind := "branches"
	if ref.Kind == RefTag {
		kind = "tags"
	}
	var out struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	if err := g.get(ctx, g.project(repo)+"/repository/"+kind+"/"+url.PathEscape(ref.Name), &out); err != nil {
		return "", err
	}
	sha := strings.ToLower(out.Commit.ID)
	if !ValidCommit(sha) {
		return "", errors.New("forge: GitLab : commit illisible")
	}
	return sha, nil
}

// Compare liste les commits de base à head, du plus ancien au plus récent (ordre de
// l'API de comparaison de GitLab).
func (g *GitLab) Compare(ctx context.Context, repo, base, head string) (Comparison, error) {
	var out struct {
		Commits []struct {
			ID string `json:"id"`
		} `json:"commits"`
		Diffs []struct {
			NewPath string `json:"new_path"`
		} `json:"diffs"`
	}
	q := url.Values{"from": {base}, "to": {head}}
	if err := g.get(ctx, g.project(repo)+"/repository/compare?"+q.Encode(), &out); err != nil {
		return Comparison{}, err
	}
	var c Comparison
	for _, x := range out.Commits {
		c.Commits = append(c.Commits, strings.ToLower(x.ID))
	}
	for _, d := range out.Diffs {
		c.Files = append(c.Files, d.NewPath)
	}
	return c, nil
}

// VerifyWebhook compare X-Gitlab-Token au secret en temps constant : les deux valeurs
// sont hachées pour que la comparaison ne dépende pas non plus de leur longueur.
func (g *GitLab) VerifyWebhook(header http.Header, body []byte) (*Push, error) {
	got := header.Get("X-Gitlab-Token")
	if got == "" {
		return nil, ErrSignature
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256(g.cfg.WebhookSecret)
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return nil, ErrSignature
	}
	switch header.Get("X-Gitlab-Event") {
	case "Push Hook", "Tag Push Hook":
	default:
		return nil, nil
	}
	var p struct {
		Ref     string `json:"ref"`
		After   string `json:"after"`
		Project struct {
			PathWithNamespace string `json:"path_with_namespace"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrPayload, err)
	}
	ref, ok := ParseGitRef(p.Ref)
	if !ok || p.Project.PathWithNamespace == "" {
		return nil, ErrPayload
	}
	delivery := header.Get("X-Gitlab-Event-UUID")
	if delivery == "" {
		delivery = header.Get("Idempotency-Key")
	}
	return &Push{
		Delivery: delivery, Repo: p.Project.PathWithNamespace, Ref: ref,
		After: strings.ToLower(p.After), Deleted: zeroCommit(p.After),
	}, nil
}

// project renvoie le chemin d'API d'un projet, désigné par son chemin encodé.
func (g *GitLab) project(repo string) string { return "/projects/" + url.PathEscape(repo) }

func (g *GitLab) get(ctx context.Context, path string, out any) error {
	header := http.Header{
		"Private-Token": {g.cfg.Token},
		"Accept":        {"application/json"},
		"User-Agent":    {"lotor-repo-agent"},
	}
	return call(ctx, g.client, http.MethodGet, g.web.String()+"/api/v4"+path, header, nil, out)
}
