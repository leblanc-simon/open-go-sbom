package forge

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHubConfig décrit une GitHub App (github.com ou GitHub Enterprise Server).
type GitHubConfig struct {
	Name string
	// URL est l'URL web de la forge (https://github.com), à laquelle les URL de forge des
	// projets sont comparées ; APIURL celle de l'API (https://api.github.com, ou
	// https://hôte/api/v3 pour GitHub Enterprise Server).
	URL    string
	APIURL string
	// AppID est l'identifiant de l'application ou son « client ID » (émetteur du JWT).
	AppID      string
	PrivateKey *rsa.PrivateKey
	// InstallationID fixe l'installation ; à zéro, elle est cherchée pour chaque dépôt.
	InstallationID int64
	WebhookSecret  []byte
	HTTPClient     *http.Client
	// Now remplace l'horloge (tests).
	Now func() time.Time
}

// tokenMargin : un jeton d'installation (valable une heure) est renouvelé cinq minutes
// avant son expiration, pour qu'un clonage en cours ne le voie pas expirer.
const tokenMargin = 5 * time.Minute

type installationToken struct {
	value   string
	expires time.Time
}

// GitHub est une forge GitHub accédée par une GitHub App.
type GitHub struct {
	cfg    GitHubConfig
	web    baseURL
	api    string
	client *http.Client
	now    func() time.Time

	mu            sync.Mutex
	installations map[string]int64             // dépôt (minuscules) → installation
	tokens        map[string]installationToken // dépôt (minuscules) → jeton restreint à lui
}

var _ Provider = (*GitHub)(nil)

// NewGitHub valide la configuration d'une GitHub App.
func NewGitHub(cfg GitHubConfig) (*GitHub, error) {
	if cfg.Name == "" {
		return nil, errors.New("forge: GitHub : nom manquant")
	}
	if cfg.URL == "" {
		cfg.URL = "https://github.com"
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	web, err := parseBaseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	api, err := parseBaseURL(cfg.APIURL)
	if err != nil {
		return nil, fmt.Errorf("forge: GitHub : URL d'API : %w", err)
	}
	if cfg.AppID == "" || cfg.PrivateKey == nil {
		return nil, errors.New("forge: GitHub : identifiant d'application et clé privée obligatoires")
	}
	if len(cfg.WebhookSecret) == 0 {
		return nil, errors.New("forge: GitHub : secret de webhook obligatoire")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &GitHub{
		cfg: cfg, web: web, api: api.String(), client: defaultClient(cfg.HTTPClient), now: now,
		installations: map[string]int64{}, tokens: map[string]installationToken{},
	}, nil
}

// Name renvoie le nom de la forge.
func (g *GitHub) Name() string { return g.cfg.Name }

// Kind renvoie KindGitHub.
func (g *GitHub) Kind() Kind { return KindGitHub }

// Repo reconnaît https://github.com/owner/name (avec ou sans « .git »).
func (g *GitHub) Repo(forgeURL string) (string, bool) {
	segs, ok := g.web.repoPath(forgeURL)
	if !ok || len(segs) != 2 {
		return "", false
	}
	return segs[0] + "/" + segs[1], true
}

// CloneURL renvoie https://github.com/owner/name.git.
func (g *GitHub) CloneURL(repo string) string { return g.web.String() + "/" + repo + ".git" }

// Credentials renvoie le jeton d'installation, avec l'utilisateur que GitHub attend pour
// un clonage HTTP par une application.
func (g *GitHub) Credentials(ctx context.Context, repo string) (Credentials, error) {
	tok, err := g.token(ctx, repo)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{Username: "x-access-token", Password: tok}, nil
}

// ResolveRef lit le commit d'une branche ou d'une étiquette (une étiquette annotée est
// déréférencée jusqu'à son commit par l'API).
func (g *GitHub) ResolveRef(ctx context.Context, repo string, ref Ref) (string, error) {
	prefix := "heads/"
	if ref.Kind == RefTag {
		prefix = "tags/"
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := g.get(ctx, repo, "/repos/"+repo+"/commits/"+prefix+escapeRef(ref.Name), &out); err != nil {
		return "", err
	}
	sha := strings.ToLower(out.SHA)
	if !ValidCommit(sha) {
		return "", errors.New("forge: GitHub : commit illisible")
	}
	return sha, nil
}

// Compare liste les commits de base à head. GitHub les donne du plus ancien au plus
// récent, 250 au plus : au-delà, l'agent n'analyse que les plus récents de toute façon.
func (g *GitHub) Compare(ctx context.Context, repo, base, head string) (Comparison, error) {
	var out struct {
		Commits []struct {
			SHA string `json:"sha"`
		} `json:"commits"`
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if err := g.get(ctx, repo, "/repos/"+repo+"/compare/"+base+"..."+head, &out); err != nil {
		return Comparison{}, err
	}
	var c Comparison
	for _, x := range out.Commits {
		c.Commits = append(c.Commits, strings.ToLower(x.SHA))
	}
	for _, f := range out.Files {
		c.Files = append(c.Files, f.Filename)
	}
	return c, nil
}

// VerifyWebhook vérifie X-Hub-Signature-256 (HMAC-SHA256 du corps), en temps constant,
// avant toute lecture du corps.
func (g *GitHub) VerifyWebhook(header http.Header, body []byte) (*Push, error) {
	sig, ok := strings.CutPrefix(header.Get("X-Hub-Signature-256"), "sha256=")
	if !ok {
		return nil, ErrSignature
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return nil, ErrSignature
	}
	mac := hmac.New(sha256.New, g.cfg.WebhookSecret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return nil, ErrSignature
	}
	if header.Get("X-GitHub-Event") != "push" {
		return nil, nil
	}
	var p struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrPayload, err)
	}
	ref, ok := ParseGitRef(p.Ref)
	if !ok || p.Repository.FullName == "" {
		return nil, ErrPayload
	}
	return &Push{
		Delivery: header.Get("X-GitHub-Delivery"), Repo: p.Repository.FullName, Ref: ref,
		After: strings.ToLower(p.After), Deleted: p.Deleted || zeroCommit(p.After),
	}, nil
}

// get appelle l'API avec le jeton d'installation du dépôt.
func (g *GitHub) get(ctx context.Context, repo, path string, out any) error {
	tok, err := g.token(ctx, repo)
	if err != nil {
		return err
	}
	return call(ctx, g.client, http.MethodGet, g.api+path, g.headers("Bearer "+tok), nil, out)
}

func (g *GitHub) headers(auth string) http.Header {
	return http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
		"Authorization":        {auth},
		"User-Agent":           {"lotor-repo-agent"},
	}
}

// token renvoie un jeton d'installation valable, limité à la lecture du contenu
// (« contents: read » ; « metadata: read » est toujours accordé par GitHub) et au seul
// dépôt repo, et le met en cache par dépôt jusqu'à peu avant son expiration. Un jeton qui
// fuit (il passe dans l'environnement de git) n'ouvre ainsi qu'un dépôt, pas toute
// l'installation (SEC-10).
func (g *GitHub) token(ctx context.Context, repo string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, err := g.installation(ctx, repo)
	if err != nil {
		return "", err
	}
	key := strings.ToLower(repo)
	if t, ok := g.tokens[key]; ok && g.now().Add(tokenMargin).Before(t.expires) {
		return t.value, nil
	}
	_, name, ok := strings.Cut(repo, "/")
	if !ok || name == "" {
		return "", fmt.Errorf("forge: GitHub : dépôt %q invalide", repo)
	}
	jwt, err := appJWT(g.cfg.PrivateKey, g.cfg.AppID, g.now())
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	body := map[string]any{"permissions": map[string]string{"contents": "read"}, "repositories": []string{name}}
	path := "/app/installations/" + strconv.FormatInt(id, 10) + "/access_tokens"
	if err := call(ctx, g.client, http.MethodPost, g.api+path, g.headers("Bearer "+jwt), body, &out); err != nil {
		if errors.Is(err, ErrNotFound) && g.cfg.InstallationID == 0 {
			delete(g.installations, strings.ToLower(repo))
		}
		return "", fmt.Errorf("forge: GitHub : jeton d'installation : %w", err)
	}
	if out.Token == "" || out.ExpiresAt.IsZero() {
		return "", errors.New("forge: GitHub : jeton d'installation illisible")
	}
	g.tokens[key] = installationToken{value: out.Token, expires: out.ExpiresAt}
	return out.Token, nil
}

// installation renvoie l'installation de l'application sur le dépôt (verrou tenu).
func (g *GitHub) installation(ctx context.Context, repo string) (int64, error) {
	if g.cfg.InstallationID != 0 {
		return g.cfg.InstallationID, nil
	}
	key := strings.ToLower(repo)
	if id, ok := g.installations[key]; ok {
		return id, nil
	}
	jwt, err := appJWT(g.cfg.PrivateKey, g.cfg.AppID, g.now())
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := call(ctx, g.client, http.MethodGet, g.api+"/repos/"+repo+"/installation", g.headers("Bearer "+jwt), nil, &out); err != nil {
		return 0, fmt.Errorf("forge: GitHub : installation de l'application : %w", err)
	}
	if out.ID <= 0 {
		return 0, errors.New("forge: GitHub : installation illisible")
	}
	g.installations[key] = out.ID
	return out.ID, nil
}
