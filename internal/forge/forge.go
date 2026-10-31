package forge

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Kind est la nature d'une forge.
type Kind string

// Natures de forge prises en charge.
const (
	KindGitHub Kind = "github"
	KindGitLab Kind = "gitlab"
)

// RefKind est la nature d'une référence git suivie.
type RefKind string

// Natures de référence (celles de l'API des agents).
const (
	RefBranch RefKind = "branch"
	RefTag    RefKind = "tag"
)

// Ref est une référence git : branche ou étiquette.
type Ref struct {
	Kind RefKind
	Name string
}

// ParseGitRef lit une référence complète (refs/heads/main, refs/tags/v1.0).
func ParseGitRef(full string) (Ref, bool) {
	if name, ok := strings.CutPrefix(full, "refs/heads/"); ok && name != "" {
		return Ref{Kind: RefBranch, Name: name}, true
	}
	if name, ok := strings.CutPrefix(full, "refs/tags/"); ok && name != "" {
		return Ref{Kind: RefTag, Name: name}, true
	}
	return Ref{}, false
}

// Push est un webhook de push vérifié. Il ne sert que de signal : l'agent résout ensuite
// lui-même la tête de la référence auprès de la forge, si bien qu'un webhook rejoué ou
// en retard ne fait jamais analyser un commit dépassé.
type Push struct {
	// Delivery identifie la livraison (X-GitHub-Delivery, X-Gitlab-Event-UUID) ; vide si
	// la forge ne l'a pas fourni.
	Delivery string
	// Repo est le chemin du dépôt sur la forge (owner/name, group/sub/project).
	Repo string
	Ref  Ref
	// After est le commit annoncé (informatif) ; Deleted signale une référence supprimée.
	After   string
	Deleted bool
}

// Comparison est la différence entre deux commits d'une même histoire.
type Comparison struct {
	// Commits va du plus ancien au plus récent, base exclue, tête incluse.
	Commits []string
	// Files sont les chemins modifiés (bornés par la forge).
	Files []string
}

// Credentials sont les identifiants de clonage HTTP d'un dépôt. Ils se masquent à
// l'affichage pour qu'un journal ou un message d'erreur ne les révèle jamais.
type Credentials struct {
	Username string
	Password string
}

// String masque les identifiants.
func (Credentials) String() string { return "forge.Credentials{***}" }

// GoString masque les identifiants (%#v).
func (Credentials) GoString() string { return "forge.Credentials{***}" }

// Provider est une forge configurée.
type Provider interface {
	// Name est le nom donné à la forge dans la configuration (segment de l'URL de son
	// webhook).
	Name() string
	Kind() Kind
	// Repo renvoie le chemin du dépôt si l'URL de forge d'un projet désigne un dépôt de
	// cette forge.
	Repo(forgeURL string) (string, bool)
	// CloneURL est l'URL de clonage HTTP du dépôt, sans identifiants.
	CloneURL(repo string) string
	// Credentials donne les identifiants de clonage, valables au moins quelques minutes.
	Credentials(ctx context.Context, repo string) (Credentials, error)
	// ResolveRef donne le commit pointé par une référence.
	ResolveRef(ctx context.Context, repo string, ref Ref) (string, error)
	// Compare donne les commits de base (exclu) à head (inclus).
	Compare(ctx context.Context, repo, base, head string) (Comparison, error)
	// VerifyWebhook authentifie un webhook puis le lit. Un événement authentique sans
	// intérêt (ping, autre événement) donne (nil, nil) ; un webhook mal signé,
	// ErrSignature ; un corps illisible, ErrPayload.
	VerifyWebhook(header http.Header, body []byte) (*Push, error)
}

// Erreurs communes aux forges.
var (
	ErrSignature = errors.New("forge: signature de webhook invalide")
	ErrPayload   = errors.New("forge: webhook illisible")
	ErrNotFound  = errors.New("forge: dépôt ou référence introuvable")
	ErrDenied    = errors.New("forge: accès refusé")
)

// commitPattern est un commit SHA-1 ou SHA-256 en hexadécimal.
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// ValidCommit indique si s est un commit complet en hexadécimal minuscule.
func ValidCommit(s string) bool { return commitPattern.MatchString(s) }

// zeroCommit indique un commit nul (référence créée ou supprimée).
func zeroCommit(s string) bool { return s != "" && strings.Trim(s, "0") == "" }

// baseURL est l'URL web d'une forge, normalisée : schéma http(s), hôte, chemin sans « / »
// final (une instance GitLab peut être servie sous un sous-chemin).
type baseURL struct {
	scheme string
	host   string
	path   string
}

func parseBaseURL(raw string) (baseURL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return baseURL{}, errors.New("forge: URL de forge invalide (http(s)://hôte[/chemin] attendu)")
	}
	return baseURL{scheme: u.Scheme, host: strings.ToLower(u.Host), path: strings.TrimRight(u.Path, "/")}, nil
}

func (b baseURL) String() string { return b.scheme + "://" + b.host + b.path }

// repoPath extrait le chemin d'un dépôt d'une URL de projet de cette forge : même schéma
// et même hôte, sous le chemin de base, sans « .git » ni partie « /-/… » (GitLab).
func (b baseURL) repoPath(forgeURL string) ([]string, bool) {
	u, err := url.Parse(strings.TrimSpace(forgeURL))
	if err != nil || u.Scheme != b.scheme || !strings.EqualFold(u.Host, b.host) || u.User != nil {
		return nil, false
	}
	rest, ok := strings.CutPrefix(u.Path, b.path+"/")
	if !ok {
		return nil, false
	}
	if before, _, found := strings.Cut(rest, "/-/"); found {
		rest = before
	}
	rest = strings.TrimSuffix(strings.Trim(rest, "/"), ".git")
	segs := strings.Split(rest, "/")
	for _, s := range segs {
		if !validSegment(s) {
			return nil, false
		}
	}
	return segs, true
}

// validSegment accepte un segment de chemin de dépôt : lettres, chiffres, « - », « _ »
// et « . », sans « . » ni « .. » seuls.
func validSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// SameRepo compare deux chemins de dépôt sans tenir compte de la casse, comme GitHub et
// GitLab.
func SameRepo(a, b string) bool { return strings.EqualFold(a, b) }

// escapeRef encode un nom de référence segment par segment (les « / » d'une branche
// restent des séparateurs, comme l'attend l'API de GitHub).
func escapeRef(name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
