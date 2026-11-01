package repoagent

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"leblanc.io/open-go-base/appconf"

	"leblanc.io/lotor/internal/forge"
)

// EnvPrefix préfixe les variables d'environnement de l'agent dépôt.
const EnvPrefix = "LOTOR_REPO_"

// Config est la configuration de lotor-repo-agent. Aucun secret n'y figure : jeton
// d'agent, clé privée de la GitHub App, jetons des comptes de service et secrets de
// webhook sont désignés par « credential:nom » (credentials systemd) ou par le chemin d'un
// fichier en 0600 (ReadSecret).
type Config struct {
	Logging appconf.Logging `yaml:"logging" env-prefix:"LOTOR_REPO_"`
	Server  ServerConfig    `yaml:"server"  env-prefix:"LOTOR_REPO_"`
	Webhook WebhookConfig   `yaml:"webhook" env-prefix:"LOTOR_REPO_"`
	Work    WorkConfig      `yaml:"work"    env-prefix:"LOTOR_REPO_"`
	Catchup CatchupConfig   `yaml:"catchup" env-prefix:"LOTOR_REPO_"`
	Status  StatusConfig    `yaml:"status"  env-prefix:"LOTOR_REPO_"`
	// Forges ne se déclarent que dans le fichier de configuration.
	Forges []Forge `yaml:"forges"`
}

// ServerConfig décrit le serveur lotor et le jeton d'agent.
type ServerConfig struct {
	URL       string        `yaml:"url"        env:"SERVER_URL"        env-description:"URL of the lotor server (https://sbom.example.org)"`
	TokenFile string        `yaml:"token_file" env:"SERVER_TOKEN_FILE" env-default:"credential:agent-token" env-description:"Agent token: credential:<name> (systemd credential) or absolute path of a 0600 file"`
	CAFile    string        `yaml:"ca_file"    env:"SERVER_CA_FILE"    env-description:"PEM file of the authority that signed the server certificate (system roots if empty)"`
	Timeout   time.Duration `yaml:"timeout"    env:"SERVER_TIMEOUT"    env-default:"2m"  env-description:"Maximum duration of one request to the server (SBOM upload included)"`
	// ClientCertFile et ClientKeyFile : certificat client du mTLS (la clé est un secret :
	// credential:<nom> ou fichier en 0600).
	ClientCertFile string `yaml:"client_cert_file" env:"SERVER_CLIENT_CERT_FILE" env-description:"Client certificate (PEM) for mTLS"`
	ClientKeyFile  string `yaml:"client_key_file"  env:"SERVER_CLIENT_KEY_FILE"  env-description:"Client certificate key for mTLS: credential:<name> or absolute path of a 0600 file"`
	Proxy          string `yaml:"proxy"            env:"SERVER_PROXY"            env-description:"HTTP(S) proxy URL (default: HTTPS_PROXY and NO_PROXY)"`
	Retries        int    `yaml:"retries"          env:"SERVER_RETRIES"          env-default:"5" env-description:"Attempts of one request (network errors, 429, 5xx; Retry-After honoured)"`
}

// WebhookConfig décrit le récepteur de webhooks, exposé aux forges.
type WebhookConfig struct {
	Listen         string   `yaml:"listen"          env:"WEBHOOK_LISTEN"          env-default:":8080" env-description:"Listen address of the webhook receiver (POST /webhooks/<forge>); empty: no receiver, catch-up only"`
	TLSCertFile    string   `yaml:"tls_cert_file"   env:"WEBHOOK_TLS_CERT_FILE"   env-description:"PEM certificate for native TLS (otherwise behind a TLS reverse proxy)"`
	TLSKeyFile     string   `yaml:"tls_key_file"    env:"WEBHOOK_TLS_KEY_FILE"    env-description:"Private key for native TLS: credential:<name> or absolute path of a 0600 file"`
	MaxBodyKiB     int      `yaml:"max_body_kib"    env:"WEBHOOK_MAX_BODY_KIB"    env-default:"1024" env-description:"Maximum webhook body size, in KiB"`
	RateLimit      int      `yaml:"rate_limit"      env:"WEBHOOK_RATE_LIMIT"      env-default:"120"  env-description:"Webhook requests per minute and per IP (0: unlimited)"`
	TrustedProxies []string `yaml:"trusted_proxies" env:"WEBHOOK_TRUSTED_PROXIES" env-separator:"," env-description:"Reverse proxies (IP or CIDR) whose X-Forwarded-For is trusted for rate limiting"`
}

// WorkConfig borne le travail d'analyse.
type WorkConfig struct {
	Dir          string        `yaml:"dir"           env:"WORK_DIR"           env-default:"/var/lib/lotor-repo-agent/work" env-description:"Working directory: one subdirectory per analysis, always removed"`
	Parallelism  int           `yaml:"parallelism"   env:"WORK_PARALLELISM"   env-default:"2"    env-description:"Analyses run at the same time"`
	QueueSize    int           `yaml:"queue_size"    env:"WORK_QUEUE_SIZE"    env-default:"1000" env-description:"Maximum references waiting for analysis (in memory, deduplicated)"`
	CloneTimeout time.Duration `yaml:"clone_timeout" env:"WORK_CLONE_TIMEOUT" env-default:"10m"  env-description:"Maximum duration of a clone"`
	ScanTimeout  time.Duration `yaml:"scan_timeout"  env:"WORK_SCAN_TIMEOUT"  env-default:"15m"  env-description:"Maximum duration of a Syft scan"`
	MaxCloneMiB  int           `yaml:"max_clone_mib" env:"WORK_MAX_CLONE_MIB" env-default:"1024" env-description:"Maximum size of a clone on disk, in MiB"`
	Git          string        `yaml:"git"           env:"WORK_GIT"           env-default:"git"  env-description:"git binary"`
}

// CatchupConfig règle le rattrapage : au démarrage puis à intervalle, chaque référence suivie
// est comparée au dernier commit connu du serveur.
type CatchupConfig struct {
	Interval   time.Duration `yaml:"interval"    env:"CATCHUP_INTERVAL"    env-default:"15m" env-description:"Interval between two catch-up passes"`
	MaxCommits int           `yaml:"max_commits" env:"CATCHUP_MAX_COMMITS" env-default:"20"  env-description:"Maximum missed commits analysed per reference (the most recent ones)"`
}

// Forge décrit une forge. GitHub : app_id, private_key_file et facultativement
// installation_id ; GitLab : token_file. AllowedNamespaces borne les dépôts que l'agent
// accepte d'analyser (propriétaires GitHub, groupes GitLab, « * » pour tous) : le choix
// des dépôts vient du serveur, c'est-à-dire des administrateurs d'organisation ; c'est à
// l'exploitant de l'agent de dire ce que ses identifiants peuvent lire pour eux (SEC-10).
type Forge struct {
	Name              string        `yaml:"name"`
	AllowedNamespaces []string      `yaml:"allowed_namespaces"`
	Kind              forge.Kind    `yaml:"kind"`
	URL               string        `yaml:"url"`
	APIURL            string        `yaml:"api_url"`
	AppID             string        `yaml:"app_id"`
	InstallationID    int64         `yaml:"installation_id"`
	PrivateKeyFile    string        `yaml:"private_key_file"`
	TokenFile         string        `yaml:"token_file"`
	WebhookSecretFile string        `yaml:"webhook_secret_file"`
	Timeout           time.Duration `yaml:"timeout"`
}

// Defaults renvoie les valeurs posées avant le chargement.
func Defaults() Config {
	var c Config
	c.Logging.Level = "info"
	return c
}

// Load lit la configuration (fichier -c s'il existe, sinon environnement ; --help et
// --version terminent le programme), puis la valide.
func Load(name, version, defaultPath string) (Config, error) {
	cfg := Defaults()
	if err := appconf.Load(&cfg, appconf.Options{Name: name, Version: version, DefaultCfgPath: defaultPath}); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

// Plafonds de configuration.
const (
	maxParallelism = 64
	maxQueue       = 100_000
	maxCommits     = 250
	maxBodyKiB     = 25 << 10 // 25 Mio : la limite des webhooks de GitHub
)

var forgeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate vérifie la configuration, sans lire les secrets.
func (c Config) Validate() error {
	var errs []error
	if err := validServerURL(c.Server.URL); err != nil {
		errs = append(errs, err)
	}
	if c.Server.TokenFile == "" {
		errs = append(errs, errors.New("server.token_file obligatoire"))
	}
	if (c.Server.ClientCertFile == "") != (c.Server.ClientKeyFile == "") {
		errs = append(errs, errors.New("server.client_cert_file et server.client_key_file vont ensemble"))
	}
	if c.Server.Retries < 1 || c.Server.Retries > 20 {
		errs = append(errs, errors.New("server.retries : entre 1 et 20"))
	}
	if c.Server.Timeout <= 0 {
		errs = append(errs, errors.New("server.timeout doit être positif"))
	}
	if c.Webhook.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Webhook.Listen); err != nil {
			errs = append(errs, fmt.Errorf("webhook.listen : %w", err))
		}
	}
	if (c.Webhook.TLSCertFile == "") != (c.Webhook.TLSKeyFile == "") {
		errs = append(errs, errors.New("webhook.tls_cert_file et webhook.tls_key_file vont ensemble"))
	}
	if c.Webhook.MaxBodyKiB < 1 || c.Webhook.MaxBodyKiB > maxBodyKiB {
		errs = append(errs, fmt.Errorf("webhook.max_body_kib entre 1 et %d", maxBodyKiB))
	}
	if c.Webhook.RateLimit < 0 {
		errs = append(errs, errors.New("webhook.rate_limit négatif"))
	}
	if c.Work.Dir == "" || !strings.HasPrefix(c.Work.Dir, "/") {
		errs = append(errs, errors.New("work.dir : chemin absolu attendu"))
	}
	if c.Work.Parallelism < 1 || c.Work.Parallelism > maxParallelism {
		errs = append(errs, fmt.Errorf("work.parallelism entre 1 et %d", maxParallelism))
	}
	if c.Work.QueueSize < 1 || c.Work.QueueSize > maxQueue {
		errs = append(errs, fmt.Errorf("work.queue_size entre 1 et %d", maxQueue))
	}
	if c.Status.Enabled && (c.Status.Context == "" || len(c.Status.Context) > 100 || c.Status.Timeout <= 0 ||
		c.Status.Timeout > 2*time.Hour || c.Status.Poll <= 0) {
		errs = append(errs, errors.New("status : context de 1 à 100 caractères, timeout dans ]0, 2h], poll positif"))
	}
	if c.Work.CloneTimeout <= 0 || c.Work.ScanTimeout <= 0 {
		errs = append(errs, errors.New("work.clone_timeout et work.scan_timeout doivent être positifs"))
	}
	if c.Work.MaxCloneMiB < 1 {
		errs = append(errs, errors.New("work.max_clone_mib doit être positif"))
	}
	if c.Work.Git == "" {
		errs = append(errs, errors.New("work.git obligatoire"))
	}
	if c.Catchup.Interval < time.Minute {
		errs = append(errs, errors.New("catchup.interval : une minute au moins"))
	}
	if c.Catchup.MaxCommits < 1 || c.Catchup.MaxCommits > maxCommits {
		errs = append(errs, fmt.Errorf("catchup.max_commits entre 1 et %d", maxCommits))
	}
	if len(c.Forges) == 0 {
		errs = append(errs, errors.New("forges : au moins une forge"))
	}
	seen := map[string]bool{}
	for i, f := range c.Forges {
		if err := f.validate(); err != nil {
			errs = append(errs, fmt.Errorf("forges[%d] : %w", i, err))
		}
		if seen[f.Name] {
			errs = append(errs, fmt.Errorf("forges[%d] : nom %q en double", i, f.Name))
		}
		seen[f.Name] = true
	}
	return errors.Join(errs...)
}

func validServerURL(s string) error {
	u, err := url.Parse(s)
	if s == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("server.url : URL https absolue sans identifiants attendue (l'agent ne parle qu'en HTTPS)")
	}
	return nil
}

func (f Forge) validate() error {
	if !forgeName.MatchString(f.Name) {
		return errors.New("name : minuscules, chiffres et tirets (63 caractères au plus)")
	}
	if f.WebhookSecretFile == "" {
		return errors.New("webhook_secret_file obligatoire")
	}
	if f.Timeout < 0 {
		return errors.New("timeout négatif")
	}
	if len(f.AllowedNamespaces) == 0 {
		return errors.New(`allowed_namespaces obligatoire : propriétaires ou groupes autorisés, ou "*" pour tous`)
	}
	for _, ns := range f.AllowedNamespaces {
		if ns != "*" && (ns == "" || strings.HasPrefix(ns, "/") || strings.HasSuffix(ns, "/") || strings.Contains(ns, "//") || strings.Contains(ns, "*")) {
			return fmt.Errorf("allowed_namespaces : %q n'est ni « * » ni un chemin de propriétaire ou de groupe", ns)
		}
	}
	switch f.Kind {
	case forge.KindGitHub:
		if f.AppID == "" || f.PrivateKeyFile == "" {
			return errors.New("GitHub : app_id et private_key_file obligatoires")
		}
		if f.TokenFile != "" {
			return errors.New("GitHub : token_file est réservé à GitLab")
		}
	case forge.KindGitLab:
		if f.TokenFile == "" {
			return errors.New("GitLab : token_file obligatoire")
		}
		if f.AppID != "" || f.PrivateKeyFile != "" || f.APIURL != "" || f.InstallationID != 0 {
			return errors.New("GitLab : app_id, private_key_file, api_url et installation_id sont réservés à GitHub")
		}
	default:
		return fmt.Errorf("kind %q inconnu (github, gitlab)", f.Kind)
	}
	return nil
}

// Providers construit les forges, en lisant leurs secrets.
func (c Config) Providers() ([]forge.Provider, error) {
	var out []forge.Provider
	for _, f := range c.Forges {
		p, err := f.provider()
		if err != nil {
			return nil, fmt.Errorf("forge %s : %w", f.Name, err)
		}
		out = append(out, Scoped(p, f.AllowedNamespaces))
	}
	return out, nil
}

// Scoped borne p aux dépôts des espaces allowed (« * » : tous) : un dépôt hors périmètre
// n'est pas reconnu (Repo faux), donc jamais cloné ni analysé, quelle que soit l'URL de
// forge que le serveur envoie.
func Scoped(p forge.Provider, allowed []string) forge.Provider {
	if slices.Contains(allowed, "*") {
		return p
	}
	lower := make([]string, len(allowed))
	for i, ns := range allowed {
		lower[i] = strings.ToLower(ns)
	}
	return scopedProvider{Provider: p, allowed: lower}
}

type scopedProvider struct {
	forge.Provider
	allowed []string
}

func (s scopedProvider) Repo(forgeURL string) (string, bool) {
	repo, ok := s.Provider.Repo(forgeURL)
	if !ok {
		return "", false
	}
	r := strings.ToLower(repo)
	for _, ns := range s.allowed {
		if strings.HasPrefix(r, ns+"/") {
			return repo, true
		}
	}
	return "", false
}

func (f Forge) provider() (forge.Provider, error) {
	hook, err := ReadSecret(f.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	timeout := f.Timeout
	if timeout == 0 {
		timeout = forge.DefaultTimeout
	}
	client := &http.Client{Timeout: timeout}
	switch f.Kind {
	case forge.KindGitHub:
		pemKey, err := ReadSecret(f.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		key, err := forge.ParseRSAPrivateKey(pemKey)
		if err != nil {
			return nil, err
		}
		return forge.NewGitHub(forge.GitHubConfig{
			Name: f.Name, URL: f.URL, APIURL: f.APIURL, AppID: f.AppID, PrivateKey: key,
			InstallationID: f.InstallationID, WebhookSecret: hook, HTTPClient: client,
		})
	default:
		tok, err := ReadSecret(f.TokenFile)
		if err != nil {
			return nil, err
		}
		return forge.NewGitLab(forge.GitLabConfig{
			Name: f.Name, URL: f.URL, Token: string(tok), WebhookSecret: hook, HTTPClient: client,
		})
	}
}
