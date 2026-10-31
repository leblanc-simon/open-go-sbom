package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const testDSN = "postgres://ogsbom_app:pwd@localhost:5432/ogsbom"

// load appelle Load avec des arguments de ligne de commande maîtrisés (appconf lit
// os.Args, qui porte sinon les options de go test).
func load(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = append([]string{"ogsbom-server", "-c", filepath.Join(t.TempDir(), "absent.yaml")}, args...)
	return Load("ogsbom-server", "test")
}

func valid() Config {
	c := Defaults()
	c.Web.Host, c.Web.Port, c.Web.RateLimit = "127.0.0.1", 8080, 100
	c.HTTP = HTTP{ReadHeaderTimeout: time.Second, ShutdownTimeout: time.Second}
	c.Management = Management{Host: "127.0.0.1", Port: 8081}
	c.Logging.Format = "text"
	c.Database.DSN = testDSN
	c.Database.MaxOpenConns, c.Database.MaxIdleConns = 10, 5
	c.Database.StartupTimeout = time.Second
	c.Migration.MaxConns = 2
	c.Secrets = Secrets{Keys: map[string]string{"k1": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, ActiveKey: "k1"}
	c.Auth.SessionTTL, c.Auth.CookieSecure, c.Auth.BcryptCost = time.Hour, "auto", 12
	c.MFA.ChallengeTTL, c.MFA.MaxAttempts = time.Minute, 5
	c.Login.RateLimit = 10
	c.AgentAPI = AgentAPI{RateLimit: 120, FailureRateLimit: 30}
	c.Workers = Workers{Enabled: true, Concurrency: 4, PollInterval: time.Second, Lease: 30 * time.Second,
		RetryBase: 10 * time.Second, RetryMax: 30 * time.Minute, Retention: time.Hour,
		ScheduleInterval: 10 * time.Second, ShutdownTimeout: 30 * time.Second, OrgLimit: 2}
	c.Ingest = Ingest{MaxUploadMiB: 32, MaxDecompressedMiB: 128, MaxDepth: 64, MaxComponents: 100000, DecodeTimeout: 5 * time.Minute}
	return c
}

func TestLoadFromEnvironmentWithDefaults(t *testing.T) {
	t.Setenv("OGSBOM_DB_DSN", testDSN)
	t.Setenv("OGSBOM_PORT", "9000")
	t.Setenv("OGSBOM_DB_MAX_OPEN_CONNS", "7")
	t.Setenv("OGSBOM_SECRETS_KEYS", "k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("OGSBOM_SECRETS_ACTIVE_KEY", "k1")
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Driver != "postgres" || cfg.I18n.DefaultLanguage != "fr" || cfg.Logging.Level != "info" {
		t.Errorf("défauts du projet non appliqués : %q %q %q", cfg.Database.Driver, cfg.I18n.DefaultLanguage, cfg.Logging.Level)
	}
	if cfg.Web.Port != 9000 || cfg.Database.DSN != testDSN || cfg.Database.MaxOpenConns != 7 {
		t.Errorf("variables non lues : %+v", cfg)
	}
	if cfg.Database.MaxIdleConns != 10 || cfg.HTTP.ShutdownTimeout != 30*time.Second || cfg.Migration.MaxConns != 2 || cfg.Management.Port != 8081 {
		t.Errorf("défauts env-default non appliqués : %+v", cfg)
	}
	if !cfg.Workers.Enabled || cfg.Workers.Concurrency != 4 || cfg.Workers.Retention != 168*time.Hour || cfg.Workers.OrgLimit != 2 {
		t.Errorf("défauts des workers : %+v", cfg.Workers)
	}
	if cfg.Ingest != (Ingest{MaxUploadMiB: 32, MaxDecompressedMiB: 128, MaxDepth: 64, MaxComponents: 100000, DecodeTimeout: 5 * time.Minute}) ||
		MiB(cfg.Ingest.MaxUploadMiB) != 32<<20 {
		t.Errorf("défauts de l'ingestion : %+v", cfg.Ingest)
	}
	if cfg.Secrets.Keys["k1"] == "" {
		t.Errorf("clés de secrets non lues : %v", cfg.Secrets.Keys)
	}
}

func TestLoadFromFileThenEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
database:
  driver: postgres
  dsn: ` + testDSN + `
  max_open_conns: 5
  max_idle_conns: 2
i18n:
  default_language: en
http:
  shutdown_timeout: 5s
secrets:
  keys:
    k1: ` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) + `
  active_key: k1
workers:
  enabled: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OGSBOM_DB_MAX_IDLE_CONNS", "3")
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"ogsbom-server", "-c", path}
	cfg, err := Load("ogsbom-server", "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.MaxOpenConns != 5 || cfg.I18n.DefaultLanguage != "en" || cfg.HTTP.ShutdownTimeout != 5*time.Second {
		t.Errorf("fichier mal lu : %+v", cfg)
	}
	// Un false écrit dans le fichier n'est pas écrasé par un défaut.
	if cfg.Workers.Enabled {
		t.Error("workers.enabled: false ignoré")
	}
	if cfg.Database.MaxIdleConns != 3 {
		t.Errorf("la variable d'environnement ne l'emporte pas : %d", cfg.Database.MaxIdleConns)
	}
}

func TestLoadReportsInvalidConfiguration(t *testing.T) {
	t.Setenv("OGSBOM_DB_DSN", testDSN)
	t.Setenv("OGSBOM_DB_DRIVER", "sqlite")
	_, err := load(t)
	if err == nil || !strings.Contains(err.Error(), "database.driver (OGSBOM_DB_DRIVER)") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		field string
		edit  func(*Config)
	}{
		{"pilote", "database.driver (OGSBOM_DB_DRIVER)", func(c *Config) { c.Database.Driver = "sqlite" }},
		{"DSN absent", "database.dsn (OGSBOM_DB_DSN)", func(c *Config) { c.Database.DSN = "" }},
		{"DSN illisible", "database.dsn", func(c *Config) { c.Database.DSN = "postgres://h:port/x" }},
		{"pool vide", "database.max_open_conns", func(c *Config) { c.Database.MaxOpenConns = 0 }},
		{"inactives négatives", "database.max_idle_conns", func(c *Config) { c.Database.MaxIdleConns = -1 }},
		{"attente nulle", "database.startup_timeout", func(c *Config) { c.Database.StartupTimeout = 0 }},
		{"pool de migration", "migration.max_conns (OGSBOM_MIGRATION_MAX_CONNS)", func(c *Config) { c.Migration.MaxConns = 1 }},
		{"même rôle pour migrer", "migration.dsn", func(c *Config) { c.Migration.DSN = testDSN }},
		{"port web", "web.port", func(c *Config) { c.Web.Port = 70000 }},
		{"proxy", "web.trusted_proxies", func(c *Config) { c.Web.TrustedProxies = []string{"10.0.0.0/33"} }},
		{"gestion sur le port web", "management.port", func(c *Config) { c.Management.Port = 8080 }},
		{"gestion sur toutes les interfaces", "management.port", func(c *Config) { c.Management = Management{Host: "0.0.0.0", Port: 8080} }},
		{"niveau de journal", "logging.level", func(c *Config) { c.Logging.Level = "verbose" }},
		{"format de journal", "logging.format", func(c *Config) { c.Logging.Format = "xml" }},
		{"langue", "i18n.default_language", func(c *Config) { c.I18n.DefaultLanguage = "x!" }},
		{"arrêt", "http.shutdown_timeout", func(c *Config) { c.HTTP.ShutdownTimeout = 0 }},
		{"en-têtes", "http.read_header_timeout", func(c *Config) { c.HTTP.ReadHeaderTimeout = 0 }},
		{"certificat sans clé", "tls.key_file", func(c *Config) { c.TLS.CertFile = certFile }},
		{"clé sans certificat", "tls.cert_file", func(c *Config) { c.TLS.KeyFile = certFile }},
		{"mTLS sans TLS", "tls.client_ca_file", func(c *Config) { c.TLS.ClientCAFile = certFile }},
		{"certificat absent", "tls.cert_file", func(c *Config) {
			c.TLS.CertFile, c.TLS.KeyFile = filepath.Join(dir, "absent.pem"), certFile
		}},
		{"CORS", "cors.max_age", func(c *Config) { c.CORS.MaxAge = -1 }},
		{"clé absente", "secrets.keys", func(c *Config) { c.Secrets = Secrets{} }},
		{"clé active absente", "secrets.keys", func(c *Config) { c.Secrets.ActiveKey = "k2" }},
		{"durée de session", "auth.session_ttl", func(c *Config) { c.Auth.SessionTTL = 0 }},
		{"nom du cookie", "auth.cookie_name", func(c *Config) { c.Auth.CookieName = "" }},
		{"cookie Secure", "auth.cookie_secure", func(c *Config) { c.Auth.CookieSecure = "yes" }},
		{"coût bcrypt", "auth.bcrypt_cost", func(c *Config) { c.Auth.BcryptCost = 4 }},
		{"émetteur TOTP", "mfa.issuer", func(c *Config) { c.MFA.Issuer = "" }},
		{"durée du défi", "mfa.challenge_ttl", func(c *Config) { c.MFA.ChallengeTTL = 0 }},
		{"tentatives TOTP", "mfa.max_attempts", func(c *Config) { c.MFA.MaxAttempts = 0 }},
		{"limite de connexion", "login.rate_limit", func(c *Config) { c.Login.RateLimit = -1 }},
		{"limite de l'API des agents", "agent_api.rate_limit", func(c *Config) { c.AgentAPI.RateLimit = -1 }},
		{"limite des jetons refusés", "agent_api.failure_rate_limit", func(c *Config) { c.AgentAPI.FailureRateLimit = -1 }},
		{"bootstrap sans mot de passe", "bootstrap.admin_password", func(c *Config) { c.Bootstrap.AdminEmail = "a@example.org" }},
		{"bootstrap e-mail invalide", "bootstrap.admin_email", func(c *Config) {
			c.Bootstrap.AdminEmail, c.Bootstrap.AdminPassword = "pas une adresse", "un mot de passe assez long"
		}},
		{"bootstrap mot de passe court", "bootstrap.admin_password", func(c *Config) {
			c.Bootstrap.AdminEmail, c.Bootstrap.AdminPassword = "a@example.org", "court"
		}},
		{"secours sans ticket", "bootstrap.rescue_ticket", func(c *Config) { c.Bootstrap.RescueEmail = "a@example.org" }},
		{"secours ticket court", "bootstrap.rescue_ticket", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket = "a@example.org", "court"
		}},
		{"secours e-mail invalide", "bootstrap.rescue_totp_email", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket = "x", "INC-2026-1031"
		}},
		{"workers", "workers.concurrency (OGSBOM_WORKERS_CONCURRENCY)", func(c *Config) { c.Workers.Concurrency = 0 }},
		{"attente des workers", "workers.poll_interval", func(c *Config) { c.Workers.PollInterval = 0 }},
		{"bail", "workers.lease", func(c *Config) { c.Workers.Lease = 500 * time.Millisecond }},
		{"réessai", "workers.retry_base", func(c *Config) { c.Workers.RetryBase = 0 }},
		{"réessai maximal", "workers.retry_max", func(c *Config) { c.Workers.RetryMax = time.Second }},
		{"rétention", "workers.retention", func(c *Config) { c.Workers.Retention = 0 }},
		{"planificateur", "workers.schedule_interval", func(c *Config) { c.Workers.ScheduleInterval = 0 }},
		{"arrêt des workers", "workers.shutdown_timeout", func(c *Config) { c.Workers.ShutdownTimeout = 0 }},
		{"plafond par organisation", "workers.org_limit", func(c *Config) { c.Workers.OrgLimit = 0 }},
		{"envoi nul", "ingest.max_upload_mib", func(c *Config) { c.Ingest.MaxUploadMiB = 0 }},
		{"envoi démesuré", "ingest.max_upload_mib", func(c *Config) { c.Ingest.MaxUploadMiB, c.Ingest.MaxDecompressedMiB = 5000, 5000 }},
		{"décompressé plus petit que l'envoi", "ingest.max_decompressed_mib", func(c *Config) { c.Ingest.MaxDecompressedMiB = 16 }},
		{"profondeur", "ingest.max_depth", func(c *Config) { c.Ingest.MaxDepth = 4 }},
		{"composants", "ingest.max_components", func(c *Config) { c.Ingest.MaxComponents = 0 }},
		{"délai de décodage", "ingest.decode_timeout", func(c *Config) { c.Ingest.DecodeTimeout = 0 }},
		{"clé trop courte", "secrets.keys", func(c *Config) {
			c.Secrets = Secrets{Keys: map[string]string{"k1": "c2hvcnQ="}, ActiveKey: "k1"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := valid()
			c.edit(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("err = %v, attendu une erreur sur %s", err, c.field)
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("erreur sans champ : %v", err)
			}
		})
	}
}

func TestValidateReportsEveryError(t *testing.T) {
	cfg := valid()
	cfg.Database.Driver = "mysql"
	cfg.Web.Port = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "database.driver") || !strings.Contains(err.Error(), "web.port") {
		t.Fatalf("err = %v", err)
	}
}

func TestFieldsHaveEnvAndDescription(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Fields() {
		if !strings.HasPrefix(f.Env, EnvPrefix) || f.Env == EnvPrefix {
			t.Errorf("%s : variable %q sans préfixe ou sans nom", f.Path, f.Env)
		}
		if f.Description == "" {
			t.Errorf("%s : pas de env-description (absent de --help)", f.Path)
		}
		if seen[f.Env] {
			t.Errorf("variable %s en double", f.Env)
		}
		seen[f.Env] = true
	}
	if !seen["OGSBOM_DB_DSN"] || !seen["OGSBOM_MIGRATION_DSN"] || !seen["OGSBOM_TLS_CERT_FILE"] {
		t.Errorf("variables attendues manquantes : %v", seen)
	}
}

// TestHelpListsEveryVariable lance --help dans un sous-processus (appconf termine le
// programme) et vérifie que chaque variable y figure avec sa description.
func TestHelpListsEveryVariable(t *testing.T) {
	if os.Getenv("OGSBOM_CONFIG_HELP_CHILD") == "1" {
		os.Args = []string{"ogsbom-server", "--help"}
		_, _ = Load("ogsbom-server", "test")
		os.Exit(3) // --help aurait dû terminer en code 0
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelpListsEveryVariable$")
	cmd.Env = append(os.Environ(), "OGSBOM_CONFIG_HELP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help : %v\n%s", err, out)
	}
	for _, f := range Fields() {
		if !bytes.Contains(out, []byte(f.Env)) || !bytes.Contains(out, []byte(f.Description)) {
			t.Errorf("--help ne documente pas %s (%s)", f.Env, f.Description)
		}
	}
}

// TestExampleConfiguration vérifie que config.example.yaml ne contient que des clés
// connues, les contient toutes et constitue une configuration valide.
func TestExampleConfiguration(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("clé inconnue ou valeur invalide : %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(body, &tree); err != nil {
		t.Fatal(err)
	}
	for _, f := range Fields() {
		if !hasPath(tree, strings.Split(f.Path, ".")) {
			t.Errorf("config.example.yaml ne documente pas %s", f.Path)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("config.example.yaml invalide : %v", err)
	}
}

func hasPath(tree map[string]any, path []string) bool {
	v, ok := tree[path[0]]
	if !ok {
		return false
	}
	if len(path) == 1 {
		return true
	}
	sub, ok := v.(map[string]any)
	return ok && hasPath(sub, path[1:])
}
