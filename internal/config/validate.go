package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"time"

	"golang.org/x/text/language"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/secret"
)

// FieldError est une erreur de configuration qui nomme son champ.
type FieldError struct {
	Path string
	Msg  string
}

func (e *FieldError) Error() string {
	if env := envOf(e.Path); env != "" {
		return fmt.Sprintf("%s (%s) : %s", e.Path, env, e.Msg)
	}
	return e.Path + " : " + e.Msg
}

type validator struct{ errs []error }

func (v *validator) fail(path, format string, args ...any) {
	v.errs = append(v.errs, &FieldError{Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) port(path string, p int) {
	if p < 1 || p > 65535 {
		v.fail(path, "port invalide %d (1 à 65535)", p)
	}
}

func (v *validator) positive(path string, n int64) {
	if n <= 0 {
		v.fail(path, "doit être strictement positif")
	}
}

func (v *validator) nonNegative(path string, n int64) {
	if n < 0 {
		v.fail(path, "ne peut pas être négatif")
	}
}

func (v *validator) oneOf(path, got string, allowed ...string) {
	if !slices.Contains(allowed, got) {
		v.fail(path, "valeur %q invalide (attendu : %v)", got, allowed)
	}
}

func (v *validator) readable(path, file string) {
	if file == "" {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		v.fail(path, "fichier illisible : %v", err)
		return
	}
	_ = f.Close()
}

// Validate vérifie la configuration et renvoie toutes les erreurs, chacune nommant son
// champ et sa variable d'environnement.
func (c Config) Validate() error {
	var v validator

	v.port("web.port", c.Web.Port)
	v.nonNegative("web.rate_limit", int64(c.Web.RateLimit))
	for _, p := range c.Web.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			v.fail("web.trusted_proxies", "CIDR invalide %q", p)
		}
	}

	v.positive("http.read_header_timeout", int64(c.HTTP.ReadHeaderTimeout))
	v.nonNegative("http.read_timeout", int64(c.HTTP.ReadTimeout))
	v.nonNegative("http.write_timeout", int64(c.HTTP.WriteTimeout))
	v.nonNegative("http.idle_timeout", int64(c.HTTP.IdleTimeout))
	v.positive("http.shutdown_timeout", int64(c.HTTP.ShutdownTimeout))

	switch {
	case c.TLS.CertFile != "" && c.TLS.KeyFile == "":
		v.fail("tls.key_file", "obligatoire avec tls.cert_file")
	case c.TLS.KeyFile != "" && c.TLS.CertFile == "":
		v.fail("tls.cert_file", "obligatoire avec tls.key_file")
	}
	if c.TLS.ClientCAFile != "" && !c.TLS.Enabled() {
		v.fail("tls.client_ca_file", "le mTLS des agents exige le TLS natif (tls.cert_file et tls.key_file)")
	}
	v.readable("tls.cert_file", c.TLS.CertFile)
	v.readable("tls.key_file", c.TLS.KeyFile)
	v.readable("tls.client_ca_file", c.TLS.ClientCAFile)

	v.port("management.port", c.Management.Port)
	if c.Management.Port == c.Web.Port && (c.Management.Host == c.Web.Host || c.Management.Host == "0.0.0.0" || c.Web.Host == "0.0.0.0") {
		v.fail("management.port", "doit différer de web.port : l'écoute de gestion est séparée")
	}

	v.oneOf("logging.level", c.Logging.Level, "debug", "info", "warn", "error")
	v.oneOf("logging.format", c.Logging.Format, "text", "json")

	if _, err := language.Parse(c.I18n.DefaultLanguage); err != nil {
		v.fail("i18n.default_language", "étiquette de langue invalide %q", c.I18n.DefaultLanguage)
	}

	v.nonNegative("cors.max_age", int64(c.CORS.MaxAge))

	// Le dialecte d'authx et de mfax se déduit du pilote : seul PostgreSQL est supporté.
	if c.Database.Driver != "postgres" {
		v.fail("database.driver", "doit valoir « postgres » (reçu %q)", c.Database.Driver)
	}
	appRole := ""
	if c.Database.DSN == "" {
		v.fail("database.dsn", "obligatoire (connexion du rôle d'exécution)")
	} else if r, err := db.RoleFromDSN(c.Database.DSN); err != nil {
		v.fail("database.dsn", "%v", err)
	} else {
		appRole = r
	}
	v.positive("database.max_open_conns", int64(c.Database.MaxOpenConns))
	v.nonNegative("database.max_idle_conns", int64(c.Database.MaxIdleConns))
	v.nonNegative("database.conn_max_lifetime", int64(c.Database.ConnMaxLifetime))
	v.positive("database.startup_timeout", int64(c.Database.StartupTimeout))

	if c.Migration.DSN != "" {
		if r, err := db.RoleFromDSN(c.Migration.DSN); err != nil {
			v.fail("migration.dsn", "%v", err)
		} else if r == appRole {
			v.fail("migration.dsn", "doit désigner le rôle propriétaire, distinct du rôle d'exécution %q", r)
		}
	}
	// Le verrou de migration tient une connexion pendant que les migrations en utilisent
	// une autre.
	if c.Migration.MaxConns < 2 {
		v.fail("migration.max_conns", "au moins 2 connexions (reçu %d)", c.Migration.MaxConns)
	}
	v.nonNegative("migration.lock_timeout", int64(c.Migration.LockTimeout))

	if len(c.Secrets.Keys) > 0 || c.Secrets.ActiveKey != "" {
		if _, err := secret.Parse(c.Secrets.Keys, c.Secrets.ActiveKey); err != nil {
			v.fail("secrets.keys", "%v", err)
		}
	}

	v.positive("workers.concurrency", int64(c.Workers.Concurrency))
	v.positive("workers.poll_interval", int64(c.Workers.PollInterval))
	if c.Workers.Lease < time.Second {
		v.fail("workers.lease", "au moins 1s (reçu %s)", c.Workers.Lease)
	}
	v.positive("workers.retry_base", int64(c.Workers.RetryBase))
	if c.Workers.RetryMax < c.Workers.RetryBase {
		v.fail("workers.retry_max", "doit valoir au moins workers.retry_base (%s)", c.Workers.RetryBase)
	}
	v.positive("workers.retention", int64(c.Workers.Retention))
	v.positive("workers.schedule_interval", int64(c.Workers.ScheduleInterval))
	v.positive("workers.shutdown_timeout", int64(c.Workers.ShutdownTimeout))

	return errors.Join(v.errs...)
}
