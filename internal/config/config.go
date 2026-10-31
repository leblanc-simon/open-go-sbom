package config

import (
	"time"

	"leblanc.io/open-go-base/appconf"
)

// EnvPrefix préfixe toutes les variables d'environnement du serveur.
const EnvPrefix = "OGSBOM_"

// Config est la configuration d'ogsbom-server : fragments d'appconf (Web, Logging, I18n,
// CORS, base de données) et fragments propres au projet. Les fragments Auth et MFA
// d'appconf arrivent avec authx et mfax (T03), Workers avec la file (T02), Ingest, VulnDB
// et Bootstrap avec leurs lots.
type Config struct {
	Web        appconf.Web     `yaml:"web"        env-prefix:"OGSBOM_"`
	HTTP       HTTP            `yaml:"http"       env-prefix:"OGSBOM_"`
	TLS        TLS             `yaml:"tls"        env-prefix:"OGSBOM_"`
	Management Management      `yaml:"management" env-prefix:"OGSBOM_"`
	Logging    appconf.Logging `yaml:"logging"    env-prefix:"OGSBOM_"`
	I18n       appconf.I18n    `yaml:"i18n"       env-prefix:"OGSBOM_"`
	CORS       appconf.CORS    `yaml:"cors"       env-prefix:"OGSBOM_"`
	Database   Database        `yaml:"database"   env-prefix:"OGSBOM_"`
	Migration  Migration       `yaml:"migration"  env-prefix:"OGSBOM_"`
	Secrets    Secrets         `yaml:"secrets"    env-prefix:"OGSBOM_"`
}

// HTTP règle les délais des serveurs HTTP (public et gestion) et l'arrêt propre.
type HTTP struct {
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"HTTP_READ_HEADER_TIMEOUT" env-default:"10s"  env-description:"Maximum time to read request headers"`
	ReadTimeout       time.Duration `yaml:"read_timeout"        env:"HTTP_READ_TIMEOUT"        env-default:"60s"  env-description:"Maximum time to read a whole request, body included"`
	WriteTimeout      time.Duration `yaml:"write_timeout"       env:"HTTP_WRITE_TIMEOUT"       env-default:"60s"  env-description:"Maximum time to write a response"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"        env:"HTTP_IDLE_TIMEOUT"        env-default:"120s" env-description:"Keep-alive idle connection timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"    env:"HTTP_SHUTDOWN_TIMEOUT"    env-default:"30s"  env-description:"Grace period for in-flight requests on SIGTERM"`
}

// TLS active le TLS natif du serveur public. Sans lui, le serveur est placé derrière un
// mandataire inverse qui termine TLS, et le mTLS des agents est indisponible.
type TLS struct {
	CertFile     string `yaml:"cert_file"      env:"TLS_CERT_FILE"      env-description:"PEM certificate chain; enables native TLS with key_file"`
	KeyFile      string `yaml:"key_file"       env:"TLS_KEY_FILE"       env-description:"PEM private key of the certificate"`
	ClientCAFile string `yaml:"client_ca_file" env:"TLS_CLIENT_CA_FILE" env-description:"PEM CA bundle to verify agent client certificates (mTLS)"`
}

// Enabled indique si le TLS natif est configuré.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Management décrit l'écoute de gestion : /healthz, /readyz et /metrics, séparés de
// l'interface publique pour ne jamais les exposer par erreur.
type Management struct {
	Host string `yaml:"host" env:"MANAGEMENT_HOST" env-default:"127.0.0.1" env-description:"Listen IP for probes and metrics"`
	Port int    `yaml:"port" env:"MANAGEMENT_PORT" env-default:"8081"      env-description:"Listen port for probes and metrics"`
}

// Database complète le fragment d'appconf (pilote et DSN du rôle d'exécution) par les
// réglages du pool.
type Database struct {
	appconf.Database `yaml:",inline"`

	MaxOpenConns    int           `yaml:"max_open_conns"    env:"DB_MAX_OPEN_CONNS"    env-default:"20"  env-description:"Maximum open connections of the runtime pool"`
	MaxIdleConns    int           `yaml:"max_idle_conns"    env:"DB_MAX_IDLE_CONNS"    env-default:"10"  env-description:"Maximum idle connections of the runtime pool"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" env-default:"30m" env-description:"Maximum lifetime of a pooled connection"`
	StartupTimeout  time.Duration `yaml:"startup_timeout"   env:"DB_STARTUP_TIMEOUT"   env-default:"60s" env-description:"How long to wait for the database at startup"`
}

// Migration désigne la connexion du rôle propriétaire, utilisée seulement pour migrer.
// Sans DSN, le serveur ne migre pas et vérifie que le schéma est à jour.
type Migration struct {
	DSN         string        `yaml:"dsn"          env:"MIGRATION_DSN"          env-description:"Owner role connection, used only to migrate; empty to skip migrations"`
	MaxConns    int           `yaml:"max_conns"    env:"MIGRATION_MAX_CONNS"    env-default:"2"  env-description:"Connections of the migration pool (at least 2)"`
	LockTimeout time.Duration `yaml:"lock_timeout" env:"MIGRATION_LOCK_TIMEOUT" env-default:"5m" env-description:"Maximum wait for another instance's migration lock"`
}

// Secrets porte les clés de chiffrement des secrets stockés (internal/secret) : clés de
// 32 octets en base64, nommées, et le nom de la clé active.
type Secrets struct {
	Keys      map[string]string `yaml:"keys"       env:"SECRETS_KEYS"       env-description:"Encryption keys as id:base64 pairs separated by commas"`
	ActiveKey string            `yaml:"active_key" env:"SECRETS_ACTIVE_KEY" env-description:"Id of the key used to encrypt"`
}

// Defaults renvoie les valeurs qui diffèrent des défauts d'appconf : appconf ne pose un
// défaut que sur un champ vide, ces valeurs l'emportent donc tant que la configuration ne
// les change pas.
func Defaults() Config {
	var c Config
	c.Database.Driver = "postgres"
	c.I18n.DefaultLanguage = "fr"
	c.Logging.Level = "info"
	return c
}

// Load lit la configuration (fichier -c s'il existe, sinon environnement ; --help et
// --version terminent le programme), puis la valide.
func Load(name, version string) (Config, error) {
	cfg := Defaults()
	if err := appconf.Load(&cfg, appconf.Options{Name: name, Version: version}); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}
