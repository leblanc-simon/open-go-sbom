// Commande ogsbom-server : interface web, API REST et, dans les lots suivants, workers et
// planificateur. main ne fait que charger la configuration, construire les dépendances,
// lancer les serveurs et attendre le signal d'arrêt.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"leblanc.io/open-go-base/logx"

	"leblanc.io/open-go-sbom/internal/config"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/web"
	"leblanc.io/open-go-sbom/internal/web/middleware"
	"leblanc.io/open-go-sbom/locales"
	webfs "leblanc.io/open-go-sbom/web"
)

const name = "ogsbom-server"

// version est injectée à la construction : -ldflags "-X 'main.version=…'".
var version = "develop"

func main() {
	// --help et --version terminent ici, en code 0.
	cfg, err := config.Load(name, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s : configuration invalide :\n%v\n", name, err)
		os.Exit(2)
	}
	logger := logx.New(cfg.Logging)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("arrêt sur erreur", "err", err)
		os.Exit(1)
	}
	logger.Info("arrêt terminé")
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	logger.Info("démarrage", "version", version)

	catalog, err := locale.New(locales.FS, ".", cfg.I18n.DefaultLanguage)
	if err != nil {
		return fmt.Errorf("i18n.default_language (OGSBOM_I18N_DEFAULT_LANGUAGE) : %w", err)
	}

	pool, err := db.Start(ctx, db.StartOptions{
		DSN: cfg.Database.DSN,
		Pool: db.PoolConfig{
			MaxOpenConns:    cfg.Database.MaxOpenConns,
			MaxIdleConns:    cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
			ApplicationName: name,
		},
		StartupTimeout:    cfg.Database.StartupTimeout,
		MigrationDSN:      cfg.Migration.DSN,
		MigrationMaxConns: cfg.Migration.MaxConns,
		LockTimeout:       cfg.Migration.LockTimeout,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("base de données : %w", err)
	}
	defer pool.Close()

	templates, err := webfs.Templates()
	if err != nil {
		return err
	}
	static, err := webfs.Static()
	if err != nil {
		return err
	}
	assets, err := render.NewAssets(static)
	if err != nil {
		return err
	}
	renderer, err := render.New(render.Options{Templates: templates, Assets: assets, Catalog: catalog, Version: version, Logger: logger})
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewDBStatsCollector(pool.DB(), "app"),
	)
	router, err := web.NewRouter(web.RouterOptions{
		Logger:         logger,
		Catalog:        catalog,
		Renderer:       renderer,
		Assets:         assets,
		Metrics:        middleware.NewHTTPMetrics(registry),
		RateLimit:      cfg.Web.RateLimit,
		TrustedProxies: cfg.Web.TrustedProxies,
		CORS:           cfg.CORS,
		CSRFSecure:     "auto",
	})
	if err != nil {
		return err
	}
	readiness := web.NewReadiness(
		web.Check{Name: "database", Run: pool.Ping},
		web.Check{Name: "schema", Run: func(ctx context.Context) error { return db.VerifySchema(ctx, pool.DB(), nil) }},
	)

	opts := web.ServerOptions{
		PublicAddr:     net.JoinHostPort(cfg.Web.Host, strconv.Itoa(cfg.Web.Port)),
		ManagementAddr: net.JoinHostPort(cfg.Management.Host, strconv.Itoa(cfg.Management.Port)),
		Public:         router,
		Management:     web.NewManagementHandler(registry, readiness),
		Timeouts: web.Timeouts{
			ReadHeader: cfg.HTTP.ReadHeaderTimeout,
			Read:       cfg.HTTP.ReadTimeout,
			Write:      cfg.HTTP.WriteTimeout,
			Idle:       cfg.HTTP.IdleTimeout,
			Shutdown:   cfg.HTTP.ShutdownTimeout,
		},
		Logger:     logger,
		OnShutdown: readiness.Drain,
	}
	if cfg.TLS.Enabled() {
		if opts.TLS, err = web.TLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.ClientCAFile); err != nil {
			return err
		}
	}
	return web.NewServer(opts).Run(ctx)
}
