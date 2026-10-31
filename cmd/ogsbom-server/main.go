// Commande ogsbom-server : interface web, API REST, workers et planificateur de la file de
// traitements. main ne fait que charger la configuration, construire les dépendances,
// lancer les serveurs et attendre le signal d'arrêt.
package main

import (
	"context"
	"errors"
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

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/api"
	"leblanc.io/open-go-sbom/internal/config"
	"leblanc.io/open-go-sbom/internal/dashboard"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/download"
	"leblanc.io/open-go-sbom/internal/finding"
	"leblanc.io/open-go-sbom/internal/ingest"
	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/sbom/schema"
	"leblanc.io/open-go-sbom/internal/search"
	"leblanc.io/open-go-sbom/internal/secret"
	"leblanc.io/open-go-sbom/internal/version/grypeversion"
	"leblanc.io/open-go-sbom/internal/vuln"
	"leblanc.io/open-go-sbom/internal/vuln/grype"
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

	box, err := secret.Parse(cfg.Secrets.Keys, cfg.Secrets.ActiveKey)
	if err != nil {
		return fmt.Errorf("secrets.keys : %w", err)
	}
	if cfg.Auth.CookieSecure != "on" {
		logger.Warn("auth.cookie_secure n'est pas « on » : cookies sans préfixe __Host-, et sans Secure hors HTTPS détecté ; réservé au développement",
			"cookie_secure", cfg.Auth.CookieSecure)
	}
	accounts := account.NewService(pool, cfg.Auth.BcryptCost)
	b := cfg.Bootstrap
	if err := accounts.Startup(ctx, account.StartupOptions{
		AdminEmail: b.AdminEmail, AdminPassword: b.AdminPassword, RescueEmail: b.RescueEmail, RescueTicket: b.RescueTicket,
		RescuePassword: b.RescuePassword,
	}, pool, box, logger); err != nil {
		return err
	}

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
	agents := agent.NewService(pool)
	dash := dashboard.NewService(pool)
	validator, err := schema.New()
	if err != nil {
		return err
	}
	ingester, err := ingest.NewService(ingest.Options{
		Pool: pool, Validator: validator, Logger: logger,
		Limits: ingest.Limits{
			MaxUpload: config.MiB(cfg.Ingest.MaxUploadMiB),
			SBOM: sbom.Limits{
				MaxBytes: config.MiB(cfg.Ingest.MaxDecompressedMiB), MaxDepth: cfg.Ingest.MaxDepth,
				MaxComponents: cfg.Ingest.MaxComponents,
			},
		},
	})
	if err != nil {
		return err
	}
	searcher := search.NewService(pool, grypeversion.New())
	exports := search.NewExportLimiter(cfg.UserAPI.MaxExports, cfg.UserAPI.ExportTimeout)
	vulndbScreen := web.VulnDBOptions{MaxAge: cfg.VulnDB.MaxAge, Offline: cfg.VulnDB.Offline, ListingURL: cfg.VulnDB.ListingURL,
		SyncInterval: cfg.VulnDB.SyncInterval, MaxArchive: config.MiB(cfg.VulnDB.MaxArchiveMiB),
		UploadTimeout: cfg.VulnDB.DownloadTimeout}
	router, err := web.NewRouter(web.RouterOptions{
		Logger:         logger,
		Catalog:        catalog,
		Renderer:       renderer,
		Assets:         assets,
		Metrics:        middleware.NewHTTPMetrics(registry),
		RateLimit:      cfg.Web.RateLimit,
		TrustedProxies: cfg.Web.TrustedProxies,
		CORS:           cfg.CORS,
		CSRFSecure:     cfg.Auth.CookieSecure,
		Identity: &web.IdentityOptions{
			Pool:           pool,
			Accounts:       accounts,
			Orgs:           org.NewService(pool),
			Projects:       project.NewService(pool),
			Agents:         agents,
			Inventory:      inventory.NewService(pool),
			Ingest:         ingester,
			Findings:       finding.NewService(pool),
			Search:         searcher,
			Exports:        exports,
			Dashboard:      dash,
			VulnDB:         vulndbScreen,
			Secrets:        box,
			Auth:           cfg.Auth,
			MFA:            cfg.MFA,
			LoginRateLimit: cfg.Login.RateLimit,
			SessionMaxAge:  cfg.Login.SessionMaxAge,
		},
		AgentAPI: &api.AgentOptions{
			Agents:           agents,
			Ingest:           ingester,
			RateLimit:        cfg.AgentAPI.RateLimit,
			FailureRateLimit: cfg.AgentAPI.FailureRateLimit,
			// La validation de la configuration garantit le TLS natif avec client_ca_file.
			RequireClientCert: cfg.TLS.ClientCAFile != "",
		},
		UserAPI: &api.UserOptions{
			Pool:             pool,
			Accounts:         accounts,
			Search:           searcher,
			Exports:          exports,
			RateLimit:        cfg.UserAPI.RateLimit,
			FailureRateLimit: cfg.UserAPI.FailureRateLimit,
		},
	})
	if err != nil {
		return err
	}
	checks := []web.Check{
		{Name: "database", Run: pool.Ping},
		{Name: "schema", Run: func(ctx context.Context) error { return db.VerifySchema(ctx, pool.DB(), nil) }},
	}
	// Seule une instance worker a besoin d'une base de vulnérabilités chargée : une
	// instance purement web reste disponible (import sur un site isolé).
	var vulndb *vuln.Manager
	if cfg.Workers.Enabled {
		vulndb = vuln.NewManager(vuln.ManagerOptions{Pool: pool, Engine: grype.NewEngine(), Dir: cfg.VulnDB.Dir,
			SyncInterval: cfg.VulnDB.SyncInterval, Logger: logger})
		checks = append(checks, web.Check{Name: "vulndb", Run: vulndb.Ready})
	}
	if err := vuln.RegisterMetrics(registry, pool, vulndb, cfg.VulnDB.MaxAge, logger); err != nil {
		return err
	}
	readiness := web.NewReadiness(checks...)

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
	jobMetrics, err := jobs.NewMetrics(registry, pool, logger)
	if err != nil {
		return err
	}
	services := []func(context.Context) error{web.NewServer(opts).Run}
	if cfg.Workers.Enabled {
		runner := jobs.NewRunner(pool, jobs.RunnerOptions{
			Concurrency:     cfg.Workers.Concurrency,
			PollInterval:    cfg.Workers.PollInterval,
			Lease:           cfg.Workers.Lease,
			Backoff:         jobs.Backoff{Base: cfg.Workers.RetryBase, Max: cfg.Workers.RetryMax, Jitter: jobs.DefaultRetryJitter},
			Retention:       cfg.Workers.Retention,
			ShutdownTimeout: cfg.Workers.ShutdownTimeout,
			Logger:          logger,
			Metrics:         jobMetrics,
		})
		scheduler := jobs.NewScheduler(pool, jobs.SchedulerOptions{
			Interval: cfg.Workers.ScheduleInterval,
			Logger:   logger,
			Metrics:  jobMetrics,
		})
		if err := runner.Register(account.PurgeKind, accounts.PurgeHandler()); err != nil {
			return err
		}
		if err := runner.Register(ingest.DecodeKind, ingester.DecodeHandler(),
			jobs.WithOrgLimit(cfg.Workers.OrgLimit), jobs.WithTimeout(cfg.Ingest.DecodeTimeout)); err != nil {
			return err
		}
		if err := registerAnalysis(cfg, runner, scheduler, pool, vulndb, ingester, logger); err != nil {
			return err
		}
		if err := scheduler.Register(account.PurgeSchedule()); err != nil {
			return err
		}
		if err := registerDashboard(runner, scheduler, dash); err != nil {
			return err
		}
		services = append(services, runner.Run, scheduler.Run, vulndb.Run)
	}
	return runAll(ctx, services...)
}

// registerAnalysis enregistre l'analyse de vulnérabilités : analyses des références,
// réanalyse du parc, vérification de la liste de distribution (sauf hors ligne).
func registerAnalysis(cfg config.Config, runner *jobs.Runner, scheduler *jobs.Scheduler, pool *db.Pool, vulndb *vuln.Manager,
	ingester *ingest.Service, logger *slog.Logger) error {
	analyzer := finding.NewAnalyzer(finding.Options{Pool: pool, Engine: vulndb, Blobs: ingester, Logger: logger})
	source, err := grype.NewSource(download.New(name+"/"+version, cfg.VulnDB.DownloadTimeout), cfg.VulnDB.ListingURL)
	if err != nil {
		return err
	}
	checker := vuln.NewChecker(vuln.CheckerOptions{Pool: pool, Source: source, Engine: grype.NewEngine(), Dir: cfg.VulnDB.Dir,
		MaxArchive: config.MiB(cfg.VulnDB.MaxArchiveMiB), Logger: logger})
	check := checker.Handler()
	if cfg.VulnDB.Offline {
		// Un job mis en file avant le passage hors ligne se termine sans réseau.
		check = jobs.HandlerFunc(func(context.Context, jobs.Execution) error { return nil })
	}
	for _, r := range []struct {
		kind string
		h    jobs.Handler
		opts []jobs.KindOption
	}{
		{inventory.AnalysisKind, analyzer.Handler(), []jobs.KindOption{jobs.WithOrgLimit(cfg.Workers.OrgLimit),
			jobs.WithTimeout(cfg.VulnDB.AnalysisTimeout)}},
		{vuln.RescanAllKind, analyzer.RescanAllHandler(), nil},
		{finding.RescanOrgKind, analyzer.RescanOrgHandler(), nil},
		// Téléchargement, puis installation complète pour valider l'archive.
		{vuln.CheckKind, check, []jobs.KindOption{jobs.WithTimeout(2 * cfg.VulnDB.DownloadTimeout)}},
		// Archive téléversée depuis l'administration : même validation, même en mode hors ligne.
		{vuln.ImportKind, checker.ImportHandler(), []jobs.KindOption{jobs.WithTimeout(2 * cfg.VulnDB.DownloadTimeout)}},
	} {
		if err := runner.Register(r.kind, r.h, r.opts...); err != nil {
			return err
		}
	}
	if cfg.VulnDB.Offline {
		return nil
	}
	return scheduler.Register(vuln.CheckSchedule(cfg.VulnDB.CheckInterval))
}

// registerDashboard enregistre les statistiques quotidiennes du tableau de bord.
func registerDashboard(runner *jobs.Runner, scheduler *jobs.Scheduler, dash *dashboard.Service) error {
	if err := runner.Register(dashboard.StatsAllKind, dash.StatsAllHandler()); err != nil {
		return err
	}
	if err := runner.Register(dashboard.StatsOrgKind, dash.StatsOrgHandler()); err != nil {
		return err
	}
	return scheduler.Register(dashboard.StatsSchedule())
}

// runAll lance les services ensemble et attend qu'ils aient tous rendu la main ; le
// premier qui s'arrête, sur erreur ou non, arrête les autres.
func runAll(ctx context.Context, services ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(services))
	for _, run := range services {
		go func() {
			errs <- run(ctx)
			cancel()
		}()
	}
	var all []error
	for range services {
		all = append(all, <-errs)
	}
	return errors.Join(all...)
}
