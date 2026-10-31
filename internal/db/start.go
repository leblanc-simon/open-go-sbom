package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// StartOptions paramètre Start.
type StartOptions struct {
	// DSN est la connexion du rôle d'exécution, Pool les réglages de son pool.
	DSN  string
	Pool PoolConfig
	// StartupTimeout borne l'attente de la base.
	StartupTimeout time.Duration
	// MigrationDSN est la connexion du rôle propriétaire ; vide, rien n'est migré et le
	// schéma doit déjà être à jour.
	MigrationDSN      string
	MigrationMaxConns int
	LockTimeout       time.Duration
	// Before est passé à Migrate (authx, mfax en T03).
	Before []Step
	Logger *slog.Logger
}

// Start prépare la base au démarrage du serveur : attente bornée, migrations avec le
// rôle propriétaire (pool fermé ensuite), contrôle du rôle d'exécution, vérification du
// schéma. Il renvoie le pool d'exécution, ou une erreur qui doit empêcher le démarrage.
func Start(ctx context.Context, o StartOptions) (*Pool, error) {
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	app, err := Open(o.DSN, o.Pool)
	if err != nil {
		return nil, err
	}
	pool := NewPool(app)
	fail := func(err error) (*Pool, error) {
		_ = pool.Close()
		return nil, err
	}
	if err := WaitReady(ctx, app, o.StartupTimeout, logger); err != nil {
		return fail(err)
	}
	if o.MigrationDSN != "" {
		if err := migrateWith(ctx, o, logger); err != nil {
			return fail(err)
		}
	}
	if err := CheckRuntimeRole(ctx, app); err != nil {
		return fail(err)
	}
	if err := VerifySchema(ctx, app, nil); err != nil {
		if errors.Is(err, ErrPendingMigrations) && o.MigrationDSN == "" {
			err = fmt.Errorf("%w (aucune connexion de migration configurée : migration.dsn)", err)
		}
		return fail(err)
	}
	return pool, nil
}

func migrateWith(ctx context.Context, o StartOptions, logger *slog.Logger) error {
	appRole, err := RoleFromDSN(o.DSN)
	if err != nil {
		return err
	}
	owner, err := Open(o.MigrationDSN, PoolConfig{MaxOpenConns: o.MigrationMaxConns, ApplicationName: o.Pool.ApplicationName + "-migrate"})
	if err != nil {
		return fmt.Errorf("db: connexion de migration : %w", err)
	}
	defer owner.Close()
	if err := WaitReady(ctx, owner, o.StartupTimeout, logger); err != nil {
		return fmt.Errorf("db: connexion de migration : %w", err)
	}
	applied, err := Migrate(ctx, owner, MigrateOptions{AppRole: appRole, LockTimeout: o.LockTimeout, Before: o.Before, Logger: logger})
	if err != nil {
		return err
	}
	logger.Info("schéma à jour", "applied", len(applied))
	return nil
}
