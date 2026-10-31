package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// PoolConfig règle un pool de connexions. Les valeurs nulles gardent celles de
// database/sql (pas de limite, pas d'expiration).
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	// ApplicationName apparaît dans pg_stat_activity.
	ApplicationName string
}

// Open ouvre un pool database/sql sur le pilote pgx. Il ne contacte pas encore la base :
// voir WaitReady. Chaque connexion est en UTC, pour que les timestamptz relus n'en
// dépendent pas.
func Open(dsn string, pc PoolConfig) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// L'erreur de pgx peut citer le DSN, mot de passe compris : on ne la propage pas.
		return nil, errors.New("db: DSN PostgreSQL illisible")
	}
	cfg.RuntimeParams["timezone"] = "UTC"
	if pc.ApplicationName != "" {
		cfg.RuntimeParams["application_name"] = pc.ApplicationName
	}
	pool := stdlib.OpenDB(*cfg)
	pool.SetMaxOpenConns(pc.MaxOpenConns)
	pool.SetMaxIdleConns(pc.MaxIdleConns)
	pool.SetConnMaxLifetime(pc.ConnMaxLifetime)
	pool.SetConnMaxIdleTime(pc.ConnMaxIdleTime)
	return pool, nil
}

// RoleFromDSN renvoie le rôle PostgreSQL d'un DSN. L'exécuteur de migrations s'en sert
// pour accorder ses droits au rôle d'exécution sans le redemander en configuration.
func RoleFromDSN(dsn string) (string, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "", errors.New("db: DSN PostgreSQL illisible")
	}
	if cfg.User == "" {
		return "", errors.New("db: le DSN ne nomme aucun rôle")
	}
	return cfg.User, nil
}

// WaitReady attend que la base réponde, au plus timeout, en réessayant avec un délai
// croissant. Il sert au démarrage, quand la base peut démarrer en même temps que le
// serveur.
func WaitReady(ctx context.Context, pool *sql.DB, timeout time.Duration, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	delay := 250 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err := pool.PingContext(ctx)
		if err == nil {
			return nil
		}
		if logger != nil {
			logger.Warn("base de données injoignable, nouvel essai", "attempt", attempt, "retry_in", delay.String(), "err", pingError(err))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("db: base injoignable après %s : %w", timeout, pingError(err))
		case <-time.After(delay):
		}
		delay = min(delay*2, 5*time.Second)
	}
}

// pingError garde le message de pgx, qui ne contient pas le mot de passe, mais retire le
// contexte expiré qui masquerait la vraie cause.
func pingError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errors.New("délai dépassé")
	}
	return err
}
