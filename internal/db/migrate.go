package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"leblanc.io/lotor/internal/db/migrations"
)

// MigrationsTable suit les migrations du projet appliquées.
const MigrationsTable = "lotor_schema_migrations"

// bootstrapLockKey sérialise la création de MigrationsTable entre instances qui démarrent
// ensemble : deux CREATE TABLE IF NOT EXISTS concurrents peuvent sinon échouer sur le
// catalogue. Verrou consultatif de transaction, compatible avec pgbouncer.
const bootstrapLockKey int64 = 0x6f6773626f6d // « lotor »

var (
	// ErrChecksumMismatch : une migration déjà appliquée a été modifiée depuis.
	ErrChecksumMismatch = errors.New("db: migration publiée modifiée")
	// ErrUnknownMigration : la base porte une migration que ce binaire ne connaît pas
	// (base migrée par une version plus récente).
	ErrUnknownMigration = errors.New("db: migration inconnue de ce binaire")
	// ErrPendingMigrations : le schéma n'est pas à jour.
	ErrPendingMigrations = errors.New("db: migrations en attente")
)

var migrationName = regexp.MustCompile(`^([0-9]{3})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Migration est un fichier de migration du projet.
type Migration struct {
	Version  int
	Name     string // nom du fichier, 001_init.sql
	Checksum string // SHA-256 hexadécimal du contenu
	SQL      string
}

// LoadMigrations lit les migrations à la racine de fsys. Les noms suivent NNN_<sujet>.sql
// et les numéros se suivent à partir de 001 : un trou ou un doublon est une erreur.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("db: lecture des migrations : %w", err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("db: nom de migration invalide %q (attendu NNN_<sujet>.sql)", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("db: lecture de %s : %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: version, Name: e.Name(), Checksum: hex.EncodeToString(sum[:]), SQL: string(body)})
	}
	slices.SortFunc(out, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("db: migrations non contiguës : %s à la position %d", m.Name, i+1)
		}
	}
	return out, nil
}

// Step est une migration externe au projet jouée sous le verrou de migration, avant celles
// du projet : celles d'authx et de mfax toujours, puis MigrateOptions.Before. Elle utilise le pool du propriétaire, sur une autre
// connexion que celle qui tient le verrou.
type Step struct {
	Name string
	Run  func(ctx context.Context, owner *sql.DB) error
}

// MigrateOptions paramètre Migrate.
type MigrateOptions struct {
	// AppRole est le rôle d'exécution : il reçoit les droits des privilèges par défaut et
	// la lecture de MigrationsTable. Obligatoire.
	AppRole string
	// Migrations remplace les migrations embarquées (tests).
	Migrations fs.FS
	// LockTimeout borne l'attente du verrou de migration (0 : sans limite).
	LockTimeout time.Duration
	// Before est joué sous le verrou, après authx et mfax et avant les migrations du projet.
	Before []Step
	Logger *slog.Logger
}

// Migrate applique les migrations avec le pool du rôle propriétaire, dans cet ordre :
// verrou (LOCK TABLE … IN EXCLUSIVE MODE dans une transaction, sur une connexion dédiée),
// migrations d'authx et de mfax, étapes Before, migrations du projet en attente, validation (CheckOrgIsolation), puis
// validation de la transaction. Les migrations du projet et leur enregistrement partagent
// la transaction du verrou : tout ou rien. Une seconde instance attend le verrou, puis
// constate qu'il n'y a rien à faire. Le pool doit permettre au moins deux connexions.
//
// Migrate renvoie les migrations appliquées par cet appel.
func Migrate(ctx context.Context, owner *sql.DB, opts MigrateOptions) ([]Migration, error) {
	if opts.AppRole == "" {
		return nil, errors.New("db: rôle d'exécution non précisé pour la migration")
	}
	if max := owner.Stats().MaxOpenConnections; max != 0 && max < 2 {
		return nil, fmt.Errorf("db: le pool de migration doit permettre au moins 2 connexions (%d)", max)
	}
	fsys := opts.Migrations
	if fsys == nil {
		fsys = migrations.FS
	}
	all, err := LoadMigrations(fsys)
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	if err := bootstrap(ctx, owner, opts.AppRole); err != nil {
		return nil, err
	}

	conn, err := owner.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: connexion du verrou de migration : %w", err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("db: transaction du verrou de migration : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lock(ctx, tx, opts.LockTimeout); err != nil {
		return nil, err
	}
	for _, step := range append(externalSteps(), opts.Before...) {
		if err := step.Run(ctx, owner); err != nil {
			return nil, fmt.Errorf("db: migration %s : %w", step.Name, err)
		}
	}
	applied, err := readApplied(ctx, tx)
	if err != nil {
		return nil, err
	}
	pending, err := pendingMigrations(all, applied)
	if err != nil {
		return nil, err
	}
	if len(pending) > 0 {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('lotor.app_role', $1, true)", opts.AppRole); err != nil {
			return nil, fmt.Errorf("db: déclaration du rôle d'exécution : %w", err)
		}
	}
	for _, m := range pending {
		if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
			return nil, fmt.Errorf("db: migration %s : %w", m.Name, err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO "+MigrationsTable+" (version, name, checksum) VALUES ($1, $2, $3)",
			m.Version, m.Name, m.Checksum); err != nil {
			return nil, fmt.Errorf("db: enregistrement de %s : %w", m.Name, err)
		}
		logger.Info("migration appliquée", "migration", m.Name)
	}
	if err := CheckOrgIsolation(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("db: validation des migrations : %w", err)
	}
	return pending, nil
}

func bootstrap(ctx context.Context, owner *sql.DB, appRole string) error {
	tx, err := owner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: création de %s : %w", MigrationsTable, err)
	}
	defer func() { _ = tx.Rollback() }()
	stmts := []string{
		fmt.Sprintf("SELECT pg_advisory_xact_lock(%d)", bootstrapLockKey),
		`CREATE TABLE IF NOT EXISTS ` + MigrationsTable + ` (
			version    integer PRIMARY KEY CHECK (version > 0),
			name       text NOT NULL UNIQUE,
			checksum   text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
			applied_at timestamptz NOT NULL DEFAULT now()
		)`,
		// La table précède 001_init et ses privilèges par défaut : lecture accordée ici, pour
		// que le rôle d'exécution vérifie le schéma (VerifySchema, /readyz).
		"GRANT SELECT ON " + MigrationsTable + " TO " + pgx.Identifier{appRole}.Sanitize(),
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("db: création de %s : %w", MigrationsTable, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: création de %s : %w", MigrationsTable, err)
	}
	return nil
}

func lock(ctx context.Context, tx *sql.Tx, timeout time.Duration) error {
	if timeout > 0 {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('lock_timeout', $1, true)",
			strconv.FormatInt(timeout.Milliseconds(), 10)+"ms"); err != nil {
			return fmt.Errorf("db: délai du verrou de migration : %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, "LOCK TABLE "+MigrationsTable+" IN EXCLUSIVE MODE"); err != nil {
		return fmt.Errorf("db: verrou de migration : %w", err)
	}
	// Le délai ne concerne que l'attente d'une autre instance, pas les migrations.
	if timeout > 0 {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('lock_timeout', '0', true)"); err != nil {
			return fmt.Errorf("db: délai du verrou de migration : %w", err)
		}
	}
	return nil
}

type appliedMigration struct {
	Name     string
	Checksum string
}

func readApplied(ctx context.Context, q Querier) (map[int]appliedMigration, error) {
	rows, err := q.QueryContext(ctx, "SELECT version, name, checksum FROM "+MigrationsTable)
	if err != nil {
		return nil, fmt.Errorf("db: lecture de %s : %w", MigrationsTable, err)
	}
	defer rows.Close()
	out := map[int]appliedMigration{}
	for rows.Next() {
		var v int
		var a appliedMigration
		if err := rows.Scan(&v, &a.Name, &a.Checksum); err != nil {
			return nil, fmt.Errorf("db: lecture de %s : %w", MigrationsTable, err)
		}
		out[v] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: lecture de %s : %w", MigrationsTable, err)
	}
	return out, nil
}

// pendingMigrations compare les migrations connues à celles de la base : toute
// divergence d'une migration appliquée est fatale.
func pendingMigrations(all []Migration, applied map[int]appliedMigration) ([]Migration, error) {
	known := make(map[int]bool, len(all))
	var pending []Migration
	for _, m := range all {
		known[m.Version] = true
		a, ok := applied[m.Version]
		if !ok {
			pending = append(pending, m)
			continue
		}
		if a.Name != m.Name || a.Checksum != m.Checksum {
			return nil, fmt.Errorf("%w : %s (enregistrée : %s, somme %s ; embarquée : somme %s)",
				ErrChecksumMismatch, m.Name, a.Name, a.Checksum, m.Checksum)
		}
	}
	var unknown []string
	for v, a := range applied {
		if !known[v] {
			unknown = append(unknown, a.Name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return nil, fmt.Errorf("%w : %s", ErrUnknownMigration, strings.Join(unknown, ", "))
	}
	return pending, nil
}

// VerifySchema vérifie, avec n'importe quel rôle qui lit MigrationsTable, que toutes les
// migrations embarquées sont appliquées et inchangées. Le serveur l'exécute au démarrage
// et /readyz à chaque sonde.
func VerifySchema(ctx context.Context, q Querier, fsys fs.FS) error {
	if fsys == nil {
		fsys = migrations.FS
	}
	all, err := LoadMigrations(fsys)
	if err != nil {
		return err
	}
	var exists bool
	if err := q.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", MigrationsTable).Scan(&exists); err != nil {
		return fmt.Errorf("db: lecture de %s : %w", MigrationsTable, err)
	}
	applied := map[int]appliedMigration{}
	if exists {
		if applied, err = readApplied(ctx, q); err != nil {
			return err
		}
	}
	pending, err := pendingMigrations(all, applied)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		names := make([]string, len(pending))
		for i, m := range pending {
			names[i] = m.Name
		}
		return fmt.Errorf("%w : %s", ErrPendingMigrations, strings.Join(names, ", "))
	}
	return nil
}
