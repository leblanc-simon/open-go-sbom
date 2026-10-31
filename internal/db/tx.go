package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"leblanc.io/lotor/internal/tenant"
)

// Querier est ce dont une requête a besoin : Tx et OrgTx l'implémentent, ce qui permet à
// une fonction de travailler dans la transaction de son appelant (par exemple pour mettre
// un job en file avec la donnée qui le motive).
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx est une transaction sur les seules tables globales. Elle n'expose ni Commit ni
// Rollback : c'est InTx qui conclut.
type Tx struct {
	tx *sql.Tx
}

// ExecContext exécute une requête sans résultat.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

// QueryContext exécute une requête qui renvoie des lignes.
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

// QueryRowContext exécute une requête qui renvoie au plus une ligne.
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, query, args...)
}

// OrgTx est une transaction dans laquelle l'organisation est déclarée à PostgreSQL : la
// RLS limite chaque lecture et chaque écriture à cette organisation.
type OrgTx struct {
	Tx
	org tenant.OrgID
}

// OrgID renvoie l'organisation déclarée pour la transaction.
func (t *OrgTx) OrgID() tenant.OrgID { return t.org }

// TxOption ajuste les options d'une transaction.
type TxOption func(*sql.TxOptions)

// ReadOnly ouvre une transaction en lecture seule.
func ReadOnly() TxOption { return func(o *sql.TxOptions) { o.ReadOnly = true } }

// Isolation fixe le niveau d'isolement (READ COMMITTED par défaut).
func Isolation(level sql.IsolationLevel) TxOption {
	return func(o *sql.TxOptions) { o.Isolation = level }
}

// Pool est le pool du rôle d'exécution. Toute donnée d'organisation passe par InOrg,
// les tables globales par InTx.
type Pool struct {
	db *sql.DB
}

// NewPool enveloppe un pool ouvert par Open.
func NewPool(db *sql.DB) *Pool { return &Pool{db: db} }

// DB renvoie le *sql.DB sous-jacent, pour les stores d'authx et de mfax qui l'exigent.
// Hors transaction, une table d'organisation reste inaccessible : la RLS échoue faute
// d'organisation déclarée.
func (p *Pool) DB() *sql.DB { return p.db }

// Ping vérifie que la base répond.
func (p *Pool) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

// Close ferme le pool.
func (p *Pool) Close() error { return p.db.Close() }

// InTx exécute fn dans une transaction réservée aux tables globales. La transaction est
// validée si fn renvoie nil, annulée sinon (et en cas de panique, relancée ensuite).
func (p *Pool) InTx(ctx context.Context, fn func(*Tx) error, opts ...TxOption) error {
	return p.run(ctx, opts, func(tx *sql.Tx) error {
		return fn(&Tx{tx: tx})
	})
}

// InOrg exécute fn dans une transaction où l'organisation org est déclarée par
// set_config('lotor.org_id', …, true). La déclaration ne vaut que pour la transaction,
// ce qui la rend sûre avec un pool et avec pgbouncer en mode session.
func (p *Pool) InOrg(ctx context.Context, org tenant.OrgID, fn func(*OrgTx) error, opts ...TxOption) error {
	if org.IsZero() {
		return tenant.ErrZeroOrgID
	}
	return p.run(ctx, opts, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('lotor.org_id', $1, true)", org.String()); err != nil {
			return fmt.Errorf("db: déclaration de l'organisation : %w", err)
		}
		return fn(&OrgTx{Tx: Tx{tx: tx}, org: org})
	})
}

func (p *Pool) run(ctx context.Context, opts []TxOption, fn func(*sql.Tx) error) (err error) {
	var o sql.TxOptions
	for _, opt := range opts {
		opt(&o)
	}
	tx, err := p.db.BeginTx(ctx, &o)
	if err != nil {
		return fmt.Errorf("db: ouverture de transaction : %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return errors.Join(err, fmt.Errorf("db: annulation : %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: validation : %w", err)
	}
	return nil
}
