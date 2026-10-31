package account

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
)

// Method est la méthode d'authentification d'une session (table session_auth).
type Method string

const (
	// MethodLocalTOTP : mot de passe local et TOTP.
	MethodLocalTOTP Method = "local_totp"
	// MethodSSO : fournisseur d'identité d'une organisation (T25).
	MethodSSO Method = "sso"
)

// storeTimeout borne une écriture faite pour le compte d'authx ou de mfax, dont les
// interfaces de stockage ne transmettent pas de contexte.
const storeTimeout = 10 * time.Second

func sessionHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// SessionRecorder enveloppe le SessionStore d'authx : toute session pleinement
// authentifiée qu'il crée est enregistrée dans session_auth avec sa méthode et journalisée
// (connexion réussie). Avec mfax en enrôlement obligatoire, une telle session ne s'ouvre
// qu'après le TOTP : sa méthode est donc local_totp. Une session sans ligne dans
// session_auth est refusée par l'interface.
type SessionRecorder struct {
	authx.SessionStore
	pool *db.Pool
}

// NewSessionRecorder enveloppe inner.
func NewSessionRecorder(inner authx.SessionStore, pool *db.Pool) *SessionRecorder {
	return &SessionRecorder{SessionStore: inner, pool: pool}
}

// Create persiste la session puis, pour une session authentifiée, sa méthode et
// l'événement de connexion. En cas d'échec, la session est retirée : elle ne peut pas
// exister sans sa méthode.
func (r *SessionRecorder) Create(s *authx.Session) error {
	if err := r.SessionStore.Create(s); err != nil {
		return err
	}
	if s.Purpose != authx.PurposeAuth {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	err := r.pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO session_auth (session_hash, user_id, method) VALUES ($1, $2, $3)`,
			sessionHash(s.Token), s.UserID, string(MethodLocalTOTP)); err != nil {
			return err
		}
		var email string
		if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, s.UserID).Scan(&email); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, audit.Actor{UserID: s.UserID, Email: email, IP: s.IP},
			audit.Event{Action: audit.LoginSucceeded, TargetType: "account",
				TargetID: strconv.FormatInt(s.UserID, 10), TargetLabel: email,
				Details: map[string]string{"method": string(MethodLocalTOTP)}})
	})
	if err != nil {
		_ = r.SessionStore.Delete(s.Token)
		return fmt.Errorf("account: méthode de la session : %w", err)
	}
	return nil
}

// SessionMethod renvoie la méthode d'authentification de la session token ; ok est faux
// si la session n'en a pas.
func (s *Service) SessionMethod(ctx context.Context, token string) (m Method, ok bool, err error) {
	var method string
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT method FROM session_auth WHERE session_hash = $1`, sessionHash(token)).Scan(&method)
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("account: méthode de la session : %w", err)
	}
	return Method(method), true, nil
}
