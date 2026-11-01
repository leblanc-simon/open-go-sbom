package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
)

// CheckReconfigurePassword valide le nouveau mot de passe d'une reconfiguration du TOTP
// (ReconfigureTOTP) sans rien modifier. L'appelant l'appelle avant de consommer le code
// de réauthentification : un mot de passe refusé ne doit pas coûter un code de secours.
func (s *Service) CheckReconfigurePassword(ctx context.Context, id int64, next, confirm string) error {
	_, err := s.checkNewPassword(ctx, id, next, confirm)
	return err
}

// checkNewPassword vérifie qu'un nouveau mot de passe est confirmé, conforme et différent
// de l'actuel ; il renvoie son empreinte bcrypt.
func (s *Service) checkNewPassword(ctx context.Context, id int64, next, confirm string) (string, error) {
	if next != confirm {
		return "", &ValidationError{Field: "confirm", Key: KeyPasswordMismatch}
	}
	var hash, email string
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT password_hash, email FROM users WHERE id = $1`, id).Scan(&hash, &email)
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("account: lecture du compte %d : %w", id, err)
	}
	if err := ValidatePassword(next, email); err != nil {
		return "", err
	}
	if err := authx.CheckPassword(hash, next); err == nil {
		return "", &ValidationError{Field: "password", Key: KeyPasswordUnchanged}
	} else if !errors.Is(err, authx.ErrInvalidCredentials) {
		return "", fmt.Errorf("account: vérification du mot de passe : %w", err)
	}
	newHash, err := authx.HashPassword(next, s.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("account: hachage : %w", err)
	}
	return newHash, nil
}

// ReconfigureTOTP retire le second facteur du compte id à sa propre demande, après une
// réauthentification par un code TOTP ou un code de secours (vérifiée par l'appelant) :
// secret, défis et codes de secours sont supprimés, toutes ses sessions fermées, et le mot
// de passe remplacé par next. Le TOTP reste obligatoire : la connexion suivante, avec ce
// nouveau mot de passe, mène à un nouvel enrôlement, qui tire un nouveau jeu de codes.
//
// Le nouveau mot de passe ferme la fenêtre « mot de passe seul » (SEC2-06) : sans TOTP, le
// premier qui donne le mot de passe enrôle son application. Un attaquant qui connaîtrait
// l'ancien (hameçonnage, arrêté jusque-là par le TOTP) ne peut pas profiter de l'intervalle
// avant la reconnexion du titulaire. Les jetons personnels sont gardés : le titulaire a
// prouvé qu'il détient un facteur.
func (s *Service) ReconfigureTOTP(ctx context.Context, actor audit.Actor, id int64, next, confirm string) error {
	newHash, err := s.checkNewPassword(ctx, id, next, confirm)
	if err != nil {
		return err
	}
	err = s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		for _, q := range []string{
			`DELETE FROM mfa_totp WHERE user_id = $1`,
			`DELETE FROM mfa_challenges WHERE user_id = $1`,
			`DELETE FROM mfa_recovery_codes WHERE user_id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, u.ID); err != nil {
				return audit.Event{}, err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = $1, must_change_pwd = 0 WHERE id = $2`, newHash, u.ID); err != nil {
			return audit.Event{}, err
		}
		if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountTOTPReconfigured, u, map[string]string{"password_changed": "true"}), nil
	})
	if err != nil {
		return fmt.Errorf("account: reconfiguration du TOTP du compte %d : %w", id, err)
	}
	return nil
}
