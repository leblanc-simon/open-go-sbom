package account

import (
	"context"
	"fmt"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
)

// ReconfigureTOTP retire le second facteur du compte id à sa propre demande, après une
// réauthentification par un code TOTP ou un code de secours (vérifiée par l'appelant) :
// secret, défis et codes de secours sont supprimés et toutes ses sessions fermées. Le TOTP
// reste obligatoire : la connexion suivante (mot de passe) mène à un nouvel enrôlement, qui
// tire un nouveau jeu de codes. Contrairement à la réinitialisation par un administrateur,
// le mot de passe et les jetons personnels sont gardés : le titulaire a prouvé qu'il
// détient un facteur, rien n'indique une compromission.
func (s *Service) ReconfigureTOTP(ctx context.Context, actor audit.Actor, id int64) error {
	err := s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		for _, q := range []string{
			`DELETE FROM mfa_totp WHERE user_id = $1`,
			`DELETE FROM mfa_challenges WHERE user_id = $1`,
			`DELETE FROM mfa_recovery_codes WHERE user_id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, u.ID); err != nil {
				return audit.Event{}, err
			}
		}
		if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountTOTPReconfigured, u, nil), nil
	})
	if err != nil {
		return fmt.Errorf("account: reconfiguration du TOTP du compte %d : %w", id, err)
	}
	return nil
}
