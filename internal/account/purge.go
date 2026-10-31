package account

import (
	"context"
	"fmt"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/jobs"
)

// PurgeKind est le type du job qui supprime sessions et défis TOTP expirés ; le
// déclencheur de session_auth emporte leurs méthodes.
const PurgeKind = "auth.purge"

// PurgeSchedule passe toutes les heures.
func PurgeSchedule() jobs.Schedule {
	return jobs.Schedule{Name: PurgeKind, Every: time.Hour, Job: jobs.Job{Kind: PurgeKind}}
}

// PurgeExpired supprime les sessions et les défis TOTP expirés, et renvoie leur nombre.
// Idempotent : une seconde exécution ne trouve plus rien.
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		for _, q := range []string{
			`DELETE FROM sessions WHERE expires_at < now()`,
			`DELETE FROM mfa_challenges WHERE expires_at < now()`,
		} {
			res, err := tx.ExecContext(ctx, q)
			if err != nil {
				return err
			}
			c, _ := res.RowsAffected()
			n += c
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("account: purge des sessions expirées : %w", err)
	}
	return n, nil
}

// PurgeHandler est le handler du job PurgeKind.
func (s *Service) PurgeHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		_, err := s.PurgeExpired(ctx)
		return err
	})
}
