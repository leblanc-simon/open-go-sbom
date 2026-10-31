package account

import (
	"context"
	"fmt"
	"log/slog"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/secret"
)

// StartupOptions reprend le fragment bootstrap de la configuration.
type StartupOptions struct {
	AdminEmail     string
	AdminPassword  string
	RescueEmail    string
	RescueTicket   string
	RescuePassword string
}

// Startup applique au démarrage du serveur le premier administrateur, la procédure de
// secours et le rechiffrement des secrets TOTP par la clé active. Une erreur doit empêcher
// le démarrage. Les journaux rappellent de retirer de la configuration ce qui a servi.
func (s *Service) Startup(ctx context.Context, o StartupOptions, pool *db.Pool, box *secret.Box, logger *slog.Logger) error {
	if o.AdminEmail != "" {
		created, err := s.Bootstrap(ctx, o.AdminEmail, o.AdminPassword)
		if err != nil {
			return fmt.Errorf("bootstrap.admin_email : %w", err)
		}
		if created {
			logger.Warn("premier administrateur créé : retirer bootstrap.admin_email et bootstrap.admin_password de la configuration")
		} else {
			logger.Info("bootstrap ignoré, des comptes existent déjà : retirer bootstrap.admin_email et bootstrap.admin_password de la configuration")
		}
	} else if n, err := s.ActiveAdmins(ctx); err != nil {
		return err
	} else if n == 0 {
		logger.Warn("aucun administrateur d'instance actif : bootstrap.* sur une base vide, sinon procédure de docs/operations.md")
	}
	if o.RescueEmail != "" {
		applied, err := s.RescueTOTP(ctx, o.RescueEmail, o.RescueTicket, o.RescuePassword)
		if err != nil {
			return fmt.Errorf("bootstrap.rescue_totp_email : %w", err)
		}
		if applied {
			logger.Warn("procédure de secours appliquée, TOTP et mot de passe réinitialisés : retirer bootstrap.rescue_totp_email, bootstrap.rescue_ticket et bootstrap.rescue_password", "ticket", o.RescueTicket)
		} else {
			logger.Warn("procédure de secours déjà appliquée pour ce ticket : retirer bootstrap.rescue_totp_email, bootstrap.rescue_ticket et bootstrap.rescue_password", "ticket", o.RescueTicket)
		}
	}
	n, err := RotateTOTPSecrets(ctx, pool, box)
	if err != nil {
		return err
	}
	if n > 0 {
		logger.Info("secrets TOTP rechiffrés avec la clé active", "count", n, "key", box.ActiveKeyID())
	}
	return nil
}
