package account

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// ViewerState est ce que l'interface vérifie et affiche à chaque requête d'un compte
// connecté, lu en une transaction.
type ViewerState struct {
	// Method est la méthode d'authentification de la session ; HasMethod est faux si la
	// session n'en a pas (elle est alors refusée).
	Method    Method
	HasMethod bool
	// AuthenticatedAt est l'instant de l'authentification de la session (mot de passe et
	// TOTP) : la durée absolue d'une session se compte depuis lui.
	AuthenticatedAt time.Time
	TOTPEnabled     bool
	Settings        Settings
	Orgs            []crossorg.OrgRef
}

// Viewer lit l'état du compte userID pour la session token.
func (s *Service) Viewer(ctx context.Context, userID int64, token string) (ViewerState, error) {
	var v ViewerState
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		var method, lang, theme sql.NullString
		var authAt sql.NullTime
		var org sql.Null[tenant.OrgID]
		var totp int
		if err := tx.QueryRowContext(ctx, `
			SELECT a.method, a.created_at,
			       coalesce((SELECT enabled FROM mfa_totp WHERE user_id = $1), 0),
			       s.language, s.theme, s.default_org_id
			  FROM (SELECT 1) one
			  LEFT JOIN session_auth a ON a.session_hash = $2 AND a.user_id = $1
			  LEFT JOIN account_settings s ON s.user_id = $1`,
			userID, sessionHash(token)).Scan(&method, &authAt, &totp, &lang, &theme, &org); err != nil {
			return err
		}
		v.Method, v.HasMethod = Method(method.String), method.Valid
		v.AuthenticatedAt = authAt.Time
		v.TOTPEnabled = totp == 1
		v.Settings = Settings{Language: lang.String, Theme: theme.String}
		if org.Valid {
			v.Settings.DefaultOrg = org.V
		}
		var err error
		v.Orgs, err = crossorg.UserOrgs(ctx, tx, userID)
		return err
	}, db.ReadOnly())
	if err != nil {
		return ViewerState{}, fmt.Errorf("account: état du compte %d : %w", userID, err)
	}
	return v, nil
}
