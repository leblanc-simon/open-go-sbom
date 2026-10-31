package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// Settings sont les préférences d'un compte. Une valeur vide laisse le choix au reste de
// l'ordre (langue : § 18 ; thème : celui du système ou de la bascule).
type Settings struct {
	Language   string // "", "fr" ou "en"
	Theme      string // "", "light" ou "dark"
	DefaultOrg tenant.OrgID
}

// Languages et Themes sont les valeurs acceptées (en plus du vide).
var (
	Languages = []string{"fr", "en"}
	Themes    = []string{"light", "dark"}
)

// Settings renvoie les préférences d'un compte (vides s'il n'en a pas enregistré).
func (s *Service) Settings(ctx context.Context, userID int64) (Settings, error) {
	var out Settings
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		var lang, theme sql.NullString
		var org sql.Null[tenant.OrgID]
		err := tx.QueryRowContext(ctx,
			`SELECT language, theme, default_org_id FROM account_settings WHERE user_id = $1`, userID,
		).Scan(&lang, &theme, &org)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = Settings{Language: lang.String, Theme: theme.String}
		if org.Valid {
			out.DefaultOrg = org.V
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return Settings{}, fmt.Errorf("account: préférences du compte %d : %w", userID, err)
	}
	return out, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SaveSettings enregistre les préférences d'un compte. L'organisation par défaut doit être
// une organisation active dont il est membre.
func (s *Service) SaveSettings(ctx context.Context, actor audit.Actor, userID int64, set Settings) error {
	if set.Language != "" && !slices.Contains(Languages, set.Language) {
		return &ValidationError{Field: "language", Key: KeyLanguageInvalid}
	}
	if set.Theme != "" && !slices.Contains(Themes, set.Theme) {
		return &ValidationError{Field: "theme", Key: KeyThemeInvalid}
	}
	return s.update(ctx, actor, userID, func(tx *db.Tx, u User) (audit.Event, error) {
		var org any
		if !set.DefaultOrg.IsZero() {
			orgs, err := crossorg.UserOrgs(ctx, tx, userID)
			if err != nil {
				return audit.Event{}, err
			}
			if !slices.ContainsFunc(orgs, func(o crossorg.OrgRef) bool { return o.Org == set.DefaultOrg }) {
				return audit.Event{}, &ValidationError{Field: "default_org", Key: KeyDefaultOrgInvalid}
			}
			org = set.DefaultOrg
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO account_settings (user_id, language, theme, default_org_id, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (user_id) DO UPDATE
			   SET language = excluded.language, theme = excluded.theme,
			       default_org_id = excluded.default_org_id, updated_at = now()`,
			userID, nullable(set.Language), nullable(set.Theme), org); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountSettingsChanged, u, map[string]string{"language": set.Language, "theme": set.Theme}), nil
	})
}
