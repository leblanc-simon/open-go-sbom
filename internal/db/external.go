package db

import (
	"context"
	"database/sql"

	"leblanc.io/open-go-base/appconf"
	authsql "leblanc.io/open-go-base/authx/sqlstore"
	mfasql "leblanc.io/open-go-base/mfax/sqlstore"
)

// externalSteps sont les migrations d'authx puis de mfax (tables users, sessions,
// mfa_totp, mfa_challenges). Migrate les joue toujours, sous le verrou et avant celles du
// projet, qui s'appuient sur elles (droits, clés étrangères vers users).
func externalSteps() []Step {
	return []Step{
		{Name: "authx", Run: func(_ context.Context, owner *sql.DB) error {
			return authsql.Migrate(owner, appconf.DialectPostgres)
		}},
		{Name: "mfax", Run: func(_ context.Context, owner *sql.DB) error {
			return mfasql.Migrate(owner, appconf.DialectPostgres)
		}},
	}
}
