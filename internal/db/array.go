package db

import (
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Array permet de relire un tableau PostgreSQL dans une slice Go à travers database/sql :
//
//	var tags []string
//	err := row.Scan(db.Array(&tags))
//
// Les tableaux passent en paramètre sans aide ($1::text[] avec une []string) ; c'est la
// lecture que database/sql ne sait pas faire seule avec pgx. Une pgtype.Map n'est pas sûre
// en concurrence : chaque appel en crée une.
func Array[T any](dst *[]T) sql.Scanner {
	m := pgtype.NewMap()
	// pgx ne connaît pas uuid.UUID (seulement [16]byte) : sans cela, []uuid.UUID échoue.
	m.RegisterDefaultPgType((*uuid.UUID)(nil), "uuid")
	m.RegisterDefaultPgType((*[]uuid.UUID)(nil), "_uuid")
	return m.SQLScanner(dst)
}
