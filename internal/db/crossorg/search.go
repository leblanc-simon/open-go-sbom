package crossorg

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
)

// MaxSearchComponents borne les composants renvoyés par ComponentsByName et
// ComponentsByHash.
const MaxSearchComponents = 1000

// ComponentMatches est le résultat d'une recherche de composants par nom ou empreinte.
type ComponentMatches struct {
	IDs []uuid.UUID
	// Truncated : plus de MaxSearchComponents composants correspondent.
	Truncated bool
	// Approx : aucun nom ne contient la requête, les composants sont ceux dont le nom lui
	// ressemble (trigrammes).
	Approx bool
}

// ComponentsByName renvoie les composants de l'organisation de tx dont le nom contient
// query (sans casse), ou à défaut lui ressemble, du plus pertinent au moins pertinent
// (fonction lotor_search_component_names, ADR 0024).
//
// Ce n'est pas une lecture inter-organisations : la fonction applique elle-même la
// condition de la RLS (organisation déclarée par InOrg) pour que l'index trigramme serve,
// ce que la RLS empêche sur un opérateur non LEAKPROOF. Elle exige donc une *db.OrgTx.
func ComponentsByName(ctx context.Context, tx *db.OrgTx, query string) (ComponentMatches, error) {
	return componentMatches(ctx, tx, `SELECT component_id, approx FROM lotor_search_component_names($1, $2)`, query)
}

// ComponentsByHash renvoie les composants de l'organisation de tx qui portent l'empreinte
// hash (« sha256:<hex> », fonction lotor_search_component_hashes, même principe que
// ComponentsByName pour l'index GIN des tableaux).
func ComponentsByHash(ctx context.Context, tx *db.OrgTx, hash string) (ComponentMatches, error) {
	return componentMatches(ctx, tx, `SELECT component_id, false FROM lotor_search_component_hashes($1, $2)`, hash)
}

func componentMatches(ctx context.Context, tx *db.OrgTx, query, arg string) (ComponentMatches, error) {
	rows, err := tx.QueryContext(ctx, query, arg, MaxSearchComponents+1)
	if err != nil {
		return ComponentMatches{}, fmt.Errorf("crossorg: recherche de composants : %w", err)
	}
	defer rows.Close()
	var m ComponentMatches
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id, &m.Approx); err != nil {
			return ComponentMatches{}, fmt.Errorf("crossorg: recherche de composants : %w", err)
		}
		if len(m.IDs) == MaxSearchComponents {
			m.Truncated = true
			break
		}
		m.IDs = append(m.IDs, id)
	}
	if err := rows.Err(); err != nil {
		return ComponentMatches{}, fmt.Errorf("crossorg: recherche de composants : %w", err)
	}
	return m, nil
}
