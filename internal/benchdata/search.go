package benchdata

import (
	"context"
	"fmt"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// SearchVersions est le nombre de versions de pkg:npm/lodash ajoutées par
// AddSearchFixtures (4.17.0 à 4.17.<SearchVersions-2>, plus « latest », illisible selon
// npm).
const SearchVersions = 31

// SearchHashes est le nombre de composants qui reçoivent une empreinte SHA-256 :
// sha256:<i en hexadécimal sur 64 caractères> pour lib-<i>, i < SearchHashes.
const SearchHashes = 1000

// AddSearchFixtures complète un jeu produit par Generate pour les mesures de la recherche
// (T09) : un paquet présent dans chaque projet à une version qui varie (le cas le plus
// lourd d'une plage vers, une occurrence par projet), et des empreintes de fichier. Le
// jeu de Generate n'a qu'une version par paquet et aucune empreinte.
func AddSearchFixtures(ctx context.Context, pool *db.Pool, org tenant.OrgID) error {
	steps := []struct {
		what  string
		query string
		args  []any
	}{
		{"lodash", `INSERT INTO components (org_id, id, purl, purl_base, type, name, version)
			SELECT $1, gen_random_uuid(), 'pkg:npm/lodash@' || v, 'pkg:npm/lodash', 'npm', 'lodash', v
			  FROM (SELECT CASE WHEN g = $2 - 1 THEN 'latest' ELSE '4.17.' || g END AS v FROM generate_series(0, $2 - 1) g) x`,
			[]any{org, SearchVersions}},
		{"liens de lodash", `INSERT INTO component_set_items (org_id, set_id, component_id, origin)
			SELECT s.org_id, s.set_id, c.id, 'syft'
			  FROM (SELECT rc.org_id, rc.set_id, row_number() OVER (ORDER BY rc.ref_id) AS k FROM ref_current rc) s
			  JOIN components c ON c.purl_base = 'pkg:npm/lodash'
			   AND c.version = CASE WHEN s.k % $1 = $1 - 1 THEN 'latest' ELSE '4.17.' || (s.k % $1) END`,
			[]any{SearchVersions}},
		{"empreintes", `UPDATE components SET hashes = ARRAY['sha256:' || lpad(to_hex(substr(name, 5)::int), 64, '0')]
			WHERE name LIKE 'lib-%' AND substr(name, 5)::int < $1`, []any{SearchHashes}},
	}
	err := pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, s := range steps {
			if _, err := tx.ExecContext(ctx, s.query, s.args...); err != nil {
				return fmt.Errorf("%s : %w", s.what, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("benchdata: recherche : %w", err)
	}
	return nil
}

// SearchHash renvoie l'empreinte donnée par AddSearchFixtures au composant lib-<i>.
func SearchHash(i int) string { return fmt.Sprintf("sha256:%064x", i) }
