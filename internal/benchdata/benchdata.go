// Package benchdata génère le jeu de données synthétique des mesures (docs/benchmarks.md) :
// une organisation de N projets, un million de liens composant × ensemble, un catalogue de
// vulnérabilités et des constats réalistes. Il écrit directement en SQL, par lots
// generate_series, sous la RLS de l'organisation (db.InOrg) : quelques dizaines de
// secondes pour le jeu complet. Réservé aux mesures et aux tests : aucun binaire ne
// l'importe.
//
// Distribution, déterministe (même jeu à paramètres égaux) :
//   - composants répartis sur cinq écosystèmes (npm, maven, pypi, golang, deb), nommés
//     lib-<i> ; chaque projet a un ensemble de Links/Projects composants distincts, choisis
//     par un pas multiplicatif modulo Components (nombre premier conseillé) ;
//   - un composant sur VulnerableEvery a une vulnérabilité, un sur 2×VulnerableEvery en a
//     une seconde ; sévérités 2 % critique, 15 % élevée, 50 % moyenne, 30 % faible, 3 %
//     inconnue ; 1 % des vulnérabilités sont KEV ; EPSS uniforme ;
//   - un constat sur dix est résolu.
package benchdata

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// Params dimensionne le jeu.
type Params struct {
	Projects        int
	Links           int // liens composant × ensemble, au total
	Components      int // composants distincts de l'organisation
	Vulnerabilities int
	VulnerableEvery int
}

// Reference est le jeu de référence des cibles chiffrées (§ 13 de l'architecture) :
// 1 000 projets, 1 million de liens.
func Reference() Params {
	return Params{Projects: 1000, Links: 1_000_000, Components: 60_013, Vulnerabilities: 5_000, VulnerableEvery: 20}
}

// Stats décrit le jeu produit.
type Stats struct {
	Projects   int
	Links      int
	Components int
	Findings   int
	Open       int
	Duration   time.Duration
}

func (p Params) validate() error {
	switch {
	case p.Projects < 1, p.Components < 1, p.Vulnerabilities < 1, p.VulnerableEvery < 1:
		return errors.New("benchdata: paramètres nuls")
	case p.Links < p.Projects || p.Links/p.Projects > p.Components:
		return fmt.Errorf("benchdata: %d liens pour %d projets et %d composants", p.Links, p.Projects, p.Components)
	}
	return nil
}

// Generate crée l'organisation org (slug) et son jeu de données. Elle prend le pool du
// rôle d'exécution : le jeu passe par la RLS comme les données réelles.
func Generate(ctx context.Context, pool *db.Pool, org tenant.OrgID, slug string, p Params) (Stats, error) {
	if err := p.validate(); err != nil {
		return Stats{}, err
	}
	start := time.Now()
	perSet := p.Links / p.Projects
	// Le catalogue est global : une transaction à part.
	if err := pool.InTx(ctx, func(tx *db.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO vulnerabilities (id, source_rank, severity, cvss_score, epss, epss_percentile, kev, risk, description,
			                             vulndb_built, updated_at)
			SELECT 'CVE-2099-' || lpad(g::text, 5, '0'), 0,
			       CASE WHEN g % 50 = 0 THEN 'critical' WHEN g % 100 < 17 THEN 'high' WHEN g % 100 < 67 THEN 'medium'
			            WHEN g % 100 < 97 THEN 'low' ELSE 'unknown' END,
			       round((1 + (g * 37 % 90) / 10.0)::numeric, 1), (g * 7919 % 100000) / 100000.0, (g * 104729 % 100000) / 100000.0,
			       g % 100 = 0, (g * 31 % 10000) / 100.0, 'Vulnérabilité synthétique ' || g, $1, $1
			  FROM generate_series(1, $2) g
			ON CONFLICT (id) DO NOTHING`, start, p.Vulnerabilities)
		return err
	}); err != nil {
		return Stats{}, fmt.Errorf("benchdata: catalogue : %w", err)
	}
	steps := []struct {
		what  string
		query string
		args  []any
	}{
		{"organisation", `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $2, 'fr')`,
			[]any{org, slug}},
		{"projets", `INSERT INTO projects (org_id, id, kind, slug, name)
			SELECT $1, gen_random_uuid(), 'repo', 'p-' || g, 'Projet ' || g FROM generate_series(1, $2) g`, []any{org, p.Projects}},
		{"références", `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			SELECT org_id, gen_random_uuid(), id, 'repo', 'branch', 'main' FROM projects`, nil},
		{"composants", `INSERT INTO components (org_id, id, purl, purl_base, type, name, version)
			SELECT $1, gen_random_uuid(),
			       'pkg:' || e.t || '/' || e.ns || 'lib-' || g || '@1.' || (g % 7) || '.' || (g % 10),
			       'pkg:' || e.t || '/' || e.ns || 'lib-' || g, e.t, 'lib-' || g, '1.' || (g % 7) || '.' || (g % 10)
			  FROM generate_series(0, $2 - 1) g
			  CROSS JOIN LATERAL (SELECT (ARRAY['npm', 'maven', 'pypi', 'golang', 'deb'])[g % 5 + 1] AS t,
			                             (ARRAY['', 'org.bench/', '', 'example.org/', 'debian/'])[g % 5 + 1] AS ns) e`,
			[]any{org, p.Components}},
		{"SBOM", `INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content)
			VALUES ($1, gen_random_uuid(), sha256('bench'::bytea), 2, 1, '\x00'::bytea)`, []any{org}},
		{"ensembles", `INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
			SELECT org_id, gen_random_uuid(), sha256(id::text::bytea), $1, $1, 0, 0 FROM projects`, []any{perSet}},
		// Ensemble k (rang du projet) : composants (j × a + k × b) mod C, j < perSet, tous
		// distincts quand a est premier avec C.
		{"liens", `INSERT INTO component_set_items (org_id, set_id, component_id, origin)
			SELECT s.org_id, s.id, c.id, 'syft'
			  FROM (SELECT cs.org_id, cs.id, row_number() OVER (ORDER BY p.slug) AS k
			          FROM component_sets cs JOIN projects p ON sha256(p.id::text::bytea) = cs.fingerprint) s
			  CROSS JOIN generate_series(0, $1 - 1) j
			  JOIN components c ON c.name = 'lib-' || ((j::bigint * 7919 + s.k * 104729) % $2)
			ON CONFLICT DO NOTHING`, []any{perSet, p.Components}},
		{"instantanés", `INSERT INTO snapshots (org_id, id, project_id, ref_id, commit_sha, scanned_at, last_scanned_at, blob_id, set_id,
			                       format, spec_version, created_at, updated_at)
			SELECT r.org_id, gen_random_uuid(), r.project_id, r.id, encode(sha256(r.id::text::bytea), 'hex'),
			       now() - interval '1 hour', now() - interval '1 hour', b.id, cs.id, 'cyclonedx', '1.6', now(), now()
			  FROM tracked_refs r
			  JOIN component_sets cs ON cs.fingerprint = sha256(r.project_id::text::bytea)
			  CROSS JOIN (SELECT id FROM sbom_blobs LIMIT 1) b`, nil},
		{"état courant", `INSERT INTO ref_current (org_id, ref_id, project_id, snapshot_id, set_id, updated_at)
			SELECT org_id, ref_id, project_id, id, set_id, now() FROM snapshots`, nil},
		{"constats", `INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, resolution, severity,
			                      cvss_score, epss, epss_percentile, kev, risk, fixed_versions, fix_state, match_type,
			                      first_seen_at, last_seen_at, resolved_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
			SELECT s.org_id, gen_random_uuid(), s.project_id, s.ref_id, c.id, v.id,
			       CASE WHEN h % 10 = 0 THEN 'resolved' ELSE 'open' END,
			       CASE WHEN h % 10 = 0 THEN 'component_removed' END,
			       v.severity, v.cvss_score, v.epss, v.epss_percentile, v.kev, v.risk, ARRAY['9.9.9'], 'fixed', 'exact-direct',
			       now() - interval '30 days', now() - interval '1 hour',
			       CASE WHEN h % 10 = 0 THEN now() - interval '2 hours' END,
			       s.id, $3, now(), now()
			  FROM snapshots s
			  JOIN component_set_items i ON i.org_id = s.org_id AND i.set_id = s.set_id
			  JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id
			  CROSS JOIN LATERAL (SELECT substr(c.name, 5)::int AS idx) n
			  CROSS JOIN LATERAL (VALUES (n.idx % $1), ((n.idx * 7) % $1 + 1)) AS pick(v)
			  JOIN vulnerabilities v ON v.id = 'CVE-2099-' || lpad((pick.v % $4 + 1)::text, 5, '0')
			  CROSS JOIN LATERAL (SELECT abs(hashtext(s.id::text || c.id::text || v.id)) AS h) hh
			 WHERE n.idx % $2 = 0 AND (pick.v = n.idx % $1 OR n.idx % ($2 * 2) = 0)
			ON CONFLICT DO NOTHING`,
			[]any{p.Vulnerabilities, p.VulnerableEvery, org.UUID(), p.Vulnerabilities}},
		{"analyses", `INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive, vulndb_built,
			                          analyzed_at, match_count, unmatched_count)
			SELECT org_id, ref_id, project_id, set_id, snapshot_id, $1, now(), now(), 0, 0 FROM ref_current`, []any{org.UUID()}},
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
		return Stats{}, fmt.Errorf("benchdata: %w", err)
	}
	st := Stats{Duration: time.Since(start)}
	err = pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM projects), (SELECT count(*) FROM component_set_items),
			(SELECT count(*) FROM components), (SELECT count(*) FROM findings), (SELECT count(*) FROM findings WHERE status = 'open')`).
			Scan(&st.Projects, &st.Links, &st.Components, &st.Findings, &st.Open)
	}, db.ReadOnly())
	return st, err
}

// String résume le jeu pour les journaux de mesure.
func (s Stats) String() string {
	return strings.Join([]string{
		fmt.Sprintf("%d projets", s.Projects), fmt.Sprintf("%d liens", s.Links), fmt.Sprintf("%d composants", s.Components),
		fmt.Sprintf("%d constats (%d ouverts)", s.Findings, s.Open), fmt.Sprintf("généré en %s", s.Duration.Round(time.Millisecond)),
	}, ", ")
}
