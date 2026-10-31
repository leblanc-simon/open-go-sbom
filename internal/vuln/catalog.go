package vuln

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"leblanc.io/lotor/internal/db"
)

// ErrNotFound : vulnérabilité absente du catalogue.
var ErrNotFound = errors.New("vuln: vulnérabilité inconnue")

// catalogChunk borne le nombre de lignes d'une insertion en lot.
const catalogChunk = 500

// sourceRank : 0 pour une fiche du NVD, 1 pour toute autre source.
func sourceRank(namespace string) int {
	if strings.HasPrefix(namespace, "nvd:") {
		return 0
	}
	return 1
}

func sep(s []string) string { return strings.Join(s, "\x1f") }

func dateOrNil(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.DateOnly)
}

// UpsertCatalog écrit les fiches dans le catalogue global, triées par identifiant (deux
// analyses concurrentes verrouillent leurs lignes communes dans le même ordre). Une fiche
// n'en remplace une autre que d'une source au moins aussi fiable (NVD d'abord) ; une
// fiche inchangée n'est pas réécrite.
func UpsertCatalog(ctx context.Context, q db.Querier, vs map[string]Vulnerability, built time.Time, now time.Time) error {
	ids := slices.Sorted(maps.Keys(vs))
	for start := 0; start < len(ids); start += catalogChunk {
		part := ids[start:min(start+catalogChunk, len(ids))]
		n := len(part)
		cols := make([][]string, 19)
		for i := range cols {
			cols[i] = make([]string, n)
		}
		for i, id := range part {
			v := vs[id]
			cvss, err := json.Marshal(nonNil(v.CVSS))
			if err != nil {
				return err
			}
			row := []string{id, sep(v.Aliases), v.Namespace, strconv.Itoa(sourceRank(v.Namespace)), string(v.Severity),
				"", string(cvss), v.Description, v.DataSource, sep(v.URLs), sep(v.CWEs), "", "", "",
				strconv.FormatBool(v.KEV != nil), "", "", "false", strconv.FormatFloat(v.Risk, 'f', 2, 64)}
			if s := v.BaseScore(); s > 0 {
				row[5] = strconv.FormatFloat(s, 'f', 1, 64)
			}
			if v.EPSS != nil {
				row[11], row[12] = strconv.FormatFloat(v.EPSS.Score, 'f', 5, 64), strconv.FormatFloat(v.EPSS.Percentile, 'f', 5, 64)
				if d := dateOrNil(&v.EPSS.Date); d != nil {
					row[13] = d.(string)
				}
			}
			if v.KEV != nil {
				if d := dateOrNil(v.KEV.DateAdded); d != nil {
					row[15] = d.(string)
				}
				if d := dateOrNil(v.KEV.DueDate); d != nil {
					row[16] = d.(string)
				}
				row[17] = strconv.FormatBool(v.KEV.Ransomware)
			}
			for c := range row {
				cols[c][i] = row[c]
			}
		}
		args := []any{built, now}
		for _, c := range cols {
			args = append(args, c)
		}
		if _, err := q.ExecContext(ctx, `
			INSERT INTO vulnerabilities (id, aliases, namespace, source_rank, severity, cvss_score, cvss, description,
			    data_source, urls, cwes, epss, epss_percentile, epss_date, kev, kev_added, kev_due, kev_ransomware, risk,
			    vulndb_built, updated_at)
			SELECT u.id, string_to_array(u.aliases, E'\x1f'), u.namespace, u.source_rank::smallint, u.severity,
			       NULLIF(u.cvss_score, '')::numeric, u.cvss::jsonb, u.description, u.data_source,
			       string_to_array(u.urls, E'\x1f'), string_to_array(u.cwes, E'\x1f'),
			       NULLIF(u.epss, '')::numeric, NULLIF(u.epss_percentile, '')::numeric, NULLIF(u.epss_date, '')::date,
			       u.kev::boolean, NULLIF(u.kev_added, '')::date, NULLIF(u.kev_due, '')::date, u.kev_ransomware::boolean,
			       u.risk::numeric, $1, $2
			  FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[],
			              $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[], $17::text[],
			              $18::text[], $19::text[], $20::text[], $21::text[])
			       AS u(id, aliases, namespace, source_rank, severity, cvss_score, cvss, description, data_source, urls, cwes,
			            epss, epss_percentile, epss_date, kev, kev_added, kev_due, kev_ransomware, risk)
			 ORDER BY u.id
			ON CONFLICT (id) DO UPDATE SET
			    aliases = EXCLUDED.aliases, namespace = EXCLUDED.namespace, source_rank = EXCLUDED.source_rank,
			    severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score, cvss = EXCLUDED.cvss,
			    description = EXCLUDED.description, data_source = EXCLUDED.data_source, urls = EXCLUDED.urls,
			    cwes = EXCLUDED.cwes, epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile,
			    epss_date = EXCLUDED.epss_date, kev = EXCLUDED.kev, kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due,
			    kev_ransomware = EXCLUDED.kev_ransomware, risk = EXCLUDED.risk, vulndb_built = EXCLUDED.vulndb_built,
			    updated_at = EXCLUDED.updated_at
			 WHERE EXCLUDED.source_rank <= vulnerabilities.source_rank
			   AND EXCLUDED.vulndb_built >= vulnerabilities.vulndb_built
			   AND (vulnerabilities.aliases, vulnerabilities.namespace, vulnerabilities.source_rank, vulnerabilities.severity,
			        vulnerabilities.cvss_score, vulnerabilities.cvss, vulnerabilities.description, vulnerabilities.data_source,
			        vulnerabilities.urls, vulnerabilities.cwes, vulnerabilities.epss, vulnerabilities.epss_percentile,
			        vulnerabilities.epss_date, vulnerabilities.kev, vulnerabilities.kev_added, vulnerabilities.kev_due,
			        vulnerabilities.kev_ransomware, vulnerabilities.risk)
			       IS DISTINCT FROM
			       (EXCLUDED.aliases, EXCLUDED.namespace, EXCLUDED.source_rank, EXCLUDED.severity, EXCLUDED.cvss_score,
			        EXCLUDED.cvss, EXCLUDED.description, EXCLUDED.data_source, EXCLUDED.urls, EXCLUDED.cwes, EXCLUDED.epss,
			        EXCLUDED.epss_percentile, EXCLUDED.epss_date, EXCLUDED.kev, EXCLUDED.kev_added, EXCLUDED.kev_due,
			        EXCLUDED.kev_ransomware, EXCLUDED.risk)`, args...); err != nil {
			return fmt.Errorf("vuln: catalogue : %w", err)
		}
	}
	return nil
}

func nonNil(c []CVSS) []CVSS {
	if c == nil {
		return []CVSS{}
	}
	return c
}

// Entry est une fiche du catalogue telle qu'elle est stockée.
type Entry struct {
	Vulnerability
	Built     time.Time
	UpdatedAt time.Time
}

// GetVulnerability lit une fiche par identifiant, ou par alias (GHSA d'un CVE).
func GetVulnerability(ctx context.Context, q db.Querier, id string) (Entry, error) {
	var e Entry
	var cvss []byte
	var score, epss, pct sql.NullFloat64
	var epssDate, added, due sql.NullTime
	var kev, ransomware bool
	var sev string
	err := q.QueryRowContext(ctx, `
		SELECT id, aliases, namespace, severity, cvss_score, cvss, description, data_source, urls, cwes, epss, epss_percentile,
		       epss_date, kev, kev_added, kev_due, kev_ransomware, risk, vulndb_built, updated_at
		  FROM vulnerabilities WHERE id = $1 OR aliases @> ARRAY[$1::text]
		 ORDER BY id = $1 DESC, id LIMIT 1`, id).Scan(&e.ID, db.Array(&e.Aliases), &e.Namespace, &sev, &score, &cvss,
		&e.Description, &e.DataSource, db.Array(&e.URLs), db.Array(&e.CWEs), &epss, &pct, &epssDate, &kev, &added, &due,
		&ransomware, &e.Risk, &e.Built, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("vuln: fiche %s : %w", id, err)
	}
	e.Severity = ParseSeverity(sev)
	if err := json.Unmarshal(cvss, &e.CVSS); err != nil {
		return Entry{}, fmt.Errorf("vuln: CVSS de %s : %w", id, err)
	}
	if epss.Valid {
		e.EPSS = &EPSS{Score: epss.Float64, Percentile: pct.Float64}
		if epssDate.Valid {
			e.EPSS.Date = epssDate.Time.UTC()
		}
	}
	if kev {
		e.KEV = &KEV{Ransomware: ransomware}
		if added.Valid {
			t := added.Time.UTC()
			e.KEV.DateAdded = &t
		}
		if due.Valid {
			t := due.Time.UTC()
			e.KEV.DueDate = &t
		}
	}
	e.Built, e.UpdatedAt = e.Built.UTC(), e.UpdatedAt.UTC()
	return e, nil
}
