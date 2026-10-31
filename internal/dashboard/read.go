package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// Service lit les indicateurs et enregistre les statistiques quotidiennes.
type Service struct {
	pool *db.Pool
	now  func() time.Time
}

// Option règle le service.
type Option func(*Service)

// WithClock remplace l'horloge du système (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService construit le service.
func NewService(pool *db.Pool, opts ...Option) *Service {
	s := &Service{pool: pool, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Now renvoie l'heure de l'horloge du service, en UTC.
func (s *Service) Now() time.Time { return s.now().UTC() }

// day renvoie le jour UTC (minuit) d'un instant.
func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// scope restreint les lectures à l'organisation entière (project nul) ou à un projet.
type scope struct{ project uuid.UUID }

func (s scope) org() bool { return s.project == uuid.Nil }

// openWhere sélectionne les constats ouverts des références actives : des projets actifs
// pour l'organisation, du projet demandé sinon. Le paramètre $1 porte la portée dans les
// deux cas (NULL pour l'organisation), pour que les requêtes numérotent leurs paramètres
// de la même façon. joins s'ajoute aux jointures (composants…).
func (s scope) openWhere(joins string) string {
	if s.org() {
		return ` FROM findings f
		  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
		  JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id` + joins + `
		 WHERE f.status = 'open' AND r.removed_at IS NULL AND p.archived_at IS NULL AND $1::uuid IS NULL`
	}
	return ` FROM findings f
	  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id` + joins + `
	 WHERE f.status = 'open' AND r.removed_at IS NULL AND f.project_id = $1`
}

// arg renvoie le paramètre $1 de la portée (NULL pour l'organisation).
func (s scope) arg() any {
	if s.org() {
		return nil
	}
	return s.project
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dashboard: %s : %w", what, err)
}

// openCounts décompte les constats ouverts de la portée, par sévérité.
func openCounts(ctx context.Context, tx *db.OrgTx, sc scope) (Counts, error) {
	rows, err := tx.QueryContext(ctx, `SELECT f.severity, count(*), count(*) FILTER (WHERE f.kev)`+sc.openWhere("")+
		` GROUP BY f.severity`, sc.arg())
	if err != nil {
		return Counts{}, wrap("constats ouverts", err)
	}
	defer rows.Close()
	c := newCounts()
	for rows.Next() {
		var sev string
		var n, kev int
		if err := rows.Scan(&sev, &n, &kev); err != nil {
			return Counts{}, wrap("constats ouverts", err)
		}
		c.BySeverity[vuln.ParseSeverity(sev)] += n
		c.KEV += kev
	}
	return c, wrap("constats ouverts", rows.Err())
}

// kevSpread compte les vulnérabilités KEV distinctes ouvertes et les projets qui en portent.
func kevSpread(ctx context.Context, tx *db.OrgTx, sc scope) (vulns, projects int, err error) {
	err = tx.QueryRowContext(ctx, `SELECT count(DISTINCT f.vuln_id), count(DISTINCT f.project_id)`+sc.openWhere("")+` AND f.kev`,
		sc.arg()).Scan(&vulns, &projects)
	return vulns, projects, wrap("KEV ouvertes", err)
}

// fixTimes renvoie le délai médian de correction par sévérité des constats résolus dans
// [from, to) : des projets actifs pour l'organisation, du projet sinon.
func fixTimes(ctx context.Context, tx *db.OrgTx, sc scope, from, to time.Time) (map[vuln.Severity]FixTime, error) {
	query := `SELECT f.severity, count(*),
		percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM f.resolved_at - f.first_seen_at))
		  FROM findings f`
	if sc.org() {
		query += ` JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id
		 WHERE p.archived_at IS NULL AND $1::uuid IS NULL`
	} else {
		query += ` WHERE f.project_id = $1`
	}
	query += ` AND f.status = 'resolved' AND f.resolved_at >= $2 AND f.resolved_at < $3 GROUP BY f.severity`
	rows, err := tx.QueryContext(ctx, query, sc.arg(), from, to)
	if err != nil {
		return nil, wrap("délais de correction", err)
	}
	defer rows.Close()
	out := map[vuln.Severity]FixTime{}
	for rows.Next() {
		var sev string
		var n int
		var median float64
		if err := rows.Scan(&sev, &n, &median); err != nil {
			return nil, wrap("délais de correction", err)
		}
		out[vuln.ParseSeverity(sev)] = FixTime{Fixed: n, Median: seconds(median)}
	}
	return out, wrap("délais de correction", rows.Err())
}

func seconds(s float64) time.Duration {
	return time.Duration(math.Round(math.Max(s, 0) * float64(time.Second)))
}

// series lit les statistiques enregistrées de la portée dans [from, to), un jour sur step
// en remontant depuis to.
func series(ctx context.Context, tx *db.OrgTx, sc scope, from, to time.Time, step int) ([]Point, error) {
	table, cond := "org_daily_stats", "$1::uuid IS NULL"
	if !sc.org() {
		table, cond = "project_daily_stats", "project_id = $1"
	}
	rows, err := tx.QueryContext(ctx, `SELECT day, open_critical, open_high, open_medium, open_low, open_negligible,
		open_unknown, open_kev FROM `+table+` WHERE `+cond+` AND day >= $2 AND day < $3 AND ($3::date - day) % $4 = 0
		ORDER BY day`, sc.arg(), from, to, step)
	if err != nil {
		return nil, wrap("série", err)
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		p := Point{Open: newCounts()}
		var crit, high, med, low, negl, unk int
		if err := rows.Scan(&p.Day, &crit, &high, &med, &low, &negl, &unk, &p.Open.KEV); err != nil {
			return nil, wrap("série", err)
		}
		p.Day = day(p.Day)
		for s, n := range map[vuln.Severity]int{vuln.SeverityCritical: crit, vuln.SeverityHigh: high, vuln.SeverityMedium: med,
			vuln.SeverityLow: low, vuln.SeverityNegligible: negl, vuln.SeverityUnknown: unk} {
			p.Open.BySeverity[s] = n
		}
		out = append(out, p)
	}
	return out, wrap("série", rows.Err())
}

// lastAnalysis renvoie la dernière analyse d'une référence de la portée.
func lastAnalysis(ctx context.Context, tx *db.OrgTx, sc scope) (*time.Time, error) {
	var t sql.NullTime
	query := `SELECT max(analyzed_at) FROM ref_analyses WHERE $1::uuid IS NULL`
	if !sc.org() {
		query = `SELECT max(analyzed_at) FROM ref_analyses WHERE project_id = $1`
	}
	if err := tx.QueryRowContext(ctx, query, sc.arg()).Scan(&t); err != nil {
		return nil, wrap("dernière analyse", err)
	}
	if !t.Valid {
		return nil, nil
	}
	u := t.Time.UTC()
	return &u, nil
}

// summary lit les indicateurs communs de la portée à l'instant now.
func summary(ctx context.Context, tx *db.OrgTx, sc scope, now time.Time, period Period) (Summary, error) {
	today := day(now)
	s := Summary{At: now, Period: period}
	var err error
	if s.Open, err = openCounts(ctx, tx, sc); err != nil {
		return Summary{}, err
	}
	if s.KEVVulns, s.KEVProjects, err = kevSpread(ctx, tx, sc); err != nil {
		return Summary{}, err
	}
	if s.FixTimes, err = fixTimes(ctx, tx, sc, now.AddDate(0, 0, -int(period)), now); err != nil {
		return Summary{}, err
	}
	if s.Trend, err = series(ctx, tx, sc, today.AddDate(0, 0, -int(period)), today, period.Step()); err != nil {
		return Summary{}, err
	}
	week, err := series(ctx, tx, sc, today.AddDate(0, 0, -WeekAgo), today.AddDate(0, 0, -WeekAgo+1), 1)
	if err != nil {
		return Summary{}, err
	}
	if len(week) == 1 {
		s.WeekAgo = &week[0].Open
	}
	s.Trend = append(s.Trend, Point{Day: today, Open: s.Open})
	s.LastAnalysis, err = lastAnalysis(ctx, tx, sc)
	return s, err
}

// read ouvre la transaction des lectures : lecture seule, un seul état pour toute la page.
func (s *Service) read(ctx context.Context, org tenant.OrgID, fn func(*db.OrgTx) error) error {
	return s.pool.InOrg(ctx, org, fn, db.ReadOnly(), db.Isolation(sql.LevelRepeatableRead))
}

// Project renvoie les indicateurs d'un projet (en-tête de sa fiche).
func (s *Service) Project(ctx context.Context, org tenant.OrgID, projectID uuid.UUID, period Period) (Summary, error) {
	var out Summary
	err := s.read(ctx, org, func(tx *db.OrgTx) error {
		var err error
		out, err = summary(ctx, tx, scope{project: projectID}, s.Now(), period)
		return err
	})
	return out, err
}

// Org renvoie le tableau de bord d'une organisation.
func (s *Service) Org(ctx context.Context, org tenant.OrgID, period Period) (Org, error) {
	var out Org
	err := s.read(ctx, org, func(tx *db.OrgTx) error {
		now := s.Now()
		var err error
		if out.Summary, err = summary(ctx, tx, scope{}, now, period); err != nil {
			return err
		}
		if out.Projects, err = projectKinds(ctx, tx); err != nil {
			return err
		}
		if out.Exposed, err = exposed(ctx, tx); err != nil {
			return err
		}
		if out.Widespread, err = widespread(ctx, tx); err != nil {
			return err
		}
		out.SilentAgents, out.Silent, err = agent.Silent(ctx, tx, now, TopN)
		return err
	})
	return out, err
}

// projectKinds compte les projets actifs par nature.
func projectKinds(ctx context.Context, tx *db.OrgTx) (map[project.Kind]int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT kind, count(*) FROM projects WHERE archived_at IS NULL GROUP BY kind`)
	if err != nil {
		return nil, wrap("projets", err)
	}
	defer rows.Close()
	out := map[project.Kind]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, wrap("projets", err)
		}
		out[project.Kind(k)] = n
	}
	return out, wrap("projets", rows.Err())
}

// severityRank classe une sévérité en SQL comme vuln.Severity.Rank.
const severityRank = `CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
	WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END`

func rankSeverity(rank int) vuln.Severity {
	all := vuln.Severities()
	i := len(all) - 1 - rank
	if i < 0 || i >= len(all) {
		return vuln.SeverityUnknown
	}
	return all[i]
}

// exposed renvoie les TopN projets actifs au risque ouvert le plus élevé.
func exposed(ctx context.Context, tx *db.OrgTx) ([]ExposedProject, error) {
	rows, err := tx.QueryContext(ctx, `SELECT p.id, p.slug, p.name, p.kind, max(f.risk),
		count(*) FILTER (WHERE f.severity = 'critical'), count(*) FILTER (WHERE f.severity = 'high'),
		count(*) FILTER (WHERE f.severity = 'medium'), count(*) FILTER (WHERE f.severity = 'low'),
		count(*) FILTER (WHERE f.severity = 'negligible'), count(*) FILTER (WHERE f.severity = 'unknown'),
		count(*) FILTER (WHERE f.kev)`+scope{}.openWhere("")+`
		 GROUP BY p.id, p.slug, p.name, p.kind
		 ORDER BY max(f.risk) DESC, count(*) DESC, p.slug LIMIT $2`, nil, TopN)
	if err != nil {
		return nil, wrap("projets exposés", err)
	}
	defer rows.Close()
	var out []ExposedProject
	for rows.Next() {
		e := ExposedProject{Open: newCounts()}
		var kind string
		var crit, high, med, low, negl, unk int
		if err := rows.Scan(&e.ID, &e.Slug, &e.Name, &kind, &e.MaxRisk, &crit, &high, &med, &low, &negl, &unk, &e.Open.KEV); err != nil {
			return nil, wrap("projets exposés", err)
		}
		e.Kind = project.Kind(kind)
		for s, n := range map[vuln.Severity]int{vuln.SeverityCritical: crit, vuln.SeverityHigh: high, vuln.SeverityMedium: med,
			vuln.SeverityLow: low, vuln.SeverityNegligible: negl, vuln.SeverityUnknown: unk} {
			if n > 0 {
				e.Open.BySeverity[s] = n
			}
		}
		out = append(out, e)
	}
	return out, wrap("projets exposés", rows.Err())
}

// widespread renvoie les TopN familles de composants (purl_base) aux constats ouverts qui
// touchent le plus de projets actifs.
func widespread(ctx context.Context, tx *db.OrgTx) ([]Component, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.purl_base, min(c.name), count(DISTINCT f.project_id),
		(array_agg(DISTINCT c.version ORDER BY c.version))[1:`+fmt.Sprint(VersionsShown)+`], count(DISTINCT c.version),
		max(`+severityRank+`), bool_or(f.kev), (array_agg(c.id ORDER BY c.version DESC, c.id))[1]`+
		scope{}.openWhere(` JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id`)+`
		 GROUP BY c.purl_base
		 ORDER BY count(DISTINCT f.project_id) DESC, max(`+severityRank+`) DESC, c.purl_base LIMIT $2`, nil, TopN)
	if err != nil {
		return nil, wrap("composants répandus", err)
	}
	defer rows.Close()
	var out []Component
	for rows.Next() {
		var c Component
		var rank int
		if err := rows.Scan(&c.PURLBase, &c.Name, &c.Projects, db.Array(&c.Versions), &c.VersionCount, &rank, &c.KEV, &c.ID); err != nil {
			return nil, wrap("composants répandus", err)
		}
		c.Worst = rankSeverity(rank)
		out = append(out, c)
	}
	return out, wrap("composants répandus", rows.Err())
}
