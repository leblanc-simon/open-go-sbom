package dashboard

import (
	"context"
	"fmt"
	"time"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// Types des jobs des statistiques quotidiennes.
const (
	// StatsAllKind met en file un StatsOrgKind par organisation active.
	StatsAllKind = "dashboard.stats_all"
	// StatsOrgKind enregistre les statistiques du jour d'une organisation.
	StatsOrgKind = "dashboard.stats_org"
)

// StatsEvery espace les enregistrements : la ligne du jour est réécrite à chaque passage,
// si bien qu'un passage manqué (arrêt, panne) ne laisse pas de trou dans la série.
const StatsEvery = time.Hour

// ProjectStatsRetention borne l'historique par projet : la plus longue période affichée,
// avec une marge.
const ProjectStatsRetention = 400

// StatsSchedule est l'échéance des statistiques quotidiennes.
func StatsSchedule() jobs.Schedule {
	return jobs.Schedule{Name: StatsAllKind, Every: StatsEvery, Job: jobs.Job{Kind: StatsAllKind, Priority: jobs.PriorityLow}}
}

// StatsAllHandler est le handler de StatsAllKind.
func (s *Service) StatsAllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		_, err := s.EnqueueAll(ctx)
		return err
	})
}

// EnqueueAll met en file l'enregistrement des statistiques de chaque organisation active
// (liste par crossorg, § 16) et en renvoie le nombre. Idempotent : la clé d'unicité fond
// les mises en file répétées.
func (s *Service) EnqueueAll(ctx context.Context) (int, error) {
	n := 0
	after := ""
	for {
		var page []crossorg.OrgSummary
		err := s.pool.InTx(ctx, func(tx *db.Tx) error {
			var err error
			if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
				return err
			}
			for _, o := range page {
				if o.ArchivedAt != nil {
					continue
				}
				if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: StatsOrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
					UniqueKey: "org:" + o.Org.String()}); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("dashboard: statistiques du parc : %w", err)
		}
		if len(page) < crossorg.MaxPage {
			return n, nil
		}
		after = page[len(page)-1].Slug
	}
}

// StatsOrgHandler est le handler de StatsOrgKind.
func (s *Service) StatsOrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(fmt.Errorf("dashboard: %s sans organisation", StatsOrgKind))
		}
		_, err := s.Record(ctx, e.OrgID)
		return err
	})
}

// Day est la ligne du jour enregistrée pour une organisation.
type Day struct {
	Day          time.Time
	Open         Counts
	KEVVulns     int
	Projects     int
	SilentAgents int
	// Fixed : constats résolus ce jour-là et délai médian de correction, par sévérité.
	Fixed map[vuln.Severity]FixTime
}

// Record enregistre l'état courant de l'organisation sous la date UTC du jour (ligne de
// l'organisation et une ligne par projet actif), et purge l'historique par projet au-delà
// de ProjectStatsRetention jours. Idempotent : un second passage le même jour réécrit les
// mêmes lignes avec l'état du moment.
func (s *Service) Record(ctx context.Context, org tenant.OrgID) (Day, error) {
	now := s.Now()
	d := Day{Day: day(now)}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		if d.Open, _, err = openState(ctx, tx, scope{}); err != nil {
			return err
		}
		if d.KEVVulns, err = kevVulns(ctx, tx, scope{}); err != nil {
			return err
		}
		kinds, err := projectKinds(ctx, tx)
		if err != nil {
			return err
		}
		d.Projects = Org{Projects: kinds}.ProjectCount()
		if d.SilentAgents, _, err = agent.Silent(ctx, tx, now, 0); err != nil {
			return err
		}
		if d.Fixed, err = fixTimes(ctx, tx, scope{}, d.Day, d.Day.AddDate(0, 0, 1)); err != nil {
			return err
		}
		if err := writeOrgDay(ctx, tx, d, now); err != nil {
			return err
		}
		return writeProjectDays(ctx, tx, d.Day, now)
	})
	if err != nil {
		return Day{}, fmt.Errorf("dashboard: statistiques du jour : %w", err)
	}
	return d, nil
}

func writeOrgDay(ctx context.Context, tx *db.OrgTx, d Day, now time.Time) error {
	args := []any{tx.OrgID(), d.Day}
	for _, sev := range vuln.Severities() {
		args = append(args, d.Open.Of(sev))
	}
	args = append(args, d.Open.KEV, d.KEVVulns, d.Projects, d.SilentAgents)
	for _, sev := range vuln.Severities() {
		args = append(args, d.Fixed[sev].Fixed)
	}
	for _, sev := range vuln.Severities() {
		var p50 any
		if f := d.Fixed[sev]; f.Fixed > 0 {
			p50 = f.Median.Seconds()
		}
		args = append(args, p50)
	}
	args = append(args, now)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO org_daily_stats (org_id, day,
		       open_critical, open_high, open_medium, open_low, open_negligible, open_unknown,
		       open_kev, kev_vulns, projects, silent_agents,
		       fixed_critical, fixed_high, fixed_medium, fixed_low, fixed_negligible, fixed_unknown,
		       fix_p50_critical, fix_p50_high, fix_p50_medium, fix_p50_low, fix_p50_negligible, fix_p50_unknown,
		       recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		        $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
		ON CONFLICT (org_id, day) DO UPDATE SET
		       open_critical = EXCLUDED.open_critical, open_high = EXCLUDED.open_high, open_medium = EXCLUDED.open_medium,
		       open_low = EXCLUDED.open_low, open_negligible = EXCLUDED.open_negligible, open_unknown = EXCLUDED.open_unknown,
		       open_kev = EXCLUDED.open_kev, kev_vulns = EXCLUDED.kev_vulns, projects = EXCLUDED.projects,
		       silent_agents = EXCLUDED.silent_agents,
		       fixed_critical = EXCLUDED.fixed_critical, fixed_high = EXCLUDED.fixed_high, fixed_medium = EXCLUDED.fixed_medium,
		       fixed_low = EXCLUDED.fixed_low, fixed_negligible = EXCLUDED.fixed_negligible, fixed_unknown = EXCLUDED.fixed_unknown,
		       fix_p50_critical = EXCLUDED.fix_p50_critical, fix_p50_high = EXCLUDED.fix_p50_high,
		       fix_p50_medium = EXCLUDED.fix_p50_medium, fix_p50_low = EXCLUDED.fix_p50_low,
		       fix_p50_negligible = EXCLUDED.fix_p50_negligible, fix_p50_unknown = EXCLUDED.fix_p50_unknown,
		       recorded_at = EXCLUDED.recorded_at`, args...)
	return wrap("ligne de l'organisation", err)
}

func writeProjectDays(ctx context.Context, tx *db.OrgTx, d, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high, open_medium, open_low,
		       open_negligible, open_unknown, open_kev, recorded_at)
		SELECT p.org_id, p.id, $1,
		       count(f.id) FILTER (WHERE f.severity = 'critical'), count(f.id) FILTER (WHERE f.severity = 'high'),
		       count(f.id) FILTER (WHERE f.severity = 'medium'), count(f.id) FILTER (WHERE f.severity = 'low'),
		       count(f.id) FILTER (WHERE f.severity = 'negligible'), count(f.id) FILTER (WHERE f.severity = 'unknown'),
		       count(f.id) FILTER (WHERE f.kev), $2
		  FROM projects p
		  LEFT JOIN (findings f JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id AND r.removed_at IS NULL)
		    ON f.org_id = p.org_id AND f.project_id = p.id AND f.status = 'open'
		 WHERE p.archived_at IS NULL
		 GROUP BY p.org_id, p.id
		ON CONFLICT (org_id, project_id, day) DO UPDATE SET
		       open_critical = EXCLUDED.open_critical, open_high = EXCLUDED.open_high, open_medium = EXCLUDED.open_medium,
		       open_low = EXCLUDED.open_low, open_negligible = EXCLUDED.open_negligible, open_unknown = EXCLUDED.open_unknown,
		       open_kev = EXCLUDED.open_kev, recorded_at = EXCLUDED.recorded_at`, d, now)
	if err != nil {
		return wrap("lignes des projets", err)
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM project_daily_stats WHERE day < $1`, d.AddDate(0, 0, -ProjectStatsRetention))
	return wrap("purge des lignes des projets", err)
}
