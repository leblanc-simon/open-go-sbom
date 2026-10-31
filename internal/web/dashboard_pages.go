package web

import (
	"net/http"
	"strconv"
	"time"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/dashboard"
	"leblanc.io/open-go-sbom/internal/finding"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// dashSeverities sont les sévérités des tuiles, de la tendance et des délais (comme les
// pastilles des constats).
var dashSeverities = []vuln.Severity{vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow}

// change est une variation prête à afficher : signe, valeur absolue et durée en jours.
type change struct {
	Known bool
	Sign  int // −1, 0 ou 1
	N     int
	Days  int
}

func changeOf(now int, before *int, days int) change {
	if before == nil {
		return change{Days: days}
	}
	d := now - *before
	c := change{Known: true, N: d, Days: days}
	switch {
	case d > 0:
		c.Sign = 1
	case d < 0:
		c.Sign, c.N = -1, -d
	}
	return c
}

// statTile est une tuile « constats ouverts » d'une sévérité.
type statTile struct {
	Sev   sevBadge
	Count int
	Week  change
}

type trendRow struct {
	Sev    sevBadge
	Chart  render.LineChart
	Value  int
	Change change
}

type trendTableRow struct {
	Date   string
	Values []int
}

// summaryView porte les indicateurs communs au tableau de bord et à la fiche projet.
type summaryView struct {
	// Prefix rend uniques les identifiants des graphiques et des titres de la page.
	Prefix      string
	Days        int
	Tiles       []statTile
	KEVVulns    int
	KEVFindings int
	KEVProjects int
	Trend       []trendRow
	AxisFrom    string
	AxisTo      string
	TableHead   []sevBadge
	Table       []trendTableRow
	Fix         render.BarChart
}

func summaryOf(prefix string, s dashboard.Summary) summaryView {
	days := int(s.Period)
	v := summaryView{Prefix: prefix, Days: days, KEVVulns: s.KEVVulns, KEVFindings: s.Open.KEV, KEVProjects: s.KEVProjects}
	from, to := s.At.UTC().AddDate(0, 0, -days), s.At.UTC()
	if len(s.Trend) > 0 {
		to = s.Trend[len(s.Trend)-1].Day
		from = to.AddDate(0, 0, -days)
	}
	v.AxisFrom, v.AxisTo = from.Format(time.DateOnly), to.Format(time.DateOnly)
	var bars []render.Bar
	for _, sev := range dashSeverities {
		badge := sevOf(sev, nil)
		var week *int
		if s.WeekAgo != nil {
			n := s.WeekAgo.Of(sev)
			week = &n
		}
		v.Tiles = append(v.Tiles, statTile{Sev: badge, Count: s.Open.Of(sev), Week: changeOf(s.Open.Of(sev), week, dashboard.WeekAgo)})

		points := make([]render.ChartPoint, 0, len(s.Trend))
		for _, p := range s.Trend {
			points = append(points, render.ChartPoint{At: p.Day, Value: float64(p.Open.Of(sev))})
		}
		chart := render.NewLineChart(from, to, points)
		chart.ID, chart.Class = prefix+"-trend-"+string(sev), "chart--"+string(sev)
		chart.TitleKey = badge.LabelKey
		row := trendRow{Sev: badge, Chart: chart, Value: s.Open.Of(sev)}
		if len(s.Trend) > 1 {
			first := s.Trend[0].Open.Of(sev)
			row.Change = changeOf(row.Value, &first, days)
			chart.DescKey = "dashboard.trend_chart_desc"
			chart.DescArgs = map[string]any{"From": s.Trend[0].Day.Format(time.DateOnly), "First": first,
				"To": to.Format(time.DateOnly), "Last": row.Value, "Max": int(chart.Max)}
		} else {
			chart.DescKey, chart.DescArgs = "dashboard.trend_chart_single", map[string]any{"Date": to.Format(time.DateOnly), "Last": row.Value}
		}
		row.Chart = chart
		v.Trend = append(v.Trend, row)
		v.TableHead = append(v.TableHead, badge)

		ft := s.FixTimes[sev]
		bars = append(bars, render.Bar{Class: badge.Class, LabelKey: badge.LabelKey, Value: ft.Median.Hours() / 24,
			ValueKey: "format.days", Missing: ft.Fixed == 0})
	}
	for i := len(s.Trend) - 1; i >= 0; i-- {
		p := s.Trend[i]
		row := trendTableRow{Date: p.Day.Format(time.DateOnly)}
		for _, sev := range dashSeverities {
			row.Values = append(row.Values, p.Open.Of(sev))
		}
		v.Table = append(v.Table, row)
	}
	v.Fix = render.BarChart{ID: prefix + "-fix", TitleKey: "dashboard.fix_title", DescKey: "dashboard.fix_desc",
		DescArgs: map[string]any{"Days": days}, Rows: render.NewBarChart(bars)}
	return v
}

type kindCount struct {
	Kind  project.Kind
	Count int
}

type exposedRow struct {
	Name, Href string
	Kind       project.Kind
	Sev        []sevCount
	KEV        int
	Risk       int
}

type widespreadRow struct {
	Name, PURLBase, Href string
	Projects             int
	Versions             []string
	More                 int
	Worst                sevBadge
	KEV                  bool
}

type silentRow struct {
	Name, Href string
	Kind       agent.Kind
	Since      *stamp // début du silence (Activity.Since)
	Days       int
}

// periodForm est le sélecteur de période (formulaire GET, sans JavaScript).
type periodForm struct {
	Action  string
	Periods []option
}

type dashboardView struct {
	render.Page
	Base         string
	Name         string
	Period       periodForm
	ProjectCount int
	Kinds        []kindCount
	LastAnalysis *stamp
	Summary      summaryView
	Exposed      []exposedRow
	Widespread   []widespreadRow
	SilentCount  int
	Silent       []silentRow
	SilentDays   int
}

func periodFormOf(action string, selected dashboard.Period) periodForm {
	f := periodForm{Action: action}
	for _, p := range dashboard.Periods() {
		n := strconv.Itoa(int(p))
		f.Periods = append(f.Periods, option{Value: n, LabelKey: "dashboard.period_" + n, Selected: p == selected})
	}
	return f
}

// orgOverview est le tableau de bord de l'organisation (/o/{slug}/).
func (id *identity) orgOverview(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	period := dashboard.ParsePeriod(r.URL.Query().Get("period"))
	d, err := id.Dashboard.Org(r.Context(), acc.Org, period)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &dashboardView{
		Page: render.Page{TitleKey: "dashboard.title", TitleArgs: map[string]any{"Name": acc.Name}, Nav: orgNav(acc, "overview")},
		Base: base, Name: acc.Name, Period: periodFormOf(base, period), ProjectCount: d.ProjectCount(),
		LastAnalysis: stampOf(d.LastAnalysis), Summary: summaryOf("org", d.Summary), SilentCount: d.SilentAgents,
		SilentDays: int(agent.SilentAfter / (24 * time.Hour)),
	}
	for _, k := range project.Kinds() {
		if n := d.Projects[k]; n > 0 {
			view.Kinds = append(view.Kinds, kindCount{Kind: k, Count: n})
		}
	}
	for _, e := range d.Exposed {
		view.Exposed = append(view.Exposed, exposedRow{Name: e.Name, Href: base + "/projects/" + e.Slug, Kind: e.Kind,
			Sev: sevCounts(finding.Counts{BySeverity: e.Open.BySeverity}), KEV: e.Open.KEV, Risk: riskOf(e.MaxRisk)})
	}
	for _, c := range d.Widespread {
		view.Widespread = append(view.Widespread, widespreadRow{Name: c.Name, PURLBase: c.PURLBase,
			Href: base + "/components/" + c.ID.String(), Projects: c.Projects, Versions: c.Versions,
			More: c.VersionCount - len(c.Versions), Worst: sevOf(c.Worst, nil), KEV: c.KEV})
	}
	for _, a := range d.Silent {
		view.Silent = append(view.Silent, silentRow{Name: a.Name, Href: base + "/agents/" + a.ID.String(), Kind: a.Kind,
			Since: stampAt(a.SilentSince()), Days: int(d.At.Sub(a.SilentSince()) / (24 * time.Hour))})
	}
	id.rd.Render(w, r, http.StatusOK, "org/dashboard", view)
}
