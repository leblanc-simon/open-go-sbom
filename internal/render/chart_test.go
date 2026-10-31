package render

import (
	"flag"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"testing/fstest"
	"time"

	"leblanc.io/open-go-sbom/internal/web/webtest"
)

var update = flag.Bool("update", false, "réécrit les fichiers attendus de testdata/")

var chartFrom = time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

func chartDay(n int) time.Time { return chartFrom.AddDate(0, 0, n) }

func TestNewLineChartGeometry(t *testing.T) {
	c := NewLineChart(chartFrom, chartDay(90), []ChartPoint{{chartDay(0), 7}, {chartDay(45), 14}, {chartDay(90), 0}})
	if c.Max != 14 || c.Line != "0,28 300,6 600,50" || c.Area != "M0,50 L0,28 300,6 600,50 L600,50 Z" ||
		c.DotX != "600" || c.DotY != "50" {
		t.Fatalf("géométrie : %+v", c)
	}
	if len(c.Hits) != 3 || c.Hits[0].X != "0" || c.Hits[0].W != "150" || c.Hits[1].X != "150" || c.Hits[1].W != "300" ||
		c.Hits[2].X != "450" || c.Hits[2].W != "150" || c.Hits[1].Date != "2026-09-16" {
		t.Fatalf("zones de survol : %+v", c.Hits)
	}
	// Un seul point : pas d'aire, un point marqué au bord droit ; série nulle sur l'axe.
	one := NewLineChart(chartFrom, chartDay(90), []ChartPoint{{chartDay(90), 0}})
	if one.Area != "" || one.Line != "600,50" || one.DotX != "600" || one.DotY != "50" || len(one.Hits) != 1 || one.Hits[0].W != "600" {
		t.Fatalf("un point : %+v", one)
	}
	if empty := NewLineChart(chartFrom, chartDay(90), nil); empty.Line != "" || empty.DotX != "" || empty.Hits != nil {
		t.Fatalf("série vide : %+v", empty)
	}
	// Intervalle nul ou point hors de l'intervalle : ramené au bord.
	if c := NewLineChart(chartFrom, chartFrom, []ChartPoint{{chartDay(-3), 1}}); c.Line != "600,6" {
		t.Fatalf("intervalle nul : %+v", c)
	}
	if c := NewLineChart(chartFrom, chartDay(10), []ChartPoint{{chartDay(-3), 1}, {chartDay(20), 1}}); c.Line != "0,6 600,6" {
		t.Fatalf("points hors intervalle : %+v", c)
	}
}

func TestNewBarChart(t *testing.T) {
	bars := NewBarChart([]Bar{{Value: 2}, {Value: 8}, {Missing: true, Value: 99}, {Value: -1}})
	if bars[0].Width != 25 || bars[1].Width != 100 || bars[2].Width != 0 || bars[3].Width != 0 {
		t.Fatalf("longueurs : %+v", bars)
	}
	if zero := NewBarChart([]Bar{{Value: 0}}); zero[0].Width != 0 {
		t.Fatalf("valeurs nulles : %+v", zero)
	}
}

type chartView struct {
	Page
	Line  LineChart
	Lines []LineChart
	Bars  BarChart
}

// chartRenderer rend les gabarits réels des graphiques (partials/charts.html) dans une
// page minimale.
func chartRenderer(t *testing.T) *Renderer {
	t.Helper()
	tpl, st := realFS(t)
	charts, err := fs.ReadFile(tpl, "partials/charts.html")
	if err != nil {
		t.Fatal(err)
	}
	assets, err := NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	layout := `{{define "layout"}}<!doctype html><html lang="{{.Page.Lang}}"><head><title>{{T "app.name"}}</title></head>` +
		`<body><a href="#main">{{T "layout.skip_to_content"}}</a><main id="main"><h1>{{T "app.name"}}</h1>{{template "content" .}}</main></body></html>{{end}}`
	r, err := New(Options{Assets: assets, Catalog: catalog(t), Templates: fstest.MapFS{
		"layout.html":          {Data: []byte(layout)},
		"partials/charts.html": {Data: charts},
		"errors/error.html":    {Data: []byte(`{{define "content"}}{{end}}`)},
		"test/line.html":       {Data: []byte(`{{define "content"}}{{range .Lines}}{{template "chart_line" .}}{{end}}{{end}}`)},
		"test/bars.html":       {Data: []byte(`{{define "content"}}{{template "chart_bars" .Bars}}{{end}}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var (
	svgElement   = regexp.MustCompile(`(?s)<svg class="chart.*?</svg>`)
	tableElement = regexp.MustCompile(`(?s)<table class="bar-chart.*?</p>`)
)

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./internal/render -run TestChartGolden -update)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s diffère de l'attendu :\n%s", name, got)
	}
}

func renderChart(t *testing.T, r *Renderer, lang, page string, v View) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/?lang="+lang, nil), http.StatusOK, page, v)
	if rec.Code != http.StatusOK {
		t.Fatalf("rendu %s : %d", page, rec.Code)
	}
	body := rec.Body.Bytes()
	webtest.AssertAccessible(t, body)
	webtest.AssertNoInlineCode(t, body)
	return body
}

// TestChartGolden compare les graphiques rendus par les vrais gabarits aux fichiers
// attendus de testdata/ : courbe complète, courbe d'un seul point (premier jour), barres.
func TestChartGolden(t *testing.T) {
	r := chartRenderer(t)
	series := NewLineChart(chartFrom, chartDay(90), []ChartPoint{{chartDay(0), 7}, {chartDay(30), 5}, {chartDay(60), 4},
		{chartDay(82), 4}, {chartDay(90), 6}})
	series.ID, series.Class = "trend-critical", "chart--critical"
	series.TitleKey, series.DescKey = "severity.critical", "chart.point"
	series.DescArgs = map[string]any{"Date": "2026-10-31", "Value": 6}
	first := NewLineChart(chartFrom, chartDay(90), []ChartPoint{{chartDay(90), 3}})
	first.ID, first.Class, first.TitleKey, first.DescKey = "trend-high", "chart--high", "severity.high", "chart.no_data"
	for _, lang := range []string{"fr", "en"} {
		body := renderChart(t, r, lang, "test/line", &chartView{Lines: []LineChart{series, first}})
		svgs := svgElement.FindAll(body, -1)
		if len(svgs) != 2 {
			t.Fatalf("%d graphiques rendus", len(svgs))
		}
		golden(t, "chart_line."+lang+".svg", append(svgs[0], '\n'))
		golden(t, "chart_line_single."+lang+".svg", append(svgs[1], '\n'))
	}

	bars := BarChart{ID: "fix", TitleKey: "chart.show_data", DescKey: "chart.no_data", Rows: NewBarChart([]Bar{
		{Class: "sev sev--critical", LabelKey: "severity.critical", Value: 2.5, ValueKey: "format.days"},
		{Class: "sev sev--high", LabelKey: "severity.high", Value: 9, ValueKey: "format.days"},
		{Class: "sev sev--medium", LabelKey: "severity.medium", Missing: true},
	})}
	body := renderChart(t, r, "fr", "test/bars", &chartView{Bars: bars})
	table := tableElement.Find(body)
	if table == nil {
		t.Fatalf("tableau absent : %s", body)
	}
	golden(t, "chart_bars.fr.html", append(table, '\n'))
}
