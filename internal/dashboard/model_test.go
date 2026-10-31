package dashboard

import (
	"testing"
	"time"

	"leblanc.io/lotor/internal/vuln"
)

func TestParsePeriod(t *testing.T) {
	for in, want := range map[string]Period{"30": Period30, "90": Period90, "365": Period365, "": DefaultPeriod,
		"7": DefaultPeriod, "abc": DefaultPeriod, "-30": DefaultPeriod} {
		if got := ParsePeriod(in); got != want {
			t.Errorf("ParsePeriod(%q) = %d, attendu %d", in, got, want)
		}
	}
}

// TestStepKeepsSeriesReadable : un point par jour jusqu'à 90 jours, un par semaine au-delà.
func TestStepKeepsSeriesReadable(t *testing.T) {
	if Period30.Step() != 1 || Period90.Step() != 1 || Period365.Step() != 7 {
		t.Fatal("pas des séries")
	}
}

func TestRankSeverityMatchesVuln(t *testing.T) {
	for _, s := range vuln.Severities() {
		if got := rankSeverity(s.Rank()); got != s {
			t.Errorf("rankSeverity(%d) = %s, attendu %s", s.Rank(), got, s)
		}
	}
	if rankSeverity(42) != vuln.SeverityUnknown || rankSeverity(-1) != vuln.SeverityUnknown {
		t.Fatal("rang hors bornes")
	}
}

func TestCountsAndDay(t *testing.T) {
	c := newCounts()
	c.BySeverity[vuln.SeverityHigh] = 2
	c.BySeverity[vuln.SeverityLow] = 3
	if c.Total() != 5 || c.Of(vuln.SeverityHigh) != 2 || c.Of(vuln.SeverityCritical) != 0 {
		t.Fatalf("décomptes : %+v", c)
	}
	paris := time.FixedZone("Paris", 3600)
	if got := day(time.Date(2026, 11, 1, 0, 30, 0, 0, paris)); !got.Equal(time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("jour UTC : %s", got)
	}
	if seconds(-3) != 0 || seconds(1.5) != 1500*time.Millisecond {
		t.Fatal("conversion des secondes")
	}
}
