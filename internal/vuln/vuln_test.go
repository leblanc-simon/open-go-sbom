package vuln

import (
	"testing"
	"time"
)

func TestSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"Critical": SeverityCritical, " HIGH ": SeverityHigh, "medium": SeverityMedium,
		"Low": SeverityLow, "Negligible": SeverityNegligible, "Unknown": SeverityUnknown, "": SeverityUnknown, "grave": SeverityUnknown} {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %s", in, got)
		}
	}
	if SeverityCritical.Rank() != 5 || SeverityUnknown.Rank() != 0 || Severity("x").Rank() != 0 || SeverityHigh.Rank() <= SeverityMedium.Rank() {
		t.Error("Rank")
	}
}

func TestPrimaryCVSS(t *testing.T) {
	v := Vulnerability{CVSS: []CVSS{
		{Version: "2.0", BaseScore: 10, Type: "Primary"},
		{Version: "3.1", BaseScore: 7.5, Type: "Secondary"},
		{Version: "3.1", BaseScore: 9.8, Type: "Primary"},
		{Version: "4.0", BaseScore: 0},
	}}
	if c, ok := v.PrimaryCVSS(); !ok || c.BaseScore != 9.8 || v.BaseScore() != 9.8 {
		t.Fatalf("PrimaryCVSS = %+v", c)
	}
	v.CVSS[2].Type = "Secondary"
	if v.BaseScore() != 9.8 {
		t.Fatal("à type égal, le score le plus haut")
	}
	if (Vulnerability{}).BaseScore() != 0 {
		t.Fatal("sans score")
	}
}

func TestParseCVSS3(t *testing.T) {
	m := ParseCVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	if len(m) != 8 || m[0] != (Metric{"av", "n"}) || m[4] != (Metric{"s", "c"}) || m[7] != (Metric{"a", "h"}) {
		t.Fatalf("métriques %+v", m)
	}
	// Métriques temporelles en plus : acceptées, ignorées.
	if len(ParseCVSS3("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P")) != 8 {
		t.Fatal("métriques temporelles")
	}
	for _, bad := range []string{"", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AV:N/PR:N/UI:N/S:C/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"} {
		if ParseCVSS3(bad) != nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestStateStale(t *testing.T) {
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	if !(State{}).Stale(now, time.Hour) {
		t.Fatal("sans base : alerte")
	}
	s := State{Target: &Archive{Built: now.Add(-6 * 24 * time.Hour)}}
	if !s.Stale(now, 5*24*time.Hour) || s.Stale(now, 7*24*time.Hour) {
		t.Fatal("âge")
	}
	if (Version{}).IsZero() != true || (Archive{Built: now, Schema: "v6"}).Version().Schema != "v6" {
		t.Fatal("Version")
	}
}
