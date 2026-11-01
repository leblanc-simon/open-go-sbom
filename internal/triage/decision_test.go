package triage

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/version/grypeversion"
)

var (
	t0      = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	projA   = uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	projB   = uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	log4j   = "pkg:maven/org.apache.logging.log4j/log4j-core"
	log4j14 = log4j + "@2.14.1"
	cve     = "CVE-2021-44228"
)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func proj(p uuid.UUID, purl string, st Status, min int) Decision {
	return Decision{ID: uuid.New(), Scope: ScopeProject, ProjectID: p, PURL: purl, PURLBase: log4j, VulnID: cve,
		Action: ActionSet, Status: st, CreatedAt: at(min)}
}

func org(vers string, st Status, min int) Decision {
	return Decision{ID: uuid.New(), Scope: ScopeOrg, PURLBase: log4j, Vers: vers, VulnID: cve, Action: ActionSet, Status: st,
		CreatedAt: at(min)}
}

func withdraw(d Decision, min int) Decision {
	d.ID, d.Action, d.Status, d.CreatedAt = uuid.New(), ActionWithdraw, "", at(min)
	return d
}

func expire(d Decision, min int) Decision {
	x := d
	x.ID, x.Action, x.Status, x.ExpiresID, x.CreatedAt = uuid.New(), ActionExpire, StatusInTriage, d.ID, at(min)
	return x
}

// TestEffectiveStatusTable : décision du projet, sinon de l'organisation, sinon « à
// analyser » ; la plus récente d'une clé l'emporte ; un retrait rend la main ; une
// échéance ramène « à analyser » à sa portée ; une plage vers ne vaut que pour ses
// versions.
func TestEffectiveStatusTable(t *testing.T) {
	r := NewResolver(grypeversion.New())
	target := Target{ProjectID: projA, PURL: log4j14, PURLBase: log4j, PURLType: "maven", Version: "2.14.1", VulnID: cve}
	pa := proj(projA, log4j14, StatusAffected, 10)
	oNA := org("", StatusNotAffected, 5)
	accepted := proj(projA, log4j14, StatusRiskAccepted, 20)
	cases := []struct {
		name string
		log  []Decision
		want Status
		from *Decision
	}{
		{"aucune décision", nil, StatusInTriage, nil},
		{"organisation seule", []Decision{oNA}, StatusNotAffected, &oNA},
		{"projet surcharge l'organisation", []Decision{oNA, pa}, StatusAffected, &pa},
		{"projet surcharge même une décision d'organisation plus récente", []Decision{pa, org("", StatusFixed, 30)}, StatusAffected, &pa},
		{"autre projet sans effet", []Decision{proj(projB, log4j14, StatusFixed, 1), oNA}, StatusNotAffected, &oNA},
		{"autre version du composant sans effet", []Decision{proj(projA, log4j+"@2.17.1", StatusFixed, 1)}, StatusInTriage, nil},
		{"la plus récente d'une clé l'emporte", []Decision{pa, proj(projA, log4j14, StatusFalsePositive, 40)}, StatusFalsePositive, nil},
		{"retrait du projet : retour à l'organisation", []Decision{oNA, pa, withdraw(pa, 50)}, StatusNotAffected, &oNA},
		{"retrait de l'organisation : à analyser", []Decision{oNA, withdraw(oNA, 50)}, StatusInTriage, nil},
		{"échéance d'un risque accepté du projet", []Decision{oNA, accepted, expire(accepted, 60)}, StatusInTriage, nil},
		{"plage qui contient la version", []Decision{org("vers:maven/<2.15.0", StatusAffected, 1)}, StatusAffected, nil},
		{"plage qui ne la contient pas", []Decision{org("vers:maven/>=2.15.0", StatusAffected, 1)}, StatusInTriage, nil},
		{"plage d'un autre schéma", []Decision{org("vers:npm/<3.0.0", StatusAffected, 1)}, StatusInTriage, nil},
		{"plage illisible", []Decision{org("vers:maven", StatusAffected, 1)}, StatusInTriage, nil},
		{"la plus récente des plages qui s'appliquent", []Decision{org("", StatusAffected, 1), org("vers:maven/2.14.1", StatusFixed, 2),
			org("vers:maven/2.17.1", StatusFalsePositive, 3)}, StatusFixed, nil},
		{"autre vulnérabilité sans effet", []Decision{func() Decision { d := org("", StatusFixed, 1); d.VulnID = "CVE-1"; return d }()},
			StatusInTriage, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.Resolve(target, c.log)
			if got.Status != c.want {
				t.Fatalf("statut %q, attendu %q", got.Status, c.want)
			}
			if c.want == StatusInTriage && got.Decision != nil && got.Decision.Action != ActionExpire {
				t.Fatalf("décision %+v pour « à analyser »", got.Decision)
			}
			if c.from != nil && (got.Decision == nil || got.Decision.ID != c.from.ID) {
				t.Fatalf("décision appliquée %+v, attendu %s", got.Decision, c.from.ID)
			}
		})
	}
}

// TestCurrentTieBreak : à date égale, l'identifiant départage (ordre total).
func TestCurrentTieBreak(t *testing.T) {
	a := proj(projA, log4j14, StatusAffected, 0)
	b := proj(projA, log4j14, StatusFixed, 0)
	a.ID = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	b.ID = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	for _, log := range [][]Decision{{a, b}, {b, a}} {
		cur := Current(log)
		if len(cur) != 1 || cur[0].ID != b.ID {
			t.Fatalf("courante %+v, attendu %s", cur, b.ID)
		}
	}
}

func TestExpiresAt(t *testing.T) {
	day := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	d := Decision{ExpiresOn: &day}
	if got, want := d.ExpiresAt(), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("échéance %v, attendu %v", got, want)
	}
	if !(Decision{}).ExpiresAt().IsZero() {
		t.Fatal("échéance sans date")
	}
}

func TestStatuses(t *testing.T) {
	for _, s := range Statuses() {
		if got, err := ParseStatus(string(s)); err != nil || got != s {
			t.Errorf("%s : %v", s, err)
		}
		if s.Hidden() != (s == StatusNotAffected || s == StatusFalsePositive) {
			t.Errorf("%s masqué : %v", s, s.Hidden())
		}
	}
	if _, err := ParseStatus("open"); err == nil {
		t.Fatal("statut inconnu accepté")
	}
}
