//go:build integration

package inventory

import (
	"context"
	"testing"
	"time"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
)

// aiComponents construit un inventaire : un composant Syft et un composant IA prouvé.
func aiComponents(conf string) []sbom.Component {
	return sbom.Normalize(sbom.RawDocument{Format: sbom.FormatCycloneDX, SpecVersion: "1.6", Components: []sbom.RawComponent{
		{PURL: "pkg:npm/express@4.18.2", Origin: "syft"},
		{PURL: "pkg:npm/jquery@3.4.1", Origin: "ia", Confidence: conf, Model: "claude-test",
			Evidence: []byte(`{"occurrences":[{"location":"public/js/jquery.min.js","line":2,"additionalContext":"jQuery v3.4.1"}]}`)},
		{PURL: "pkg:npm/nolocation@1.0.0", Origin: "ia", Evidence: []byte(`{"identity":[]}`)},
	}}).Components
}

// TestAIComponentsAndEnrichment : composants IA de l'instantané courant avec leur preuve,
// statut d'enrichissement repris à chaque envoi d'un même commit.
func TestAIComponentsAndEnrichment(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Hour)

	read := func() []AIComponent {
		var out []AIComponent
		err := tdb.App.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
			var err error
			out, err = AIComponents(ctx, tx, f.main)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := read(); len(got) != 0 {
		t.Fatalf("sans instantané : %+v", got)
	}
	r := f.repoRecord(commit(1), aiComponents("0.97"), now)
	r.Enrichment, r.EnrichmentModel = sbom.EnrichmentComplete, "claude-test"
	res := f.store(t, r)
	got := read()
	if len(got) != 1 || got[0].PURL != "pkg:npm/jquery@3.4.1" || got[0].Occurrence.Line != 2 ||
		got[0].Occurrence.Location != "public/js/jquery.min.js" || got[0].Model != "claude-test" ||
		got[0].Confidence == nil || *got[0].Confidence != 0.97 {
		t.Fatalf("%+v", got)
	}
	snap := func() Snapshot {
		var s Snapshot
		err := tdb.App.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
			var err error
			s, err = GetSnapshot(ctx, tx, f.repo, res.SnapshotID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := snap(); s.Enrichment != sbom.EnrichmentComplete || s.EnrichmentModel != "claude-test" || s.Counts.IA != 2 {
		t.Fatalf("instantané : %+v", s)
	}
	// Même commit, même inventaire, nouvel envoi incomplet… impossible (l'inventaire
	// change) ; même inventaire renvoyé sans enrichissement : le statut suit le dernier
	// envoi.
	r2 := f.repoRecord(commit(1), aiComponents("0.97"), now.Add(time.Minute))
	f.store(t, r2)
	if s := snap(); s.Enrichment != "" || s.EnrichmentModel != "" {
		t.Fatalf("statut non repris : %+v", s)
	}
	// Inventaire remplacé (confiance changée) : statut du nouvel envoi.
	r3 := f.repoRecord(commit(1), aiComponents("0.5"), now.Add(2*time.Minute))
	r3.Enrichment = sbom.EnrichmentCarried
	f.store(t, r3)
	if s := snap(); s.Enrichment != sbom.EnrichmentCarried {
		t.Fatalf("remplacement : %+v", s)
	}
	// Nouveau commit : nouvel instantané avec son statut.
	r4 := f.repoRecord(commit(2), aiComponents("0.5"), now.Add(3*time.Minute))
	r4.Enrichment = sbom.EnrichmentIncomplete
	res = f.store(t, r4)
	if s := snap(); s.Enrichment != sbom.EnrichmentIncomplete {
		t.Fatalf("nouveau commit : %+v", s)
	}
}
