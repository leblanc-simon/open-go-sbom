package triage

import "testing"

// TestJustificationCorrespondence : chaque justification a une correspondance dans
// l'autre liste ; Lossless dit exactement si l'aller-retour la redonne.
func TestJustificationCorrespondence(t *testing.T) {
	all := append(OpenVEXJustifications(), CycloneDXJustifications()...)
	if len(all) != 14 {
		t.Fatalf("%d justifications, attendu 5 + 9", len(all))
	}
	for _, j := range all {
		if _, err := ParseJustification(string(j)); err != nil {
			t.Fatal(err)
		}
		for _, v := range []Vocabulary{VocabularyOpenVEX, VocabularyCycloneDX} {
			m := j.In(v)
			if m.Vocabulary() != v {
				t.Errorf("%s vers %s : %q", j, v, m)
			}
			if got := m.In(j.Vocabulary()) == j; got != j.Lossless(v) {
				t.Errorf("%s vers %s : sans perte %v, aller-retour %v", j, v, j.Lossless(v), got)
			}
		}
	}
	// Cas nommés de la table (ADR 0036).
	for _, c := range []struct {
		j        Justification
		v        Vocabulary
		want     Justification
		lossless bool
	}{
		{JustCodeNotPresent, VocabularyOpenVEX, JustVulnerableCodeNotPresent, true},
		{JustCodeNotReachable, VocabularyOpenVEX, JustVulnerableCodeNotInExecPath, true},
		{JustProtectedAtRuntime, VocabularyOpenVEX, JustInlineMitigationsAlreadyExist, false},
		{JustRequiresConfiguration, VocabularyOpenVEX, JustVulnerableCodeNotControlled, false},
		{JustComponentNotPresent, VocabularyCycloneDX, JustCodeNotPresent, false},
		{JustInlineMitigationsAlreadyExist, VocabularyCycloneDX, JustProtectedByMitigatingControl, true},
	} {
		if got := c.j.In(c.v); got != c.want || c.j.Lossless(c.v) != c.lossless {
			t.Errorf("%s vers %s : %s (sans perte %v), attendu %s (%v)", c.j, c.v, got, c.j.Lossless(c.v), c.want, c.lossless)
		}
	}
	if _, err := ParseJustification("because"); err == nil {
		t.Fatal("justification inconnue acceptée")
	}
}
