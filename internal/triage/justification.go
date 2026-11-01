package triage

import (
	"fmt"
	"slices"
)

// Justification est la justification VEX d'un statut « non affecté », conservée telle
// qu'elle a été donnée : OpenVEX et CycloneDX n'ont pas la même liste (ADR 0036).
type Justification string

// Justifications d'OpenVEX (spécification 0.2.0).
const (
	JustComponentNotPresent           Justification = "component_not_present"
	JustVulnerableCodeNotPresent      Justification = "vulnerable_code_not_present"
	JustVulnerableCodeNotInExecPath   Justification = "vulnerable_code_not_in_execute_path"
	JustVulnerableCodeNotControlled   Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustInlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)

// Justifications de CycloneDX (analyse d'impact, 1.4 et suivantes).
const (
	JustCodeNotPresent               Justification = "code_not_present"
	JustCodeNotReachable             Justification = "code_not_reachable"
	JustRequiresConfiguration        Justification = "requires_configuration"
	JustRequiresDependency           Justification = "requires_dependency"
	JustRequiresEnvironment          Justification = "requires_environment"
	JustProtectedByCompiler          Justification = "protected_by_compiler"
	JustProtectedAtRuntime           Justification = "protected_at_runtime"
	JustProtectedAtPerimeter         Justification = "protected_at_perimeter"
	JustProtectedByMitigatingControl Justification = "protected_by_mitigating_control"
)

// Vocabulary est la liste d'origine d'une justification.
type Vocabulary string

// Vocabulaires des justifications.
const (
	VocabularyOpenVEX   Vocabulary = "openvex"
	VocabularyCycloneDX Vocabulary = "cyclonedx"
)

// OpenVEXJustifications renvoie les justifications d'OpenVEX, dans l'ordre de la
// spécification.
func OpenVEXJustifications() []Justification {
	return []Justification{JustComponentNotPresent, JustVulnerableCodeNotPresent, JustVulnerableCodeNotInExecPath,
		JustVulnerableCodeNotControlled, JustInlineMitigationsAlreadyExist}
}

// CycloneDXJustifications renvoie les justifications de CycloneDX, dans l'ordre de la
// spécification.
func CycloneDXJustifications() []Justification {
	return []Justification{JustCodeNotPresent, JustCodeNotReachable, JustRequiresConfiguration, JustRequiresDependency,
		JustRequiresEnvironment, JustProtectedByCompiler, JustProtectedAtRuntime, JustProtectedAtPerimeter,
		JustProtectedByMitigatingControl}
}

// Vocabulary renvoie la liste d'origine de la justification ("" si elle n'en a pas).
func (j Justification) Vocabulary() Vocabulary {
	switch {
	case slices.Contains(OpenVEXJustifications(), j):
		return VocabularyOpenVEX
	case slices.Contains(CycloneDXJustifications(), j):
		return VocabularyCycloneDX
	}
	return ""
}

// ParseJustification lit une justification de l'une ou l'autre liste.
func ParseJustification(s string) (Justification, error) {
	j := Justification(s)
	if j.Vocabulary() == "" {
		return "", fmt.Errorf("triage: justification VEX inconnue : %q", s)
	}
	return j, nil
}

// Table de correspondance entre les deux listes (ADR 0036, docs/utilisation.md). Elle
// perd de l'information : plusieurs justifications CycloneDX se ramènent à une seule
// d'OpenVEX, et réciproquement. Un export vers l'autre format note alors la
// justification d'origine (Lossless).
var (
	cdxToOpenVEX = map[Justification]Justification{
		JustCodeNotPresent:               JustVulnerableCodeNotPresent,
		JustCodeNotReachable:             JustVulnerableCodeNotInExecPath,
		JustRequiresConfiguration:        JustVulnerableCodeNotControlled,
		JustRequiresDependency:           JustComponentNotPresent,
		JustRequiresEnvironment:          JustVulnerableCodeNotControlled,
		JustProtectedByCompiler:          JustInlineMitigationsAlreadyExist,
		JustProtectedAtRuntime:           JustInlineMitigationsAlreadyExist,
		JustProtectedAtPerimeter:         JustInlineMitigationsAlreadyExist,
		JustProtectedByMitigatingControl: JustInlineMitigationsAlreadyExist,
	}
	openVEXToCDX = map[Justification]Justification{
		JustComponentNotPresent:           JustCodeNotPresent,
		JustVulnerableCodeNotPresent:      JustCodeNotPresent,
		JustVulnerableCodeNotInExecPath:   JustCodeNotReachable,
		JustVulnerableCodeNotControlled:   JustRequiresEnvironment,
		JustInlineMitigationsAlreadyExist: JustProtectedByMitigatingControl,
	}
)

// In renvoie la justification dans le vocabulaire v : elle-même si elle en vient, sa
// correspondance sinon ("" pour une justification vide).
func (j Justification) In(v Vocabulary) Justification {
	if j == "" || j.Vocabulary() == v {
		return j
	}
	if v == VocabularyOpenVEX {
		return cdxToOpenVEX[j]
	}
	return openVEXToCDX[j]
}

// Lossless indique si la justification passe dans le vocabulaire v sans perte : sa
// correspondance y revient à elle-même.
func (j Justification) Lossless(v Vocabulary) bool {
	if j == "" || j.Vocabulary() == v {
		return true
	}
	return j.In(v).In(j.Vocabulary()) == j
}
