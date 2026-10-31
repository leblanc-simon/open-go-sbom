package vuln

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Severity est la sévérité d'une vulnérabilité, ramenée à une échelle fermée.
type Severity string

// Sévérités, de la plus grave à la moins grave.
const (
	SeverityCritical   Severity = "critical"
	SeverityHigh       Severity = "high"
	SeverityMedium     Severity = "medium"
	SeverityLow        Severity = "low"
	SeverityNegligible Severity = "negligible"
	SeverityUnknown    Severity = "unknown"
)

// Severities renvoie les sévérités, de la plus grave à la moins grave.
func Severities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNegligible, SeverityUnknown}
}

// ParseSeverity lit une sévérité d'une source (« Critical », « HIGH »…) ; une valeur
// inconnue donne SeverityUnknown.
func ParseSeverity(s string) Severity {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	if slices.Contains(Severities(), v) {
		return v
	}
	return SeverityUnknown
}

// Rank classe une sévérité : 5 pour critical, 0 pour unknown.
func (s Severity) Rank() int {
	i := slices.Index(Severities(), s)
	if i < 0 {
		return 0
	}
	return len(Severities()) - 1 - i
}

// CVSS est un score CVSS d'une source.
type CVSS struct {
	Source    string  `json:"source,omitempty"`
	Type      string  `json:"type,omitempty"` // Primary, Secondary
	Version   string  `json:"version"`
	Vector    string  `json:"vector"`
	BaseScore float64 `json:"base_score"`
}

// EPSS est la probabilité d'exploitation à 30 jours (FIRST) et son centile.
type EPSS struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	Date       time.Time `json:"date"`
}

// KEV décrit l'inscription au catalogue CISA des vulnérabilités activement exploitées.
type KEV struct {
	DateAdded *time.Time `json:"date_added,omitempty"`
	DueDate   *time.Time `json:"due_date,omitempty"`
	// Ransomware : utilisation connue dans des campagnes de rançongiciel.
	Ransomware bool `json:"ransomware"`
}

// Vulnerability est une entrée du catalogue global, publique.
type Vulnerability struct {
	// ID est l'identifiant retenu : le CVE quand la source en donne un seul, sinon celui
	// de la source (GHSA…).
	ID      string
	Aliases []string
	// Namespace est la source des métadonnées (nvd:cpe, github:language:java…).
	Namespace   string
	Severity    Severity
	CVSS        []CVSS
	Description string
	DataSource  string
	URLs        []string
	CWEs        []string
	EPSS        *EPSS
	KEV         *KEV
	// Risk est le score de risque de Grype (0 à 100) : sévérité, EPSS, KEV.
	Risk float64
}

// BaseScore est le score CVSS retenu : le plus récent des scores principaux, sinon le plus
// récent de tous ; 0 sans score.
func (v Vulnerability) BaseScore() float64 {
	if c, ok := v.PrimaryCVSS(); ok {
		return c.BaseScore
	}
	return 0
}

// PrimaryCVSS est le score CVSS affiché : version la plus récente, score « Primary »
// d'abord.
func (v Vulnerability) PrimaryCVSS() (CVSS, bool) {
	var best CVSS
	found := false
	for _, c := range v.CVSS {
		if c.BaseScore <= 0 {
			continue
		}
		if !found || better(c, best) {
			best, found = c, true
		}
	}
	return best, found
}

func better(a, b CVSS) bool {
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	pa, pb := strings.EqualFold(a.Type, "primary"), strings.EqualFold(b.Type, "primary")
	if pa != pb {
		return pa
	}
	return a.BaseScore > b.BaseScore
}

// MatchType dit comment une correspondance a été trouvée.
type MatchType string

// Types de correspondance (ceux de Grype).
const (
	MatchExactDirect   MatchType = "exact-direct"
	MatchExactIndirect MatchType = "exact-indirect"
	MatchCPE           MatchType = "cpe"
)

// FixState dit si un correctif existe.
type FixState string

// États de correction.
const (
	FixFixed    FixState = "fixed"
	FixNotFixed FixState = "not-fixed"
	FixWontFix  FixState = "wont-fix"
	FixUnknown  FixState = "unknown"
)

// Match rattache une vulnérabilité à un composant de l'inventaire.
type Match struct {
	// PURL est le purl canonique du composant (sbom.ComponentPURL), clé de rattachement à
	// components.purl.
	PURL string
	// VulnerabilityID désigne une entrée de Result.Vulnerabilities.
	VulnerabilityID string
	// Severity est celle de la source qui a produit la correspondance (une distribution
	// peut juger moins grave que le NVD).
	Severity      Severity
	FixedVersions []string
	FixState      FixState
	Type          MatchType
	// Risk est le score de risque des métadonnées de la correspondance (0 à 100).
	Risk float64
}

// Version identifie une base de vulnérabilités : l'archive dont elle provient.
type Version struct {
	ArchiveID uuid.UUID
	Built     time.Time
	Schema    string
}

// IsZero indique l'absence de base.
func (v Version) IsZero() bool { return v.ArchiveID == uuid.Nil }

// Result est le résultat de la correspondance d'un SBOM.
type Result struct {
	// Version est la base qui a produit le résultat.
	Version Version
	Matches []Match
	// Vulnerabilities sont les entrées citées par Matches, par identifiant.
	Vulnerabilities map[string]Vulnerability
}

// Matcher confronte un SBOM d'origine (le JSON tel que reçu) à une base de vulnérabilités.
// L'adaptateur vuln/grype l'implémente ; les tests unitaires en utilisent un faux.
type Matcher interface {
	Match(ctx context.Context, blob []byte) ([]Match, map[string]Vulnerability, error)
}
