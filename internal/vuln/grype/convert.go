package grype

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"

	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// nvdNamespace est l'espace de noms des fiches NVD dans la base v6.
const nvdNamespace = "nvd:cpe"

// Bornes des champs du catalogue : une source anormale ne remplit pas la base.
const (
	maxIDLen          = 128
	maxDescriptionLen = 16 << 10
	maxListLen        = 32
	maxURLLen         = 2048
	maxShortLen       = 256
)

func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") }

// convert traduit les correspondances de Grype. Le catalogue retient, pour un CVE, la
// fiche du NVD quand la base l'a (cve), sinon celle de la première correspondance dans
// l'ordre de Grype : une même vulnérabilité garde la même fiche quel que soit l'écosystème
// du composant qui l'a révélée.
func convert(ms []match.Match, cve func(string) *vulnerability.Metadata) ([]vuln.Match, map[string]vuln.Vulnerability, error) {
	out := make([]vuln.Match, 0, len(ms))
	vulns := map[string]vuln.Vulnerability{}
	aliases := map[string][]string{}
	for _, m := range ms {
		id := m.Vulnerability.ID
		if id == "" || len(id) > maxIDLen {
			continue
		}
		p, _, err := sbom.ComponentPURL(m.Package.PURL, m.Package.Name, m.Package.Version)
		if err != nil {
			continue
		}
		md := m.Vulnerability.Metadata
		vm := vuln.Match{
			PURL:            p.String,
			VulnerabilityID: id,
			Severity:        vuln.SeverityUnknown,
			FixedVersions:   cleanList(m.Vulnerability.Fix.Versions, maxShortLen),
			FixState:        fixState(m.Vulnerability.Fix.State),
			Type:            bestType(m.Details),
		}
		if md != nil {
			vm.Severity = vuln.ParseSeverity(md.Severity)
			vm.Risk = md.RiskScore()
		}
		out = append(out, vm)
		for _, r := range m.Vulnerability.RelatedVulnerabilities {
			if r.ID != id && r.ID != "" && len(r.ID) <= maxIDLen {
				aliases[id] = append(aliases[id], r.ID)
			}
		}
		if _, ok := vulns[id]; ok {
			continue
		}
		chosen := md
		if isCVE(id) {
			if nvd := cve(id); nvd != nil {
				chosen = nvd
			}
		}
		vulns[id] = catalogEntry(id, chosen)
	}
	for id, v := range vulns {
		v.Aliases = cleanList(append(v.Aliases, aliases[id]...), maxIDLen)
		vulns[id] = v
	}
	// Une correspondance de source inconnue prend la sévérité du catalogue.
	for i, m := range out {
		if m.Severity == vuln.SeverityUnknown {
			out[i].Severity = vulns[m.VulnerabilityID].Severity
		}
		if m.Risk == 0 {
			out[i].Risk = vulns[m.VulnerabilityID].Risk
		}
	}
	return out, vulns, nil
}

func catalogEntry(id string, md *vulnerability.Metadata) vuln.Vulnerability {
	v := vuln.Vulnerability{ID: id, Severity: vuln.SeverityUnknown}
	if md == nil {
		return v
	}
	v.Namespace = truncate(md.Namespace, maxShortLen)
	v.Severity = vuln.ParseSeverity(md.Severity)
	v.Description = truncate(md.Description, maxDescriptionLen)
	if len(md.DataSource) <= maxURLLen {
		v.DataSource = md.DataSource
	}
	v.URLs = cleanList(md.URLs, maxURLLen)
	if md.ID != "" && md.ID != id {
		v.Aliases = append(v.Aliases, md.ID)
	}
	for _, c := range md.Cvss {
		if len(v.CVSS) == maxListLen || len(c.Vector) > maxShortLen {
			continue
		}
		v.CVSS = append(v.CVSS, vuln.CVSS{Source: truncate(c.Source, maxShortLen), Type: truncate(c.Type, 32),
			Version: truncate(c.Version, 16), Vector: c.Vector, BaseScore: clamp(c.Metrics.BaseScore, 0, 10)})
	}
	var cwes []string
	for _, c := range md.CWEs {
		cwes = append(cwes, c.CWE)
	}
	v.CWEs = cleanList(cwes, 64)
	if len(md.EPSS) > 0 {
		e := md.EPSS[0]
		v.EPSS = &vuln.EPSS{Score: clamp(e.EPSS, 0, 1), Percentile: clamp(e.Percentile, 0, 1), Date: e.Date.UTC()}
	}
	if len(md.KnownExploited) > 0 {
		v.KEV = kevOf(md.KnownExploited)
	}
	v.Risk = clamp(md.RiskScore(), 0, 100)
	return v
}

// kevOf résume les inscriptions au catalogue KEV : première date d'ajout, première
// échéance, rançongiciel si l'une le dit.
func kevOf(ks []vulnerability.KnownExploited) *vuln.KEV {
	k := &vuln.KEV{}
	for _, e := range ks {
		k.DateAdded = earliest(k.DateAdded, e.DateAdded)
		k.DueDate = earliest(k.DueDate, e.DueDate)
		if strings.EqualFold(e.KnownRansomwareCampaignUse, "known") {
			k.Ransomware = true
		}
	}
	return k
}

func earliest(a, b *time.Time) *time.Time {
	if b == nil {
		return a
	}
	t := b.UTC()
	if a == nil || t.Before(*a) {
		return &t
	}
	return a
}

func fixState(s vulnerability.FixState) vuln.FixState {
	switch s {
	case vulnerability.FixStateFixed:
		return vuln.FixFixed
	case vulnerability.FixStateNotFixed:
		return vuln.FixNotFixed
	case vulnerability.FixStateWontFix:
		return vuln.FixWontFix
	}
	return vuln.FixUnknown
}

// bestType classe les types de correspondance comme Grype : exact direct, exact
// indirect, CPE.
func bestType(ds match.Details) vuln.MatchType {
	best := vuln.MatchCPE
	for _, d := range ds {
		switch d.Type {
		case match.ExactDirectMatch:
			return vuln.MatchExactDirect
		case match.ExactIndirectMatch:
			best = vuln.MatchExactIndirect
		}
	}
	return best
}

// cleanList trie, dédoublonne et borne une liste de chaînes non vides.
func cleanList(in []string, maxLen int) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && len(s) <= maxLen && utf8.ValidString(s) && !strings.ContainsRune(s, 0) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxListLen {
		out = out[:maxListLen]
	}
	return out
}

func truncate(s string, n int) string {
	// PostgreSQL refuse l'octet nul dans un texte.
	s = strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func clamp(v, lo, hi float64) float64 { return max(lo, min(hi, v)) }
