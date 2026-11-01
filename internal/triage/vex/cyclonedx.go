package vex

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/triage"
)

// Propriétés CycloneDX propres à lotor (espace de noms lotor:, § 11 de l'architecture) :
// ce que l'analyse d'impact n'exprime pas.
const (
	propStatus        = "lotor:triage_status"        // risk_accepted (exploitable + will_not_fix ne le distingue pas)
	propExpires       = "lotor:triage_expires"       // dernier jour d'acceptation d'un risque
	propJustification = "lotor:triage_justification" // justification d'origine, d'une autre liste
)

// EncodeCycloneDX écrit les déclarations en un BOM CycloneDX 1.6 de VEX : les composants
// visés (bom-ref = purl) et une vulnérabilité par déclaration, avec son analyse d'impact.
func EncodeCycloneDX(m Meta, stmts []triage.Statement) ([]byte, error) {
	if len(stmts) == 0 {
		return nil, ErrNoStatement
	}
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + docID(m)
	bom.Metadata = &cdx.Metadata{Timestamp: stamp(m.Time)}
	if m.Tooling != "" {
		name, ver, _ := strings.Cut(m.Tooling, " ")
		bom.Metadata.Tools = &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: name, Version: ver}}}
	}
	if m.Author != "" {
		bom.Metadata.Authors = &[]cdx.OrganizationalContact{{Name: m.Author}}
	}
	var comps []cdx.Component
	seen := map[string]bool{}
	var vulns []cdx.Vulnerability
	for i, s := range stmts {
		if !seen[s.PURL] {
			seen[s.PURL] = true
			comps = append(comps, componentOf(s.PURL))
		}
		a, props, err := analysisOf(s)
		if err != nil {
			return nil, err
		}
		v := cdx.Vulnerability{BOMRef: fmt.Sprintf("vex-%d", i+1), ID: s.VulnID, Analysis: a,
			Affects: &[]cdx.Affects{{Ref: s.PURL}}}
		if len(props) > 0 {
			v.Properties = &props
		}
		vulns = append(vulns, v)
	}
	bom.Components, bom.Vulnerabilities = &comps, &vulns
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("vex: encodage CycloneDX : %w", err)
	}
	return buf.Bytes(), nil
}

func componentOf(p string) cdx.Component {
	c := cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: p, PackageURL: p, Name: p}
	if u, err := packageurl.FromString(p); err == nil {
		c.Name, c.Version = u.Name, u.Version
		if u.Namespace != "" {
			c.Group = u.Namespace
		}
	}
	return c
}

func analysisOf(s triage.Statement) (*cdx.VulnerabilityAnalysis, []cdx.Property, error) {
	a := &cdx.VulnerabilityAnalysis{Detail: s.Comment, FirstIssued: stamp(s.Time), LastUpdated: stamp(s.Time)}
	var props []cdx.Property
	switch s.Status {
	case triage.StatusInTriage:
		a.State = cdx.IASInTriage
	case triage.StatusAffected:
		a.State = cdx.IASExploitable
	case triage.StatusRiskAccepted:
		a.State = cdx.IASExploitable
		a.Response = &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}
		props = append(props, cdx.Property{Name: propStatus, Value: string(s.Status)})
		if s.ExpiresOn != nil {
			props = append(props, cdx.Property{Name: propExpires, Value: s.ExpiresOn.Format(time.DateOnly)})
		}
	case triage.StatusNotAffected:
		a.State = cdx.IASNotAffected
		if s.Justification != "" {
			a.Justification = cdx.ImpactAnalysisJustification(s.Justification.In(triage.VocabularyCycloneDX))
			if s.Justification.Vocabulary() != triage.VocabularyCycloneDX {
				props = append(props, cdx.Property{Name: propJustification, Value: string(s.Justification)})
			}
		}
	case triage.StatusFalsePositive:
		a.State = cdx.IASFalsePositive
	case triage.StatusFixed:
		a.State = cdx.IASResolved
	default:
		return nil, nil, fmt.Errorf("vex: statut %q", s.Status)
	}
	return a, props, nil
}

// decodeCycloneDX lit les vulnérabilités analysées d'un BOM CycloneDX (JSON) : une
// déclaration par composant visé. Une référence désigne un composant du BOM par son
// bom-ref, ou directement un purl.
func decodeCycloneDX(data []byte) (Document, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return Document{}, fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	out := Document{Format: FormatCycloneDX, Author: cdxAuthor(bom)}
	refs := map[string]string{}
	if bom.Components != nil {
		indexComponents(*bom.Components, refs)
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		indexComponents([]cdx.Component{*bom.Metadata.Component}, refs)
	}
	if bom.Vulnerabilities == nil {
		return out, nil
	}
	docTime := time.Time{}
	if bom.Metadata != nil {
		docTime = parseStamp(bom.Metadata.Timestamp)
	}
	for _, v := range *bom.Vulnerabilities {
		base, err := cdxStatus(v)
		if err != nil {
			out.Skipped++
			continue
		}
		base.VulnID = strings.TrimSpace(v.ID)
		base.Time = docTime
		if v.Analysis != nil {
			if t := parseStamp(firstNonEmpty(v.Analysis.LastUpdated, v.Analysis.FirstIssued)); !t.IsZero() {
				base.Time = t
			}
		}
		var purls []string
		if v.Affects != nil {
			for _, a := range *v.Affects {
				if p := refs[a.Ref]; p != "" {
					purls = append(purls, p)
				} else if strings.HasPrefix(a.Ref, "pkg:") {
					purls = append(purls, a.Ref)
				}
			}
		}
		slices.Sort(purls)
		purls = slices.Compact(purls)
		if len(purls) == 0 {
			out.Skipped++
		}
		for _, p := range purls {
			s := base
			s.PURL = p
			out.Statements = append(out.Statements, s)
			if len(out.Statements) > triage.MaxImportStatements {
				return Document{}, ErrTooManyStatements
			}
		}
	}
	return out, nil
}

func indexComponents(cs []cdx.Component, refs map[string]string) {
	for _, c := range cs {
		if c.BOMRef != "" && c.PackageURL != "" {
			refs[c.BOMRef] = c.PackageURL
		}
		if c.Components != nil {
			indexComponents(*c.Components, refs)
		}
	}
}

func cdxAuthor(bom cdx.BOM) string {
	m := bom.Metadata
	if m == nil {
		return ""
	}
	if m.Supplier != nil && m.Supplier.Name != "" {
		return m.Supplier.Name
	}
	if m.Manufacturer != nil && m.Manufacturer.Name != "" {
		return m.Manufacturer.Name
	}
	if m.Authors != nil {
		for _, a := range *m.Authors {
			if a.Name != "" {
				return a.Name
			}
		}
	}
	return ""
}

func property(v cdx.Vulnerability, name string) string {
	if v.Properties == nil {
		return ""
	}
	for _, p := range *v.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// cdxStatus traduit l'analyse d'impact d'une vulnérabilité, propriétés de lotor comprises.
// Une vulnérabilité sans analyse ne déclare rien.
func cdxStatus(v cdx.Vulnerability) (triage.Statement, error) {
	var s triage.Statement
	a := v.Analysis
	if a == nil || a.State == "" {
		return s, fmt.Errorf("vex: vulnérabilité %q sans analyse", v.ID)
	}
	s.Comment = a.Detail
	switch a.State {
	case cdx.IASInTriage:
		s.Status = triage.StatusInTriage
	case cdx.IASExploitable:
		s.Status = triage.StatusAffected
		if property(v, propStatus) == string(triage.StatusRiskAccepted) {
			s.Status = triage.StatusRiskAccepted
			if t, err := time.Parse(time.DateOnly, property(v, propExpires)); err == nil {
				s.ExpiresOn = &t
			}
		}
	case cdx.IASResolved, cdx.IASResolvedWithPedigree:
		s.Status = triage.StatusFixed
	case cdx.IASFalsePositive:
		s.Status = triage.StatusFalsePositive
	case cdx.IASNotAffected:
		s.Status = triage.StatusNotAffected
		if a.Justification != "" {
			j, err := triage.ParseJustification(string(a.Justification))
			if err != nil || j.Vocabulary() != triage.VocabularyCycloneDX {
				return s, fmt.Errorf("vex: justification %q", a.Justification)
			}
			s.Justification = j
		}
		if orig := property(v, propJustification); orig != "" {
			if j, err := triage.ParseJustification(orig); err == nil && j.In(triage.VocabularyCycloneDX) == s.Justification {
				s.Justification = j
			}
		}
	default:
		return s, fmt.Errorf("vex: état %q", a.State)
	}
	return s, nil
}
