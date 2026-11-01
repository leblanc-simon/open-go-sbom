package vex

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/triage"
)

// OpenVEXContext est le contexte des documents OpenVEX 0.2.0 produits.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// Statuts d'OpenVEX.
const (
	ovxNotAffected        = "not_affected"
	ovxAffected           = "affected"
	ovxFixed              = "fixed"
	ovxUnderInvestigation = "under_investigation"
)

type ovxDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Role       string         `json:"role,omitempty"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling,omitempty"`
	Statements []ovxStatement `json:"statements"`
}

type ovxVulnerability struct {
	ID      string   `json:"@id,omitempty"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type ovxIdentifiers struct {
	PURL string `json:"purl,omitempty"`
}

type ovxComponent struct {
	ID            string          `json:"@id,omitempty"`
	Identifiers   *ovxIdentifiers `json:"identifiers,omitempty"`
	Subcomponents []ovxComponent  `json:"subcomponents,omitempty"`
}

type ovxStatement struct {
	Vulnerability   ovxVulnerability `json:"vulnerability"`
	Timestamp       string           `json:"timestamp,omitempty"`
	Products        []ovxComponent   `json:"products,omitempty"`
	Status          string           `json:"status"`
	StatusNotes     string           `json:"status_notes,omitempty"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	// ActionStatement est exigé (même vide) pour le statut « affected ».
	ActionStatement *string `json:"action_statement,omitempty"`
}

// EncodeOpenVEX écrit les déclarations en un document OpenVEX 0.2.0 (correspondance des
// statuts : doc.go). Chaque déclaration vise un produit identifié par le purl du
// composant.
func EncodeOpenVEX(m Meta, stmts []triage.Statement) ([]byte, error) {
	if len(stmts) == 0 {
		return nil, ErrNoStatement
	}
	doc := ovxDocument{Context: OpenVEXContext, ID: "urn:uuid:" + docID(m), Author: m.Author, Timestamp: stamp(m.Time),
		Version: 1, Tooling: m.Tooling}
	for _, s := range stmts {
		st := ovxStatement{Vulnerability: ovxVulnerability{Name: s.VulnID}, Timestamp: stamp(s.Time),
			Products: []ovxComponent{{ID: s.PURL, Identifiers: &ovxIdentifiers{PURL: s.PURL}}}}
		var marks []mark
		switch s.Status {
		case triage.StatusInTriage:
			st.Status = ovxUnderInvestigation
		case triage.StatusFixed:
			st.Status = ovxFixed
		case triage.StatusAffected, triage.StatusRiskAccepted:
			st.Status = ovxAffected
			c := s.Comment
			st.ActionStatement = &c
			if s.Status == triage.StatusRiskAccepted {
				marks = append(marks, mark{"status", string(s.Status)})
				if s.ExpiresOn != nil {
					marks = append(marks, mark{"expires", s.ExpiresOn.Format(time.DateOnly)})
				}
			}
		case triage.StatusNotAffected:
			st.Status, st.ImpactStatement = ovxNotAffected, s.Comment
			if s.Justification != "" {
				st.Justification = string(s.Justification.In(triage.VocabularyOpenVEX))
				if s.Justification.Vocabulary() != triage.VocabularyOpenVEX {
					marks = append(marks, mark{"justification", string(s.Justification)})
				}
			}
		case triage.StatusFalsePositive:
			st.Status, st.ImpactStatement = ovxNotAffected, s.Comment
			st.Justification = string(triage.JustComponentNotPresent)
			marks = append(marks, mark{"status", string(s.Status)})
		default:
			return nil, fmt.Errorf("vex: statut %q", s.Status)
		}
		notes := ""
		if s.Status == triage.StatusInTriage || s.Status == triage.StatusFixed {
			notes = s.Comment
		}
		st.StatusNotes = writeNotes(marks, notes)
		doc.Statements = append(doc.Statements, st)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// mark est une information propre à lotor qu'OpenVEX n'exprime pas, notée dans
// status_notes : le schéma refuse toute propriété supplémentaire.
type mark struct{ key, value string }

const marksPrefix = "[lotor:"

// writeNotes écrit « [lotor:clé=valeur;…] texte ».
func writeNotes(marks []mark, text string) string {
	if len(marks) == 0 {
		return text
	}
	parts := make([]string, len(marks))
	for i, m := range marks {
		parts[i] = m.key + "=" + m.value
	}
	out := marksPrefix + strings.Join(parts, ";") + "]"
	if text != "" {
		out += " " + text
	}
	return out
}

// readNotes sépare les marques de lotor du texte de status_notes.
func readNotes(s string) (map[string]string, string) {
	marks := map[string]string{}
	rest, ok := strings.CutPrefix(s, marksPrefix)
	if !ok {
		return marks, s
	}
	inner, text, ok := strings.Cut(rest, "]")
	if !ok {
		return map[string]string{}, s
	}
	for _, kv := range strings.Split(inner, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			marks[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return marks, strings.TrimPrefix(text, " ")
}

// decodeOpenVEX lit un document OpenVEX : une déclaration par produit (ou par
// sous-composant, qui désigne alors le composant visé).
func decodeOpenVEX(data []byte) (Document, error) {
	var doc ovxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	out := Document{Format: FormatOpenVEX, Author: doc.Author}
	docTime := parseStamp(doc.Timestamp)
	for _, st := range doc.Statements {
		base, err := openVEXStatus(st)
		if err != nil {
			out.Skipped++
			continue
		}
		if t := parseStamp(st.Timestamp); !t.IsZero() {
			base.Time = t
		} else {
			base.Time = docTime
		}
		base.VulnID = strings.TrimSpace(st.Vulnerability.Name)
		purls := productPURLs(st.Products)
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

// openVEXStatus traduit le statut d'une déclaration, marques de lotor comprises.
func openVEXStatus(st ovxStatement) (triage.Statement, error) {
	marks, notes := readNotes(st.StatusNotes)
	var s triage.Statement
	action := ""
	if st.ActionStatement != nil {
		action = *st.ActionStatement
	}
	switch st.Status {
	case ovxUnderInvestigation:
		s.Status, s.Comment = triage.StatusInTriage, notes
	case ovxFixed:
		s.Status, s.Comment = triage.StatusFixed, notes
	case ovxAffected:
		s.Status, s.Comment = triage.StatusAffected, firstNonEmpty(action, notes)
		if marks["status"] == string(triage.StatusRiskAccepted) {
			s.Status = triage.StatusRiskAccepted
			if t, err := time.Parse(time.DateOnly, marks["expires"]); err == nil {
				s.ExpiresOn = &t
			}
		}
	case ovxNotAffected:
		s.Status, s.Comment = triage.StatusNotAffected, firstNonEmpty(st.ImpactStatement, notes)
		if marks["status"] == string(triage.StatusFalsePositive) {
			s.Status = triage.StatusFalsePositive
			break
		}
		if st.Justification != "" {
			j, err := triage.ParseJustification(st.Justification)
			if err != nil || j.Vocabulary() != triage.VocabularyOpenVEX {
				return s, fmt.Errorf("vex: justification %q", st.Justification)
			}
			s.Justification = j
		}
		if orig := marks["justification"]; orig != "" {
			if j, err := triage.ParseJustification(orig); err == nil && j.In(triage.VocabularyOpenVEX) == s.Justification {
				s.Justification = j
			}
		}
	default:
		return s, fmt.Errorf("vex: statut %q", st.Status)
	}
	return s, nil
}

// productPURLs renvoie les purl visés : ceux des sous-composants s'il y en a (le produit
// est alors l'ensemble qui les contient), sinon ceux des produits. Un produit sans purl
// (identifiant d'image, CPE…) ne vise aucun composant.
func productPURLs(products []ovxComponent) []string {
	var out []string
	for _, p := range products {
		if len(p.Subcomponents) > 0 {
			for _, sc := range p.Subcomponents {
				if u := componentPURL(sc); u != "" {
					out = append(out, u)
				}
			}
			continue
		}
		if u := componentPURL(p); u != "" {
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func componentPURL(c ovxComponent) string {
	if c.Identifiers != nil && strings.HasPrefix(c.Identifiers.PURL, "pkg:") {
		return c.Identifiers.PURL
	}
	if strings.HasPrefix(c.ID, "pkg:") {
		return c.ID
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func docID(m Meta) string {
	if m.ID != uuid.Nil {
		return m.ID.String()
	}
	return uuid.New().String()
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseStamp(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
