package vex

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
)

// Format est un format de VEX.
type Format string

// Formats pris en charge (JSON seulement).
const (
	FormatOpenVEX   Format = "openvex"
	FormatCycloneDX Format = "cyclonedx"
)

// Formats renvoie les formats, dans l'ordre des écrans.
func Formats() []Format { return []Format{FormatOpenVEX, FormatCycloneDX} }

// ParseFormat lit un format.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatOpenVEX, FormatCycloneDX:
		return f, nil
	}
	return "", fmt.Errorf("vex: format inconnu %q", s)
}

// MaxDocument borne la taille d'un document importé.
const MaxDocument = 1 << 20

// Erreurs de lecture.
var (
	// ErrInvalid : document illisible ou d'un format inconnu.
	ErrInvalid = errors.New("vex: document illisible")
	// ErrTooLarge : document au-delà de MaxDocument.
	ErrTooLarge = errors.New("vex: document trop gros")
	// ErrTooManyStatements : plus de triage.MaxImportStatements déclarations, produits
	// développés.
	ErrTooManyStatements = errors.New("vex: trop de déclarations")
	// ErrNoStatement : rien à exporter.
	ErrNoStatement = errors.New("vex: aucune déclaration")
)

// Meta décrit le document produit.
type Meta struct {
	ID      uuid.UUID // identifiant du document (aléatoire si nul)
	Author  string    // auteur (nom de l'organisation)
	Tooling string    // « lotor <version> »
	Time    time.Time // date du document
}

// Document est un VEX lu : son format, son auteur déclaré, ses déclarations (une par
// composant visé) et le nombre de déclarations écartées (statut, justification ou état
// inconnu, aucun purl visé).
type Document struct {
	Format     Format
	Author     string
	Statements []triage.Statement
	Skipped    int
}

// Encode écrit les déclarations dans le format f.
func Encode(f Format, m Meta, stmts []triage.Statement) ([]byte, error) {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	switch f {
	case FormatOpenVEX:
		return EncodeOpenVEX(m, stmts)
	case FormatCycloneDX:
		return EncodeCycloneDX(m, stmts)
	}
	return nil, fmt.Errorf("vex: format inconnu %q", f)
}

// StatementSource donne les déclarations d'un projet (triage.Service).
type StatementSource interface {
	Statements(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) ([]triage.Statement, error)
}

// Export écrit les déclarations d'un projet dans le format f ; ErrNoStatement si le
// projet n'a aucune décision à exporter.
func Export(ctx context.Context, src StatementSource, org tenant.OrgID, projectID uuid.UUID, f Format, m Meta) ([]byte, error) {
	stmts, err := src.Statements(ctx, org, projectID)
	if err != nil {
		return nil, err
	}
	return Encode(f, m, stmts)
}

// Decode lit un document OpenVEX (contexte https://openvex.dev/ns/…) ou CycloneDX
// (bomFormat CycloneDX), en JSON. Le document est une donnée non fiable : taille et
// nombre de déclarations sont bornés, les valeurs inconnues écartent leur déclaration.
func Decode(data []byte) (Document, error) {
	if len(data) > MaxDocument {
		return Document{}, ErrTooLarge
	}
	var head struct {
		Context   any    `json:"@context"`
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return Document{}, fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	if c, ok := head.Context.(string); ok && strings.HasPrefix(c, "https://openvex.dev/ns") {
		return decodeOpenVEX(data)
	}
	if head.BOMFormat == "CycloneDX" {
		return decodeCycloneDX(data)
	}
	return Document{}, ErrInvalid
}

//go:embed schema/openvex-0.2.0.schema.json
var schemaFS embed.FS

// OpenVEXValidator valide un document par le schéma JSON officiel d'OpenVEX 0.2.0,
// embarqué (aucune référence chargée du réseau).
type OpenVEXValidator struct {
	schema *jsonschema.Schema
}

// NewOpenVEXValidator compile le schéma embarqué.
func NewOpenVEXValidator() (*OpenVEXValidator, error) {
	raw, err := schemaFS.ReadFile("schema/openvex-0.2.0.schema.json")
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	const url = "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, err
	}
	return &OpenVEXValidator{schema: s}, nil
}

// Validate vérifie un document OpenVEX.
func (v *OpenVEXValidator) Validate(data []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	return v.schema.Validate(doc)
}
