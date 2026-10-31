// Package schema valide un SBOM par le schéma JSON officiel de son format (CycloneDX 1.5,
// 1.6, 1.7 et SPDX 2.3), embarqué dans le binaire. Les schémas sont compilés une fois par
// New ; aucune référence n'est chargée depuis le réseau. Syft JSON n'a pas de schéma
// embarqué : son décodeur fait foi.
//
// Validate, appliqué aux SBOM reçus, n'impose pas l'énumération des identifiants de
// licence SPDX des schémas CycloneDX (spdx.schema.json) : figée à la publication de chaque
// version, elle refuserait les identifiants plus récents qu'écrivent Syft et les autres
// outils (« Artistic-dist » en CycloneDX 1.6, par exemple). ValidateStrict applique les
// schémas officiels sans exception ; il vérifie les SBOM que le serveur produit.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"leblanc.io/lotor/internal/sbom"
)

//go:embed schemas
var files embed.FS

// set décrit le schéma d'une version : son répertoire, son fichier racine et l'URL de base
// de ses références.
type set struct {
	dir  string
	root string
	base string
}

var sets = map[sbom.Format]map[string]set{
	sbom.FormatCycloneDX: {
		"1.5": {dir: "schemas/cyclonedx-1.5", root: "bom-1.5.schema.json", base: "http://cyclonedx.org/schema/"},
		"1.6": {dir: "schemas/cyclonedx-1.6", root: "bom-1.6.schema.json", base: "http://cyclonedx.org/schema/"},
		"1.7": {dir: "schemas/cyclonedx-1.7", root: "bom-1.7.schema.json", base: "http://cyclonedx.org/schema/"},
	},
	sbom.FormatSPDX: {
		"2.3": {dir: "schemas/spdx-2.3", root: "spdx-schema.json", base: "http://spdx.org/rdf/terms/"},
	},
}

// spdxLicenses est le fichier des identifiants de licence SPDX des schémas CycloneDX.
const spdxLicenses = "spdx.schema.json"

type compiled map[sbom.Format]map[string]*jsonschema.Schema

// Validator valide les documents ; il est sûr pour un usage concurrent.
type Validator struct {
	lenient  compiled
	strict   compiled
	licenses map[string]map[string]bool // version CycloneDX → identifiants SPDX admis
}

// New compile les schémas embarqués.
func New() (*Validator, error) {
	v := &Validator{lenient: compiled{}, strict: compiled{}, licenses: map[string]map[string]bool{}}
	for format, versions := range sets {
		v.lenient[format] = map[string]*jsonschema.Schema{}
		v.strict[format] = map[string]*jsonschema.Schema{}
		for version, s := range versions {
			strict, err := compile(s, false)
			if err != nil {
				return nil, fmt.Errorf("schema: %s %s : %w", format, version, err)
			}
			lenient, err := compile(s, true)
			if err != nil {
				return nil, fmt.Errorf("schema: %s %s : %w", format, version, err)
			}
			v.strict[format][version], v.lenient[format][version] = strict, lenient
			if format == sbom.FormatCycloneDX {
				if v.licenses[version], err = licenseIDs(s); err != nil {
					return nil, fmt.Errorf("schema: licences de CycloneDX %s : %w", version, err)
				}
			}
		}
	}
	return v, nil
}

func licenseIDs(s set) (map[string]bool, error) {
	data, err := files.ReadFile(path.Join(s.dir, spdxLicenses))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Enum) == 0 {
		return nil, errors.New("énumération vide")
	}
	out := make(map[string]bool, len(doc.Enum))
	for _, id := range doc.Enum {
		out[id] = true
	}
	return out, nil
}

// CycloneDXLicenseIDs renvoie les identifiants de licence SPDX qu'admet le schéma officiel
// de cette version de CycloneDX (nil si la version est inconnue). Un encodeur s'en sert
// pour écrire un identifiant plus récent en nom de licence.
func (v *Validator) CycloneDXLicenseIDs(version string) map[string]bool {
	return v.licenses[version]
}

// noNetwork refuse toute référence qui ne figure pas parmi les schémas embarqués.
type noNetwork struct{}

func (noNetwork) Load(url string) (any, error) {
	return nil, fmt.Errorf("référence externe refusée : %s", url)
}

func compile(s set, lenient bool) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(noNetwork{})
	entries, err := fs.ReadDir(files, s.dir)
	if err != nil {
		return nil, err
	}
	var rootURL string
	for _, e := range entries {
		data, err := files.ReadFile(path.Join(s.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		url := s.base + e.Name()
		// Le schéma racine SPDX a pour $id l'URL des termes 2.3, pas celle de son fichier.
		if id, ok := doc.(map[string]any)["$id"].(string); ok && id != "" {
			url = id
		}
		if lenient && e.Name() == spdxLicenses {
			doc = map[string]any{"$schema": "http://json-schema.org/draft-07/schema#", "$id": url, "type": "string"}
		}
		if err := c.AddResource(url, doc); err != nil {
			return nil, err
		}
		if e.Name() == s.root {
			rootURL = url
		}
	}
	if rootURL == "" {
		return nil, errors.New("schéma racine absent")
	}
	return c.Compile(rootURL)
}

// Supports indique si un schéma est embarqué pour ce format et cette version.
func (v *Validator) Supports(format sbom.Format, version string) bool {
	_, ok := v.strict[format][version]
	return ok
}

// Validate valide un SBOM reçu (identifiants de licence CycloneDX non énumérés, voir la
// documentation du paquet). Un format sans schéma embarqué (Syft JSON) est accepté tel
// quel. Un document invalide donne un refus sbom.KeySchemaInvalid dont le détail est le
// pointeur JSON de la première violation, sans aucune valeur du document.
func (v *Validator) Validate(format sbom.Format, version string, data []byte) error {
	return validate(v.lenient, format, version, data)
}

// ValidateStrict valide data par le schéma officiel, sans exception.
func (v *Validator) ValidateStrict(format sbom.Format, version string, data []byte) error {
	return validate(v.strict, format, version, data)
}

func validate(schemas compiled, format sbom.Format, version string, data []byte) error {
	sch, ok := schemas[format][version]
	if !ok {
		if format == sbom.FormatSyft {
			return nil
		}
		return sbom.Reject(sbom.KeyUnsupportedFormat, string(format)+" "+version, nil)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return sbom.Reject(sbom.KeyMalformed, "", err)
	}
	err = sch.Validate(inst)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return fmt.Errorf("schema: validation : %w", err)
	}
	return sbom.Reject(sbom.KeySchemaInvalid, pointer(firstLeaf(ve).InstanceLocation), nil)
}

// firstLeaf descend jusqu'à la première violation élémentaire.
func firstLeaf(e *jsonschema.ValidationError) *jsonschema.ValidationError {
	for len(e.Causes) > 0 {
		e = e.Causes[0]
	}
	return e
}

// maxPointer borne le détail stocké avec l'ingestion.
const maxPointer = 200

func pointer(loc []string) string {
	var b strings.Builder
	for _, p := range loc {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(p))
	}
	s := b.String()
	if s == "" {
		s = "/"
	}
	if len(s) > maxPointer {
		s = s[:maxPointer]
	}
	return s
}
