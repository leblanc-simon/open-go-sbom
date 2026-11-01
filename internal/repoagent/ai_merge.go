package repoagent

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// Propriétés des métadonnées du SBOM sur l'enrichissement IA.
const (
	PropEnrichment       = "lotor:enrichment"
	PropEnrichmentModel  = "lotor:enrichment-model"
	PropEnrichmentPrompt = "lotor:enrichment-prompt"
	originIA             = "ia"
)

// vendoredExt sont les extensions d'une bibliothèque recopiée telle quelle : l'empreinte
// du fichier de preuve y est celle du composant (recherche par empreinte).
var vendoredExt = []string{".js", ".mjs", ".cjs", ".css"}

// mergeAI ajoute au SBOM Syft le statut de l'enrichissement et, s'il est complet, les
// composants IA acceptés. Dédoublonnage par purl_base et version : un composant déjà
// trouvé par Syft l'emporte toujours. contents donne le contenu d'un fichier de preuve
// (pour son empreinte) ; nil si illisible.
func mergeAI(bom *cyclonedx.BOM, res enrichResult, contents func(string) []byte) int {
	if res.Status == "" {
		return 0
	}
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	props := []cyclonedx.Property{}
	if bom.Metadata.Properties != nil {
		props = *bom.Metadata.Properties
	}
	props = append(props, cyclonedx.Property{Name: PropEnrichment, Value: res.Status})
	if res.Model != "" {
		props = append(props, cyclonedx.Property{Name: PropEnrichmentModel, Value: res.Model})
	}
	props = append(props, cyclonedx.Property{Name: PropEnrichmentPrompt, Value: PromptVersion})
	bom.Metadata.Properties = &props
	if res.Status == EnrichmentIncomplete || len(res.Accepted) == 0 {
		return 0
	}
	known := map[string]bool{}
	var walk func([]cyclonedx.Component)
	walk = func(cs []cyclonedx.Component) {
		for _, c := range cs {
			if p, _, err := sbom.ComponentPURL(c.PackageURL, c.Name, c.Version); err == nil {
				known[p.Base+"@"+strings.ToLower(p.Version)] = true
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	comps := []cyclonedx.Component{}
	if bom.Components != nil {
		comps = *bom.Components
	}
	walk(comps)
	added := 0
	for _, a := range res.Accepted {
		key := a.PURL.Base + "@" + strings.ToLower(a.PURL.Version)
		if known[key] {
			continue
		}
		known[key] = true
		comps = append(comps, aiComponent(a, contents))
		added++
	}
	bom.Components = &comps
	return added
}

func aiComponent(a AcceptedComponent, contents func(string) []byte) cyclonedx.Component {
	line := a.Line
	conf := float32(a.Confidence)
	// Toujours « library », image de conteneur comprise (son purl pkg:docker/… dit sa
	// nature) : le décodeur CycloneDX de Syft, celui du serveur, ignore les composants de
	// type « container », et l'image de base d'un Dockerfile serait perdue à l'ingestion
	// (défaut trouvé par la recette du lot 2).
	c := cyclonedx.Component{
		BOMRef:     "lotor-ia:" + a.PURL.String,
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       a.PURL.Name,
		Version:    a.PURL.Version,
		PackageURL: a.PURL.String,
		Properties: &[]cyclonedx.Property{
			{Name: sbomsyft.PropOrigin, Value: originIA},
			{Name: sbomsyft.PropConfidence, Value: strconv.FormatFloat(a.Confidence, 'f', 4, 64)},
			{Name: sbomsyft.PropModel, Value: a.Model},
		},
		Evidence: &cyclonedx.Evidence{
			Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: a.File, Line: &line, AdditionalContext: a.Excerpt}},
			Identity: &cyclonedx.EvidenceIdentityChoice{Identities: &[]cyclonedx.EvidenceIdentity{{
				Field: cyclonedx.EvidenceIdentityFieldTypePURL, Confidence: &conf, ConcludedValue: a.PURL.String,
				Methods: &[]cyclonedx.EvidenceIdentityMethod{{Technique: cyclonedx.EvidenceIdentityTechniqueSourceCodeAnalysis,
					Confidence: &conf, Value: a.Excerpt}},
			}}},
		},
	}
	ext := strings.ToLower(path.Ext(a.File))
	for _, v := range vendoredExt {
		if ext != v || contents == nil {
			continue
		}
		if data := contents(a.File); data != nil {
			sum := sha256.Sum256(data)
			c.Hashes = &[]cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: hex.EncodeToString(sum[:])}}
		}
	}
	return c
}
