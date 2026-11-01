package repoagent

import (
	"bytes"
	"context"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/source"

	// Syft exige un pilote SQLite pour les bases RPM récentes ; l'importer ici évite
	// qu'un binaire qui catalogue l'oublie.
	_ "modernc.org/sqlite"

	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// originSyft est la valeur de lotor:origin des composants trouvés par Syft (l'IA ajoute
// les siens avec lotor:origin=ia, ai_merge.go).
const originSyft = "syft"

// scanner catalogue une arborescence extraite avec Syft et l'encode en CycloneDX 1.6.
type scanner struct {
	agentVersion string
}

// scanBOM catalogue dir et renvoie le document CycloneDX, avant encodage (l'enrichissement
// IA s'y ajoute). name et commit nomment le composant décrit par le document (le dépôt à
// ce commit), à la place du chemin temporaire de l'analyse. Le document ne porte ni
// numéro de série ni horodatage : deux analyses du même commit donnent les mêmes octets,
// que le serveur reconnaît comme un renvoi (ADR 0023).
func (s scanner) scanBOM(ctx context.Context, dir, name, commit string) (*cyclonedx.BOM, error) {
	srcCfg := syft.DefaultGetSourceConfig().
		WithSources("dir").
		WithBasePath(dir).
		WithAlias(source.Alias{Name: name, Version: commit})
	src, err := syft.GetSource(ctx, dir, srcCfg)
	if err != nil {
		return nil, fmt.Errorf("repoagent: source Syft : %w", err)
	}
	defer src.Close()

	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("lotor-repo-agent", s.agentVersion).
		WithoutFiles().
		WithPackagesConfig(offlineCatalogers())
	doc, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("repoagent: catalogage Syft : %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	bom := cyclonedxhelpers.ToFormatModel(*doc)
	bom.SerialNumber = ""
	if bom.Metadata != nil {
		bom.Metadata.Timestamp = ""
	}
	if bom.Components != nil {
		markOrigin(*bom.Components)
	}
	return bom, nil
}

// encodeBOM encode le document en CycloneDX 1.6 JSON.
func encodeBOM(bom *cyclonedx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	enc := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("repoagent: encodage CycloneDX : %w", err)
	}
	return buf.Bytes(), nil
}

// offlineCatalogers est la configuration par défaut des catalogueurs de Syft, sans aucun
// accès réseau ni exécution : le catalogueur Go n'appelle pas « go list »
// (golang.org/x/tools/go/packages, qui lancerait la chaîne Go sur le dépôt et pourrait
// télécharger), et aucun catalogueur ne consulte un registre ou un cache local de l'agent.
func offlineCatalogers() pkgcataloging.Config {
	c := pkgcataloging.DefaultConfig()
	c.Golang.UsePackagesLib = false
	c.Golang.SearchRemoteLicenses = false
	c.Golang.SearchLocalModCacheLicenses = false
	c.Golang.SearchLocalVendorLicenses = false
	c.JavaArchive.UseNetwork = false
	c.JavaArchive.UseMavenLocalRepository = false
	c.JavaScript.SearchRemoteLicenses = false
	c.Python.SearchRemoteLicenses = false
	return c
}

// markOrigin ajoute lotor:origin=syft à chaque composant, sous-composants compris.
func markOrigin(cs []cyclonedx.Component) {
	for i := range cs {
		props := []cyclonedx.Property{}
		if cs[i].Properties != nil {
			props = *cs[i].Properties
		}
		props = append(props, cyclonedx.Property{Name: sbomsyft.PropOrigin, Value: originSyft})
		cs[i].Properties = &props
		if cs[i].Components != nil {
			markOrigin(*cs[i].Components)
		}
	}
}
