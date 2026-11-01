package hostagent

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"
)

// ImageScanner inventorie une image de conteneur exportée au format docker-archive.
type ImageScanner interface {
	ScanImage(ctx context.Context, archive, name string) (Inventory, error)
}

// SyftImageScanner inventorie une image avec Syft, depuis son archive (docker save) :
// aucun accès au moteur ni au registre, catalogueurs d'une image, sans catalogage de
// fichiers, comme pour l'hôte. Le contenu d'une image tierce n'est pas fiable : Syft
// n'y exécute rien et ne sort pas sur le réseau (offlineCatalogers).
type SyftImageScanner struct {
	// Parallelism borne les catalogueurs exécutés en même temps.
	Parallelism int
	// Version est la version de l'agent, inscrite comme outil dans le SBOM.
	Version string
}

// ScanImage inventorie l'image de l'archive et calcule l'empreinte d'inventaire du SBOM
// produit ; name (la référence de l'image) nomme le sujet du SBOM.
func (s SyftImageScanner) ScanImage(ctx context.Context, archive, name string) (Inventory, error) {
	start := time.Now()
	// Le chemin nu, et la seule source docker-archive : un préfixe serait lu comme un
	// registre (specs/lecons.md, Anchore).
	srcCfg := syft.DefaultGetSourceConfig().WithSources("docker-archive").WithAlias(source.Alias{Name: name})
	src, err := syft.GetSource(ctx, archive, srcCfg)
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: source de l'image : %w", err)
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("lotor-host-agent", s.Version).
		WithParallelism(max(s.Parallelism, 1)).
		WithoutFiles().
		WithPackagesConfig(offlineCatalogers()).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(pkgcataloging.ImageTag))
	doc, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: scan de l'image : %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Inventory{}, fmt.Errorf("hostagent: scan de l'image interrompu : %w", err)
	}
	var buf bytes.Buffer
	if err := syftjson.NewFormatEncoder().Encode(&buf, *doc); err != nil {
		return Inventory{}, fmt.Errorf("hostagent: encodage du SBOM de l'image : %w", err)
	}
	inv, err := fingerprint(buf.Bytes())
	if err != nil {
		return Inventory{}, err
	}
	inv.Started, inv.Duration = start.UTC(), time.Since(start)
	return inv, nil
}

// offlineCatalogers coupe tout ce qui, dans les catalogueurs de Syft, exécuterait un
// outil ou sortirait sur le réseau (comme repoagent pour un dépôt, specs/lecons.md T08).
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
