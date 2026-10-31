package grype

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"

	"leblanc.io/open-go-sbom/internal/vuln"
)

// maxListing borne la liste de distribution (quelques centaines d'octets en pratique).
const maxListing = 1 << 20

// Source lit la liste de distribution de Grype (latest.json) et télécharge les archives
// par le Fetcher fourni : l'adaptateur n'ouvre aucune connexion lui-même.
type Source struct {
	fetch      vuln.Fetcher
	listingURL string
	resolver   v6dist.Client
}

// NewSource renvoie une Source pour la liste listingURL : adresse de latest.json, ou
// racine des bases de Grype (vide : celle d'Anchore).
func NewSource(fetch vuln.Fetcher, listingURL string) (*Source, error) {
	cfg := v6dist.DefaultConfig()
	if listingURL != "" {
		cfg.LatestURL = listingURL
	}
	// Le client de Grype ne sert qu'à résoudre l'adresse de l'archive à partir de celle
	// de la liste, sans réseau.
	resolver, err := v6dist.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("grype: client de distribution : %w", err)
	}
	return &Source{fetch: fetch, listingURL: latestURL(cfg.LatestURL), resolver: resolver}, nil
}

// latestURL complète une racine en adresse de latest.json, comme le client de Grype.
func latestURL(u string) string {
	if strings.HasSuffix(u, ".json") {
		return u
	}
	return strings.TrimRight(u, "/") + "/v" + strconv.Itoa(v6.ModelVersion) + "/" + v6dist.LatestFileName
}

var _ vuln.Source = (*Source)(nil)

// Latest lit la liste de distribution.
func (s *Source) Latest(ctx context.Context) (vuln.Listing, error) {
	var buf bytes.Buffer
	if err := s.fetch.Fetch(ctx, s.listingURL, &buf, maxListing); err != nil {
		return vuln.Listing{}, fmt.Errorf("grype: liste de distribution : %w", err)
	}
	return parseListing(buf.Bytes(), s.resolver)
}

func parseListing(body []byte, resolver v6dist.Client) (vuln.Listing, error) {
	doc, err := v6dist.NewLatestFromReader(bytes.NewReader(body))
	if err != nil {
		return vuln.Listing{}, fmt.Errorf("grype: liste de distribution : %w", err)
	}
	if doc == nil {
		return vuln.Listing{}, errors.New("grype: liste de distribution vide")
	}
	if doc.SchemaVersion.Model != v6.ModelVersion {
		return vuln.Listing{}, fmt.Errorf("grype: schéma %s non pris en charge (attendu v%d)", doc.SchemaVersion, v6.ModelVersion)
	}
	if doc.Built.IsZero() || doc.Path == "" {
		return vuln.Listing{}, errors.New("grype: liste de distribution incomplète")
	}
	sum, err := parseChecksum(doc.Checksum)
	if err != nil {
		return vuln.Listing{}, err
	}
	u, err := resolver.ResolveArchiveURL(doc.Archive)
	if err != nil {
		return vuln.Listing{}, fmt.Errorf("grype: adresse de l'archive : %w", err)
	}
	return vuln.Listing{URL: u, Built: doc.Built.UTC(), Schema: doc.SchemaVersion.String(), SHA256: sum}, nil
}

// parseChecksum lit « sha256:<hex> ».
func parseChecksum(s string) (string, error) {
	algo, sum, ok := strings.Cut(s, ":")
	sum = strings.ToLower(sum)
	if !ok || algo != "sha256" || len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
		return "", fmt.Errorf("grype: somme de contrôle %q non prise en charge (sha256 attendue)", s)
	}
	return sum, nil
}

// Download écrit l'archive l dans w, au plus maxBytes octets.
func (s *Source) Download(ctx context.Context, l vuln.Listing, w io.Writer, maxBytes int64) error {
	if err := s.fetch.Fetch(ctx, l.URL, w, maxBytes); err != nil {
		return fmt.Errorf("grype: téléchargement de l'archive : %w", err)
	}
	return nil
}
