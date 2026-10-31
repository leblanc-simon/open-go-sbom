package sbom

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/package-url/packageurl-go"
)

// Bornes des champs d'un composant : au-delà, le composant est écarté (Document.Skipped)
// plutôt que tronqué, car une troncature changerait son identité.
const (
	MaxPURLLen    = 2048
	MaxNameLen    = 512
	MaxVersionLen = 256
)

// ErrInvalidPURL : purl illisible, trop long ou non canonicalisable.
var ErrInvalidPURL = errors.New("sbom: purl invalide")

// PURL est un purl canonique et sa base.
type PURL struct {
	// String est la forme canonique.
	String string
	// Base est la forme canonique sans version, qualificatifs ni sous-chemin.
	Base    string
	Type    string
	Name    string
	Version string
}

// CanonicalPURL met un purl sous sa forme canonique, selon la spécification purl telle que
// l'applique packageurl-go : schéma et type en minuscules, espace de noms et nom ajustés
// selon le type (minuscules pour deb, rpm, apk, alpm, golang, github, bitbucket,
// composer… ; minuscules et « _ » → « - » pour pypi), sous-chemin nettoyé, qualificatifs
// aux clés en minuscules, triés, sans valeur vide, et chaque partie encodée de façon
// unique. Aucun qualificatif n'est retiré : distro, arch, epoch, upstream… identifient le
// paquet pour Grype.
func CanonicalPURL(raw string) (PURL, error) {
	if raw == "" || len(raw) > MaxPURLLen || !utf8.ValidString(raw) || strings.ContainsFunc(raw, unicode.IsControl) {
		return PURL{}, ErrInvalidPURL
	}
	p, err := packageurl.FromString(raw)
	if err != nil {
		return PURL{}, fmt.Errorf("%w : %v", ErrInvalidPURL, err)
	}
	return fromParsed(p)
}

func fromParsed(p packageurl.PackageURL) (PURL, error) {
	s := p.ToString()
	if len(s) > MaxPURLLen {
		return PURL{}, ErrInvalidPURL
	}
	// La forme écrite doit se relire à l'identique : c'est ce qui en fait une identité.
	again, err := packageurl.FromString(s)
	if err != nil || again.ToString() != s {
		return PURL{}, ErrInvalidPURL
	}
	base := packageurl.PackageURL{Type: p.Type, Namespace: p.Namespace, Name: p.Name}
	return PURL{String: s, Base: base.ToString(), Type: p.Type, Name: p.Name, Version: p.Version}, nil
}

// GenericPURL construit pkg:generic/<nom>@<version> pour un composant sans purl utilisable.
func GenericPURL(name, version string) (PURL, error) {
	if name == "" {
		return PURL{}, ErrInvalidPURL
	}
	p := packageurl.PackageURL{Type: packageurl.TypeGeneric, Name: name, Version: version}
	if err := p.Normalize(); err != nil {
		return PURL{}, fmt.Errorf("%w : %v", ErrInvalidPURL, err)
	}
	return fromParsed(p)
}

// ComponentPURL donne le purl canonique d'un composant tel que Normalize le calcule : le
// purl du document s'il est utilisable, sinon pkg:generic/<nom>@<version> (weak vrai).
// L'analyse (T06) l'applique aux paquets de Grype pour retrouver les composants.
func ComponentPURL(raw, name, version string) (p PURL, weak bool, err error) {
	if raw != "" {
		if p, err := CanonicalPURL(raw); err == nil {
			return p, false, nil
		}
	}
	p, err = GenericPURL(name, version)
	return p, true, err
}
