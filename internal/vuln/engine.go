package vuln

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNoDatabase : aucune base de vulnérabilités n'est encore la cible de l'instance, ou
// aucune n'est chargée localement.
var ErrNoDatabase = errors.New("vuln: aucune base de vulnérabilités")

// ErrChecksum : la somme de contrôle d'une archive diffère de celle attendue. L'archive
// n'est jamais activée.
var ErrChecksum = errors.New("vuln: somme de contrôle de l'archive incorrecte")

// Description décrit une base installée.
type Description struct {
	Built  time.Time
	Schema string
}

// Database est une base ouverte, prête pour la correspondance. Match peut être appelé
// depuis plusieurs goroutines.
type Database interface {
	Matcher
	Description() Description
	Close() error
}

// Engine installe et ouvre une base locale. vuln/grype l'implémente ; aucune autre partie
// du code ne connaît le format de la base.
type Engine interface {
	// Install décompresse et valide l'archive archivePath dans dir, qui ne doit pas
	// exister. Une archive illisible, d'un schéma non pris en charge ou dont la base ne
	// s'ouvre pas est refusée.
	Install(ctx context.Context, archivePath, dir string) (Description, error)
	// Open ouvre la base installée dans dir par Install.
	Open(ctx context.Context, dir string) (Database, error)
}

// Listing est la dernière archive annoncée par la liste de distribution.
type Listing struct {
	URL    string
	Built  time.Time
	Schema string
	// SHA256 est la somme attendue, en hexadécimal minuscule.
	SHA256 string
}

// Source interroge la liste de distribution et télécharge les archives (vuln/grype).
type Source interface {
	Latest(ctx context.Context) (Listing, error)
	// Download écrit l'archive l dans w, au plus maxBytes octets. La somme de contrôle
	// est vérifiée par l'appelant.
	Download(ctx context.Context, l Listing, w io.Writer, maxBytes int64) error
}

// ErrTooLarge : la ressource téléchargée dépasse la borne demandée.
var ErrTooLarge = errors.New("vuln: téléchargement trop volumineux")

// Fetcher télécharge une ressource HTTP(S) dans w, au plus maxBytes octets (ErrTooLarge
// au-delà). internal/download l'implémente : le métier n'ouvre aucune connexion.
type Fetcher interface {
	Fetch(ctx context.Context, url string, w io.Writer, maxBytes int64) error
}
