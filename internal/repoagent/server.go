package repoagent

import (
	"context"
	"errors"
	"time"

	"leblanc.io/lotor/internal/forge"
)

// Project est un dépôt confié à l'agent par le serveur.
type Project struct {
	ID       string
	Slug     string
	ForgeURL string
	// AIMode est le réglage d'enrichissement IA transmis par le serveur ; vide vaut
	// AIDisabled.
	AIMode AIMode
	Refs   []TrackedRef
}

// TrackedRef est une référence suivie et le commit de son instantané courant (vide tant
// qu'aucun SBOM n'a été rangé).
type TrackedRef struct {
	ID         string
	Ref        forge.Ref
	LastCommit string
}

// Upload est l'envoi d'un SBOM pour un commit d'une référence.
type Upload struct {
	ProjectID    string
	Ref          forge.Ref
	Commit       string
	AgentVersion string
	ScannedAt    time.Time
	// SBOM est le document CycloneDX JSON, non compressé.
	SBOM []byte
}

// Server est ce que l'agent attend du serveur lotor : la liste des dépôts qui lui
// sont confiés, le signal de vie et l'envoi des SBOM. Réessais et respect de Retry-After
// relèvent de l'implémentation.
type Server interface {
	// Projects renvoie tous les projets de dépôt confiés à l'agent (toutes les pages).
	Projects(ctx context.Context) ([]Project, error)
	Heartbeat(ctx context.Context, version string) error
	// Upload envoie un SBOM ; il revient dès que le serveur l'a accepté (202, ou 200 pour
	// un renvoi identique). Une erreur qui enveloppe ErrRejected est définitive.
	Upload(ctx context.Context, u Upload) error
	// AIComponents renvoie les composants IA de l'instantané courant d'une référence
	// (analyse incrémentale après un redémarrage).
	AIComponents(ctx context.Context, refID string) ([]PreviousComponent, error)
}

// ErrRejected signale un envoi refusé définitivement par le serveur (référence inconnue,
// SBOM trop volumineux…) : le renvoyer tel quel n'aurait pas d'autre issue.
var ErrRejected = errors.New("repoagent: envoi refusé par le serveur")
