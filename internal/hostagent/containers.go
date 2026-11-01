package hostagent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/agentclient/gen"
)

// maxContainers borne les identités d'un signalement, comme le serveur.
const maxContainers = 500

// ContainersResult résume l'inventaire des conteneurs d'un cycle.
type ContainersResult struct {
	// Workloads : identités signalées (un service Compose et ses répliques comptent pour
	// une).
	Workloads int
	// Skipped : conteneurs écartés (sans identité ou empreinte d'image lisible, ou
	// au-delà de la borne).
	Skipped int
	// Images : images scannées pendant le cycle (une image partagée l'est une fois).
	Images    int
	Sent      int
	Confirmed int
	// Ignored : projets archivés par un utilisateur, que l'agent n'inventorie pas.
	Ignored int
	Failed  int
}

// ImageRecord est l'inventaire d'une image que le serveur a rangé ou confirmé.
type ImageRecord struct {
	Fingerprint string    `json:"fingerprint"`
	ScannedAt   time.Time `json:"scanned_at"`
}

// images renvoie les inventaires d'images connus, s'ils viennent de cette version de
// l'agent (une autre version de Syft peut inventorier autrement).
func (s State) images(version string) map[string]ImageRecord {
	if s.ImagesVersion != version || s.Images == nil {
		return map[string]ImageRecord{}
	}
	return s.Images
}

// containers inventorie les conteneurs en cours d'exécution : découverte par les moteurs,
// signalement au serveur (qui crée les projets enfants sous l'hôte de l'agent), puis,
// pour chaque conteneur dont le serveur n'a pas déjà l'inventaire, scan de son image (une
// fois par image et par cycle) et envoi de son SBOM. Un échec sur un conteneur n'empêche
// pas les autres ; seul l'échec du signalement interrompt l'inventaire.
func (a *Agent) containers(ctx context.Context, c *agentclient.Client) (ContainersResult, error) {
	var res ContainersResult
	workloads, skipped := a.discover(ctx)
	res.Skipped = skipped
	if len(workloads) > maxContainers {
		a.o.Logger.WarnContext(ctx, "trop de conteneurs : seuls les premiers sont signalés", "count", len(workloads), "max", maxContainers)
		res.Skipped += len(workloads) - maxContainers
		workloads = workloads[:maxContainers]
	}
	res.Workloads = len(workloads)
	st := a.o.Store.Load()
	known := st.images(a.o.Version)
	req := gen.ContainerReport{Version: a.o.Version, Containers: make([]gen.ContainerSighting, 0, len(workloads))}
	for _, w := range workloads {
		s := gen.ContainerSighting{Key: w.Key, Engine: gen.ContainerSightingEngine(w.Engine.Name()), Names: w.Names,
			Replicas: w.Replicas, Image: w.Image, ImageId: w.ImageID}
		if w.ComposeProject != "" {
			s.ComposeProject, s.ComposeService = &w.ComposeProject, &w.ComposeService
		}
		if !w.StartedAt.IsZero() {
			started := w.StartedAt
			s.StartedAt = &started
		}
		if rec, ok := known[w.ImageID]; ok {
			s.Inventory = &gen.ImageInventory{Fingerprint: rec.Fingerprint, ScannedAt: rec.ScannedAt}
		}
		req.Containers = append(req.Containers, s)
	}
	report, err := c.ReportContainers(ctx, req)
	if err != nil {
		return res, fmt.Errorf("hostagent: signalement des conteneurs : %w", err)
	}
	states := make(map[string]gen.ContainerState, len(report.Containers))
	for _, s := range report.Containers {
		states[s.Key] = s
	}
	kept := map[string]ImageRecord{}
	scanned := map[string]Inventory{}
	failedImages := map[string]bool{}
	for _, w := range workloads {
		s, ok := states[w.Key]
		switch {
		case !ok:
			res.Failed++
			a.o.Logger.WarnContext(ctx, "conteneur absent de la réponse du serveur", "container", w.Key)
			continue
		case s.Ignored:
			res.Ignored++
			continue
		case s.Inventory != nil && *s.Inventory == gen.ContainerStateInventoryCurrent:
			res.Confirmed++
			kept[w.ImageID] = known[w.ImageID]
			continue
		}
		if failedImages[w.ImageID] {
			res.Failed++
			continue
		}
		inv, ok := scanned[w.ImageID]
		if !ok {
			if inv, err = a.scanImage(ctx, w); err != nil {
				if ctx.Err() != nil {
					return res, ctx.Err()
				}
				res.Failed++
				failedImages[w.ImageID] = true
				a.o.Logger.ErrorContext(ctx, "scan d'une image en échec", "container", w.Key, "image", w.Image, "err", err.Error())
				continue
			}
			scanned[w.ImageID] = inv
			res.Images++
		}
		if err := a.sendContainer(ctx, c, s, inv); err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.Failed++
			a.o.Logger.ErrorContext(ctx, "envoi du SBOM d'un conteneur en échec", "container", w.Key, "err", err.Error())
			continue
		}
		res.Sent++
		kept[w.ImageID] = ImageRecord{Fingerprint: hex.EncodeToString(inv.Fingerprint[:]), ScannedAt: inv.Started}
	}
	// Seules les images des conteneurs qui tournent restent connues.
	st = a.o.Store.Load()
	st.Images, st.ImagesVersion = kept, a.o.Version
	return res, a.o.Store.Save(st)
}

// discover interroge chaque moteur. Une socket absente est ignorée (en le disant si elle
// a été configurée) ; un moteur en erreur n'empêche pas les autres.
func (a *Agent) discover(ctx context.Context) ([]Workload, int) {
	perEngine := map[ContainerEngine][]Container{}
	explicit := len(a.o.Config.Containers.Sockets) > 0
	for _, e := range a.o.Engines {
		list, err := e.Containers(ctx)
		switch {
		case errors.Is(err, ErrEngineAbsent) && !explicit:
			a.o.Logger.DebugContext(ctx, "pas de moteur de conteneurs sur cette socket", "socket", e.Socket())
			continue
		case err != nil:
			a.o.Logger.WarnContext(ctx, "moteur de conteneurs injoignable", "socket", e.Socket(), "err", err.Error())
			continue
		}
		perEngine[e] = list
		a.o.Logger.DebugContext(ctx, "conteneurs en cours", "engine", e.Name(), "socket", e.Socket(), "count", len(list))
	}
	return Workloads(perEngine)
}

// scanImage exporte l'image d'un conteneur dans le répertoire de travail (0700), la
// scanne, puis supprime l'archive.
func (a *Agent) scanImage(ctx context.Context, w Workload) (Inventory, error) {
	dir := a.o.Config.ImagesDir()
	if err := ensureStateDir(dir); err != nil {
		return Inventory{}, err
	}
	f, err := os.CreateTemp(dir, "image-*.tar")
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: archive de l'image : %w", err)
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	maxBytes := int64(a.o.Config.Containers.MaxImageMiB) << 20
	if err := w.Engine.ExportImage(ctx, w.ImageID, f, maxBytes); err != nil {
		_ = f.Close()
		return Inventory{}, err
	}
	if err := f.Close(); err != nil {
		return Inventory{}, fmt.Errorf("hostagent: archive de l'image : %w", err)
	}
	scanCtx, cancel := context.WithTimeout(ctx, a.o.Config.Scan.MaxDuration)
	defer cancel()
	inv, err := a.o.ImageScanner.ScanImage(scanCtx, path, w.Image)
	if err != nil {
		return Inventory{}, err
	}
	a.o.Logger.InfoContext(ctx, "image inventoriée", "image", w.Image, "components", inv.Components, "duration", inv.Duration.String())
	return inv, nil
}

// sendContainer envoie le SBOM d'un conteneur sur la référence de son projet enfant et
// attend son rangement.
func (a *Agent) sendContainer(ctx context.Context, c *agentclient.Client, s gen.ContainerState, inv Inventory) error {
	ic := gen.IngestionContext{ProjectId: s.Project.Id, AgentVersion: a.o.Version, ScannedAt: inv.Started}
	ic.Ref.Kind, ic.Ref.Name = gen.IngestionContextRefKindContainer, s.Key
	return a.upload(ctx, c, ic, inv)
}
