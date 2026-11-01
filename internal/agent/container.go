package agent

import (
	"context"
	"errors"
	"time"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/project"
)

// KeyNoHostProject : l'agent qui signale des conteneurs n'a pas de projet d'hôte actif
// (projet archivé) ; ses conteneurs ne peuvent être rattachés à rien.
const KeyNoHostProject = "error.agent.no_host_project"

// KeyContainersLimit : le signalement créerait plus de projets enfants que
// containers.max_per_host n'en permet pour l'hôte ; rien n'est créé (SEC2-05).
const KeyContainersLimit = "error.agent.containers_limit"

// KeyContainersNotHost : seul un agent serveur signale des conteneurs.
const KeyContainersNotHost = "validation.containers_not_host"

// ContainerReport est un conteneur (ou les répliques d'un service Compose) signalé par
// l'agent serveur, avec, si son image a déjà été inventoriée, l'empreinte d'inventaire
// de cette image : le serveur répond alors si l'inventaire courant du projet enfant est
// déjà celui-là (comme pour un compte rendu d'hôte, ADR 0020).
type ContainerReport struct {
	project.ContainerSighting
	Inventory *ContainerInventory
}

// ContainerInventory est l'inventaire connu de l'image d'un conteneur.
type ContainerInventory struct {
	Fingerprint [32]byte
	ScannedAt   time.Time
}

// ContainerResult est la réponse du serveur pour un conteneur signalé : son projet
// enfant, sa référence, et la réponse au compte rendu d'inventaire (vide sans compte
// rendu ; jamais « current » pour un projet ignoré).
type ContainerResult struct {
	project.ChildState
	Inventory InventoryState
}

// ReportContainers enregistre les conteneurs qui tournent sur l'hôte de l'agent p : les
// projets enfants sont créés au besoin, sous l'hôte confié à cet agent et sous aucun
// autre ; les comptes rendus d'inventaire sont confirmés comme ceux d'un hôte. Une seule
// transaction ; le signalement vaut aussi signal de vie.
func (s *Service) ReportContainers(ctx context.Context, p Principal, version string, reports []ContainerReport, ip, requestID string) ([]ContainerResult, error) {
	if p.Kind != KindAgent {
		return nil, errInvalid
	}
	if p.AgentKind != KindHost {
		return nil, invalid("containers", KeyContainersNotHost)
	}
	if err := ValidVersion(version); err != nil {
		return nil, err
	}
	now := s.Now()
	sightings := make([]project.ContainerSighting, len(reports))
	for i, r := range reports {
		sightings[i] = r.ContainerSighting
		if inv := r.Inventory; inv != nil && (inv.ScannedAt.IsZero() || inv.ScannedAt.After(now.Add(maxClockSkew)) ||
			inv.ScannedAt.Year() < 2000) {
			return nil, invalid("containers", project.KeyContainerInvalid)
		}
	}
	if err := project.ValidateSightings(sightings, now); err != nil {
		return nil, err
	}
	actor := audit.Actor{Email: DisplayPrefix(KindAgent, p.PublicID), IP: ip, RequestID: requestID}
	byKey := make(map[string]*ContainerInventory, len(reports))
	for _, r := range reports {
		byKey[r.Key] = r.Inventory
	}
	var out []ContainerResult
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET version = $2, last_seen_at = $3 WHERE id = $1`,
			p.AgentID, version, now); err != nil {
			return err
		}
		states, err := project.SightContainers(ctx, tx, actor, p.AgentID, sightings, now, s.maxContainers)
		if errors.Is(err, project.ErrNoHost) {
			return &ConflictError{Key: KeyNoHostProject}
		}
		if errors.Is(err, project.ErrContainerLimit) {
			return &ConflictError{Key: KeyContainersLimit}
		}
		if err != nil {
			return err
		}
		out = make([]ContainerResult, len(states))
		for i, st := range states {
			out[i].ChildState = st
			inv := byKey[st.Key]
			if inv == nil || st.Ignored {
				continue
			}
			ok, err := inventory.Confirm(ctx, tx, st.RefID, inv.Fingerprint, inv.ScannedAt.UTC(), now)
			if err != nil {
				return err
			}
			out[i].Inventory = InventoryOutdated
			if ok {
				out[i].Inventory = InventoryCurrent
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("signalement des conteneurs", err)
	}
	return out, nil
}
