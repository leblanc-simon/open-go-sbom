package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// Clés de validation propres à l'agent serveur.
const (
	KeyHostContextInvalid = "validation.host_context_invalid"
	KeyInventoryInvalid   = "validation.inventory_report_invalid"
	KeyScanNotHost        = "validation.scan_not_host"
)

// HostContext est le contexte d'un hôte annoncé par son agent : système (os-release),
// noyau, architecture, nom d'hôte et durée du dernier scan. Il est conservé sur l'agent
// (dernier annoncé) et affiché sur sa fiche et celle de son hôte.
type HostContext struct {
	Hostname     string `json:"hostname,omitempty"`
	OSID         string `json:"os_id,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	OSName       string `json:"os_name,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch,omitempty"`
	ScanDuration int64  `json:"scan_duration_ms,omitempty"` // millisecondes
}

// maxScanDuration borne la durée de scan annoncée.
const maxScanDuration = 24 * time.Hour

// Validate vérifie un contexte d'hôte : textes courts, imprimables, sans retour à la ligne.
func (h HostContext) Validate() error {
	fields := []struct {
		v   string
		max int
	}{{h.Hostname, 255}, {h.OSID, 64}, {h.OSVersion, 64}, {h.OSName, 128}, {h.Kernel, 128}, {h.Arch, 32}}
	for _, f := range fields {
		if len(f.v) > f.max || !utf8.ValidString(f.v) || strings.ContainsFunc(f.v, func(r rune) bool { return !unicode.IsPrint(r) }) {
			return invalid("host", KeyHostContextInvalid)
		}
	}
	if h.ScanDuration < 0 || h.ScanDuration > maxScanDuration.Milliseconds() {
		return invalid("host", KeyHostContextInvalid)
	}
	return nil
}

// ScanDurationValue renvoie la durée du scan.
func (h HostContext) ScanDurationValue() time.Duration {
	return time.Duration(h.ScanDuration) * time.Millisecond
}

// InventoryReport est le compte rendu d'un scan d'hôte dont l'empreinte d'inventaire n'a
// pas changé depuis le dernier envoi de l'agent (sbom.Fingerprint, calculée comme côté
// serveur).
type InventoryReport struct {
	ProjectID   uuid.UUID
	RefName     string
	Fingerprint [32]byte
	ScannedAt   time.Time
}

// InventoryState est la réponse du serveur à un compte rendu d'inventaire.
type InventoryState string

// Réponses à un compte rendu d'inventaire.
const (
	// InventoryCurrent : l'ensemble courant a cette empreinte, la date de dernière analyse
	// a avancé.
	InventoryCurrent InventoryState = "current"
	// InventoryOutdated : l'agent doit envoyer son SBOM.
	InventoryOutdated InventoryState = "outdated"
)

// HeartbeatRequest est un signal de vie : version de l'agent et, pour un agent serveur
// qui vient de scanner, compte rendu d'inventaire et contexte d'hôte.
type HeartbeatRequest struct {
	Version   string
	Inventory *InventoryReport
	Host      *HostContext
}

// HeartbeatResult est la réponse à un signal de vie.
type HeartbeatResult struct {
	// ScanRequested : un scan a été demandé depuis l'interface ; la demande est remise
	// une seule fois, par cette réponse.
	ScanRequested bool
	// Inventory répond au compte rendu d'inventaire (vide sans compte rendu).
	Inventory InventoryState
}

// maxClockSkew borne l'avance d'une date de scan sur l'horloge du serveur (comme pour
// une ingestion).
const maxClockSkew = time.Hour

// Heartbeat enregistre le signal de vie d'un agent, sa version et, s'ils sont joints, le
// contexte de l'hôte et le compte rendu d'un scan sans changement ; il remet une demande
// de scan en attente. Une seule transaction.
func (s *Service) Heartbeat(ctx context.Context, p Principal, req HeartbeatRequest) (HeartbeatResult, error) {
	if p.Kind != KindAgent {
		return HeartbeatResult{}, errInvalid
	}
	if err := ValidVersion(req.Version); err != nil {
		return HeartbeatResult{}, err
	}
	now := s.Now()
	if err := s.checkHostReport(p, req, now); err != nil {
		return HeartbeatResult{}, err
	}
	var out HeartbeatResult
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		var requested sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT scan_requested_at FROM agents WHERE id = $1 FOR UPDATE`, p.AgentID).
			Scan(&requested); err != nil {
			return err
		}
		out.ScanRequested = requested.Valid
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET version = $2, last_seen_at = $3, scan_requested_at = NULL WHERE id = $1`,
			p.AgentID, req.Version, now); err != nil {
			return err
		}
		if req.Host != nil {
			if err := storeHost(ctx, tx, p.AgentID, *req.Host, now); err != nil {
				return err
			}
		}
		if req.Inventory != nil {
			state, err := confirm(ctx, tx, p.AgentID, *req.Inventory, now)
			if err != nil {
				return err
			}
			out.Inventory = state
		}
		return nil
	})
	if err != nil {
		return HeartbeatResult{}, wrap("signal de vie", err)
	}
	return out, nil
}

// checkHostReport vérifie ce qu'un agent serveur seul peut joindre à un signal de vie.
func (s *Service) checkHostReport(p Principal, req HeartbeatRequest, now time.Time) error {
	if req.Host == nil && req.Inventory == nil {
		return nil
	}
	if p.AgentKind != KindHost {
		return invalid("inventory", KeyInventoryInvalid)
	}
	if req.Host != nil {
		if err := req.Host.Validate(); err != nil {
			return err
		}
	}
	if r := req.Inventory; r != nil {
		if r.ProjectID == uuid.Nil || r.RefName == "" || len(r.RefName) > 255 || r.ScannedAt.IsZero() ||
			r.ScannedAt.After(now.Add(maxClockSkew)) || r.ScannedAt.Year() < 2000 {
			return invalid("inventory", KeyInventoryInvalid)
		}
	}
	return nil
}

// confirm applique un compte rendu d'inventaire : la référence doit être une référence
// d'hôte confiée à l'agent ; sinon, ou si l'empreinte diffère, l'agent doit envoyer son
// SBOM (l'envoi lui dira, le cas échéant, que la référence est inconnue).
func confirm(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, r InventoryReport, now time.Time) (InventoryState, error) {
	ref, err := project.RefForAgent(ctx, tx, agentID, r.ProjectID, project.RefHost, r.RefName)
	if errors.Is(err, project.ErrNotFound) {
		return InventoryOutdated, nil
	}
	if err != nil {
		return "", err
	}
	ok, err := inventory.Confirm(ctx, tx, ref.ID, r.Fingerprint, r.ScannedAt.UTC(), now)
	if err != nil || !ok {
		return InventoryOutdated, err
	}
	return InventoryCurrent, nil
}

func storeHost(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, h HostContext, now time.Time) error {
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE agents SET host_context = $2, host_context_at = $3 WHERE id = $1 AND kind = 'host'`,
		agentID, data, now)
	return err
}

// RecordHost enregistre le contexte d'hôte joint à un envoi de SBOM par un agent serveur.
func (s *Service) RecordHost(ctx context.Context, p Principal, h HostContext) error {
	if p.Kind != KindAgent {
		return errInvalid
	}
	if p.AgentKind != KindHost {
		return invalid("host", KeyHostContextInvalid)
	}
	if err := h.Validate(); err != nil {
		return err
	}
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error { return storeHost(ctx, tx, p.AgentID, h, s.Now()) })
	return wrap("contexte d'hôte", err)
}

// RequestScan demande un scan à l'agent serveur d'un projet d'hôte ; il le reçoit à son
// prochain signal de vie. Une demande déjà en attente garde sa date.
func (s *Service) RequestScan(ctx context.Context, actor audit.Actor, org tenant.OrgID, projectSlug string) (Agent, error) {
	var a Agent
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var agentID uuid.NullUUID
		var kind string
		var archived bool
		err := tx.QueryRowContext(ctx, `SELECT agent_id, kind, archived_at IS NOT NULL FROM projects WHERE slug = $1`, projectSlug).
			Scan(&agentID, &kind, &archived)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if kind != string(KindHost) || !agentID.Valid || archived {
			return invalid("agent", KeyScanNotHost)
		}
		if a, err = loadAgent(ctx, tx, agentID.UUID, s.Now(), true); err != nil {
			return err
		}
		if a.DisabledAt != nil {
			return invalid("agent", KeyAgentDisabled)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET scan_requested_at = coalesce(scan_requested_at, $2) WHERE id = $1`,
			a.ID, s.Now()); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, agentEvent(audit.AgentScanRequested, a, map[string]string{"project": projectSlug}))
	})
	return a, wrap("demande de scan", err)
}

// mergeLabels complète les étiquettes du jeton d'inscription par celles de la
// configuration de l'agent ; le jeton, choisi par un administrateur, l'emporte.
func mergeLabels(token project.Labels, agent map[string]string) (project.Labels, error) {
	if len(agent) == 0 {
		return token, nil
	}
	out := project.Labels{}
	for k, v := range agent {
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	maps.Copy(out, token)
	return out, out.Validate()
}
